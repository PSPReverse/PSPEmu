/** @file
 * PSP Emulator - Coverage tracing API.
 */

/*
 * Copyright (C) 2020 Alexander Eichner <alexander.eichner@campus.tu-berlin.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <common/status.h>

#include <psp-cov.h>


/**
 * A DrCov basic block entry as written to the file.
 */
typedef struct DRCOVBBENTRY
{
    /** Start offset. */
    uint32_t                        u32Start;
    /** Basic block size in bytes. */
    uint16_t                        cbBb;
    /** Module ID. */
    uint16_t                        idMod;
} DRCOVBBENTRY;


/**
 * A single basic block.
 */
typedef struct PSPCOVBB
{
    /** Pointer to the next basic block. */
    struct PSPCOVBB                 *pNext;
    /** Offset from image start for the basic block. */
    uint32_t                        offBb;
    /** Size of the basic block. */
    size_t                          cbBb;
} PSPCOVBB;
/** Pointer to a basic block. */
typedef PSPCOVBB *PPSPCOVBB;
/** Pointer to a const basic block. */
typedef const PSPCOVBB *PCPSPCOVBB;


/**
 * The coverage tracer instance data.
 */
typedef struct PSPCOVINT
{
    /** Pointer to the PSP core. */
    PSPCORE                         hPspCore;
    /** Start address for the coverage tracing. */
    PSPADDR                         PspAddrBegin;
    /** End address for the coverage tracing. */
    PSPADDR                         PspAddrEnd;
    /** The core trace point handle. */
    PSPCORETP                       hCoreTp;
    /** Head of basic blocks. */
    PPSPCOVBB                       pBbsHead;
    /** Tail of the basic block list. */
    PPSPCOVBB                       pBbsTail;
    /** Number of basic blocks recorded. */
    uint32_t                        cBbs;
    /** Size of the bitmap below. */
    size_t                          cbBmHit;
    /** Bitmap for addresses alread recorded in a basic block so we don't have to search in the list. */
    uint8_t                         *pbmHit;
} PSPCOVINT;
/** Pointer to the tracer instance data. */
typedef PSPCOVINT *PPSPCOVINT;
/** Pointer to a const tracer instance. */
typedef const PSPCOVINT *PCPSPCOVINT;


/**
 * Checks whether the given range is already covered by a basic block.
 *
 * @returns true if the given range is already covered by a basic block.
 * @param   pThis                   The coverage tracer instance.
 * @param   PspAddr                 The address to start at.
 * @param   cbBb                    Size of the basic block.
 */
static bool pspEmuCovBbRangeIsCovered(PPSPCOVINT pThis, PSPADDR PspAddr, size_t cbBb)
{
    (void)cbBb;

    /* We shouldn't get any partly overlapping ranges here so we can just check the first bit. */
    uint32_t idxBit = (PspAddr - pThis->PspAddrBegin) / 2;
    uint32_t idxByte = idxBit / 8;
    idxBit %= 8;

    return (pThis->pbmHit[idxByte] & BIT(idxBit)) ? true : false;
}


/**
 * Sets the given range as covered by a basic block.
 *
 * @returns nothing.
 * @param   pThis                   The coverage tracer instance.
 * @param   PspAddr                 The address to start at.
 * @param   cbBb                    Size of the basic block.
 */
static bool pspEmuCovBbRangeSet(PPSPCOVINT pThis, PSPADDR PspAddr, size_t cbBb)
{
    uint32_t idxBit = (PspAddr - pThis->PspAddrBegin) / 2;
    uint32_t idxByte = idxBit / 8;
    idxBit %= 8;

    uint32_t cBits = cbBb / 2;

    /* Set the first unaligned bits. */
    uint8_t *pbmHit = &pThis->pbmHit[idxByte];
    if (idxBit != 0)
    {
        while (   idxBit < 8
               && cBits)
        {
            *pbmHit |= BIT(idxBit);
            idxBit++;
            cBits--;
        }

        pbmHit++;
    }

    /* Now the aligned bytes. */
    while (cBits >= 8)
    {
        *pbmHit = 0xff;
        pbmHit++;
        cBits -= 8;
    }

    /* Now the remaining ones. */
    idxBit = 0;
    switch (cBits)
    {
        case 0:
            break;
        case 1:
            *pbmHit |= 0x01;
            break;
        case 2:
            *pbmHit |= 0x03;
            break;
        case 3:
            *pbmHit |= 0x07;
            break;
        case 4:
            *pbmHit |= 0x0f;
            break;
        case 5:
            *pbmHit |= 0x1f;
            break;
        case 6:
            *pbmHit |= 0x3f;
            break;
        case 7:
            *pbmHit |= 0x7f;
            break;
        default:
            break; /* This is not supposed to happen at all. */
    }
}


/**
 * The PSP core tracing callback.
 *
 * @returns nothing.
 * @param   hCore                   The PSP core handle causing the call.
 * @param   hTp                     The trace point handle triggering.
 * @param   PspAddr                 The PSP address.
 * @param   cbBb                    Size of the basic block.
 * @param   u64Val                  Ignored for exec trace hooks.
 * @param   pvUser                  Opaque user data passed during registration.
 */
static void pspEmuCovBbTrace(PSPCORE hCore, PSPCORETP hTp, PSPADDR PspAddr, uint32_t cbBb, uint64_t u64Val, void *pvUser)
{
     PPSPCOVINT pThis = (PPSPCOVINT)pvUser;

    /* Check whether the range was hit already. */
    if (!pspEmuCovBbRangeIsCovered(pThis, PspAddr, cbBb))
    {
        /* Create a new basic block, link it and set the range as covered. */
        PPSPCOVBB pBb = (PPSPCOVBB)calloc(1, sizeof(*pBb));
        if (pBb)
        {
            pBb->pNext = NULL;
            pBb->offBb = PspAddr - pThis->PspAddrBegin;
            pBb->cbBb  = cbBb;
            if (pThis->pBbsTail)
            {
                pThis->pBbsTail->pNext = pBb;
                pThis->pBbsTail = pBb;
            }
            else
            {
                pThis->pBbsHead = pBb;
                pThis->pBbsTail = pBb;
            }

            pThis->cBbs++;
            pspEmuCovBbRangeSet(pThis, PspAddr, cbBb);
        }
        /* else: Error information. */
    }
}


/**
 * Writes the basic block table out to the given drcov file.
 *
 * @returns Status code.
 * @param   pThis                   The coverage tracer instance.
 * @param   pCov                    The coverage file to write to.
 */
static int pspEmuCovDrCovBbsDump(PPSPCOVINT pThis, FILE *pCov)
{
    int rc = 0;

    PPSPCOVBB pBb = pThis->pBbsHead;
    while (   pBb
           && !rc)
    {
        DRCOVBBENTRY BbEntry;

        BbEntry.u32Start = pBb->offBb;
        BbEntry.cbBb     = pBb->cbBb;
        BbEntry.idMod    = 0;
        size_t cWritten = fwrite(&BbEntry, sizeof(BbEntry), 1, pCov);
        if (cWritten != 1)
            rc = -1;

        pBb = pBb->pNext;
    }

    return rc;
}


int PSPEmuCovCreate(PPSPCOV phCov, PSPCORE hPspCore, PSPADDR PspAddrBegin, PSPADDR PspAddrEnd)
{
    int rc = STS_INF_SUCCESS;
    PPSPCOVINT pThis = (PPSPCOVINT)calloc(1, sizeof(*pThis));

    if (pThis)
    {
        pThis->hPspCore     = hPspCore;
        pThis->PspAddrBegin = PspAddrBegin;
        pThis->PspAddrEnd   = PspAddrEnd;
        pThis->pBbsHead     = NULL;
        pThis->pBbsTail     = NULL;

        /*
         * Allocate the bitmap, one instruction is at least two bytes (Thumb), so we need
         * one bit for every two bytes in the range.
         */
        size_t cbBmHit = (PspAddrEnd - PspAddrBegin + 1) / 2 + 1; /* One byte extra in case the range is odd (which it shouldn't be) */
        pThis->pbmHit = (uint8_t *)calloc(1, cbBmHit);
        if (pThis->pbmHit)
        {
            pThis->cbBmHit = cbBmHit;

            /* Register the handler with the core. */
            rc = PSPEmuCoreTraceRegister(hPspCore, PspAddrBegin, PspAddrEnd /*inclusive*/,
                                         PSPEMU_CORE_TRACE_F_EXEC | PSPEMU_CORE_TRACE_F_EXEC_BASIC_BLOCK,
                                         ARMASID_ANY, pspEmuCovBbTrace, pThis, &pThis->hCoreTp);
            if (STS_SUCCESS(rc))
            {
                *phCov = pThis;
                return STS_INF_SUCCESS;
            }

            free(pThis->pbmHit);
        }
        else
            rc = STS_ERR_NO_MEMORY;

        free(pThis);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


void PSPEmuCovReset(PSPCOV hCov)
{
    PPSPCOVINT pThis = hCov;

    PPSPCOVBB pBb = pThis->pBbsHead;
    while (pBb)
    {
        PPSPCOVBB pFree = pBb;
        pBb = pBb->pNext;
        free(pFree);
    }

    pThis->pBbsHead = NULL;
    pThis->pBbsTail = NULL;

    /* Clear the bitmap. */
    for (size_t i = 0; i < pThis->cbBmHit; i++)
        pThis->pbmHit[i] = 0;
}


void PSPEmuCovDestroy(PSPCOV hCov)
{
    PPSPCOVINT pThis = hCov;

    PSPEmuCoreTraceDeregister(pThis->hCoreTp);
    PPSPCOVBB pBb = pThis->pBbsHead;
    while (pBb)
    {
        PPSPCOVBB pFree = pBb;
        pBb = pBb->pNext;
        free(pFree);
    }

    if (pThis->pbmHit)
        free(pThis->pbmHit);
    free(pThis);
}


int PSPEmuCovDumpToFile(PSPCOV hCov, const char *pszFilename)
{
    PPSPCOVINT pThis = hCov;

    int rc = 0;
    FILE *pCov = fopen(pszFilename, "wb");
    if (pCov)
    {
        /* Start with the header. */
        const char szHdr[] = "DRCOV VERSION: 2\n"
                             "DRCOV FLAVOR: PSPEmu\n"
                             "Module Table: version 3, count 1\n" /* Module count is static for now. */
                             "Columns: id, containing_id, base, end, entry, path\n";
        size_t cWritten = fwrite(&szHdr[0], sizeof(szHdr) - 1, 1, pCov);
        if (cWritten == 1)
        {
            /* Write the single module we offer and afterwards the BB table header. */
            int cchWritten = fprintf(pCov, "0, 0, %#x, %#x, 0x00000000, N/A\n",
                                     pThis->PspAddrBegin, pThis->PspAddrEnd);
            if (cchWritten)
                cchWritten = fprintf(pCov, "BB Table: %u bbs\n", pThis->cBbs);
            if (cchWritten)
                rc = pspEmuCovDrCovBbsDump(pThis, pCov);
        }
        else
            rc = -1;

        fclose(pCov);
    }
    else
        rc = -1;

    return rc;
}

