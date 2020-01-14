/** @file
 * PSP Emulator - MMIO devices interface.
 */

/*
 * Copyright (C) 2020 Alexander Eichner <alexander.eichner@campus.tu-berlin.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <common/types.h>
#include <common/cdefs.h>

#define IN_PSP_EMULATOR
#include <psp-mmio-dev.h>


/**
 * The internal MMIO manager state.
 */
typedef struct PSPMMIOMINT
{
    /** The head of list of devices attached to the MMIO space (@todo AVL tree?). */
    PPSPMMIODEV                 pDevsHead;
    /** Lowest MMIO address assigned to a device (for faster lookup). */
    PSPADDR                     PspAddrMmioDevLowest;
    /** Highes MMIO address assigned to a device (inclusive). */
    PSPADDR                     PspAddrMmioDevHighest;
    /** The PSP core handle this MMIO manager is assigned to. */
    PSPCORE                     hPspCore;
} PSPMMIOMINT;
/** Pointer to the internal MMIO manager state. */
typedef PSPMMIOMINT *PPSPMMIOMINT;


/**
 * Finds the device assigned to the given MMIO address or NULL if there is nothing assigned.
 *
 * @returns Pointer to the device assigned to the MMIO address or NULL if none was found.
 * @param   pThis                   The PSP MMIO manager.
 * @param   PspAddrMmio             The absolute MMIO address to look for.
 */
static PPSPMMIODEV pspEmuMmioMgrFindDev(PPSPMMIOMINT pThis, PSPADDR PspAddrMmio)
{
    if (   PspAddrMmio < pThis->PspAddrMmioDevLowest
        || PspAddrMmio > pThis->PspAddrMmioDevHighest)
        return NULL;

    /* Slow path. */
    PPSPMMIODEV pCur = pThis->pDevsHead;
    while (pCur)
    {
        if (   PspAddrMmio >= pCur->MmioStart
            && PspAddrMmio < pCur->MmioStart + pCur->pReg->cbMmio)
            return pCur;

        pCur = pCur->pNext;
    }

    return NULL;
}

static void pspEmuMmioMgrRead(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPMMIOMINT pThis = (PPSPMMIOMINT)pvUser;

    uPspAddr += 0x01000000; /* The address contains the offset from the beginning of the registered range */
    PPSPMMIODEV pDev = pspEmuMmioMgrFindDev(pThis, uPspAddr);
    if (pDev)
        pDev->pReg->pfnMmioRead(pDev, uPspAddr - pDev->MmioStart, cbRead, pvDst);
    else
    {
        /* Unassigned read, log and return 0. */
        printf("MMIO: Unassigned read at %#08x (%zu bytes) -> returning 0\n", uPspAddr, cbRead);
        memset(pvDst, 0, cbRead);
    }
}

static void pspEmuMmioMgrWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPMMIOMINT pThis = (PPSPMMIOMINT)pvUser;

    uPspAddr += 0x01000000; /* The address contains the offset from the beginning of the registered range */

    PPSPMMIODEV pDev = pspEmuMmioMgrFindDev(pThis, uPspAddr);
    if (pDev)
        pDev->pReg->pfnMmioWrite(pDev, uPspAddr - pDev->MmioStart, cbWrite, pvSrc);
    else
    {
        /* Unassigned read, log and return 0. */
        printf("MMIO: Unassigned write at %#08x (%zu bytes) -> ignoring\n", uPspAddr, cbWrite);
        switch (cbWrite)
        {
            case 1:
                printf("MMIO:    u8Val=%#x\n", *(uint8_t *)pvSrc);
                break;
            case 2:
                printf("MMIO:    u16Val=%#x\n", *(uint16_t *)pvSrc);
                break;
            case 4:
                printf("MMIO:    u32Val=%#x\n", *(uint32_t *)pvSrc);
                break;
            case 8:
                printf("MMIO:    u64Val=%#llx\n", *(uint64_t *)pvSrc);
                break;
            default:
                printf("MMIO:    Invalid write size!\n");
        }
    }
}


int PSPEmuMmioMgrCreate(PPSPMMIOM phMmioMgr, PSPCORE hPspCore)
{
    int rc = 0;
    PPSPMMIOMINT pThis = calloc(1, sizeof(*pThis));

    if (pThis)
    {
        pThis->pDevsHead             = NULL;
        pThis->PspAddrMmioDevLowest  = 0xffffffff;
        pThis->PspAddrMmioDevHighest = 0x00000000;
        pThis->hPspCore              = hPspCore;

        rc = PSPEmuCoreMmioRegister(hPspCore, 0x01000000, 0x44000000,
                                    pspEmuMmioMgrRead, pspEmuMmioMgrWrite,
                                    pThis);
        if (!rc)
        {
            *phMmioMgr = pThis;
            return 0;
        }
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuMmioMgrDestroy(PSPMMIOM hMmioMgr)
{
    PPSPMMIOMINT pThis = hMmioMgr;

    int rc = PSPEmuCoreMmioDeregister(pThis->hPspCore, 0x01000000, 0xffffffff - 64 * _1K - 0x01000000);
    /** @todo Free  devices. */
    free(pThis);
    return rc;
}

int PSPEmuMmioDevCreate(PSPMMIOM hMmioMgr, PCPSPMMIODEVREG pDevReg, PSPADDR PspAddrMmioStart, PPSPMMIODEV *ppMmioDev)
{
    int rc = 0;
    PPSPMMIOMINT pThis = hMmioMgr;
    PPSPMMIODEV pDev = (PPSPMMIODEV)calloc(1, sizeof(*pDev) + pDevReg->cbInstance);
    if (pDev)
    {
        pDev->pReg      = pDevReg;
        pDev->hMmioMgr  = hMmioMgr;
        pDev->MmioStart = PspAddrMmioStart;

        /* Initialize the device instance and add to the list of known devices. */
        rc = pDev->pReg->pfnInit(pDev);
        if (!rc)
        {
            PPSPMMIODEV pPrev = NULL;
            PPSPMMIODEV pCur = pThis->pDevsHead;

            /* Search where to insert the new device, sorted by starting MMIO address. */
            while (pCur)
            {
                if (pCur->MmioStart > PspAddrMmioStart)
                    break;
                pPrev = pCur;
                pCur = pCur->pNext;
            }

            /* Do some sanity checks, the new MMIO range must not overlap with the previous and current device. */
            if (   (   !pPrev
                    || pPrev->MmioStart + pPrev->pReg->cbMmio <= PspAddrMmioStart)
                && (   !pCur
                    || PspAddrMmioStart + pDevReg->cbMmio <= pCur->MmioStart))
            {
                pDev->pNext = pCur;
                if (pPrev)
                    pPrev->pNext = pDev;
                else
                    pThis->pDevsHead = pDev;

                /* Adjust the lowest and highest device range. */
                if (PspAddrMmioStart < pThis->PspAddrMmioDevLowest)
                    pThis->PspAddrMmioDevLowest = PspAddrMmioStart;
                if (PspAddrMmioStart + pDevReg->cbMmio - 1 > pThis->PspAddrMmioDevHighest)
                    pThis->PspAddrMmioDevHighest = PspAddrMmioStart + pDevReg->cbMmio - 1;

                *ppMmioDev = pDev;
                return 0;
            }
            else
                rc = -1;

            pDev->pReg->pfnDestruct(pDev);
        }

        free(pDev);
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuMmioDevDestroy(PPSPMMIODEV pMmioDev)
{
    /** @todo Unlink from list. */
    pMmioDev->pReg->pfnDestruct(pMmioDev);
    free(pMmioDev);
}

