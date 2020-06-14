/** @file
 * PSP Emulator - I/O log dump tool.
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
/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <common/cdefs.h>
#include <common/status.h>

#include <psp-iolog.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/**
 * I/O log tool mode.
 */
typedef enum IOLOGTOOLMODE
{
    /** Invalid mode. */
    IOLOGTOOLMODE_INVALID = 0,
    /** Just dumps the content. */
    IOLOGTOOLMODE_DUMP,
    /** Creates and dumps a register map. */
    IOLOGTOOLMODE_REG_MAP
} IOLOGTOOLMODE;


/**
 * A PSP register.
 */
typedef struct PSPREG
{
    /** The address. */
    uint64_t                    uAddr;
    /** Size of the register. */
    size_t                      cbReg;
    /** Number of writes observed. */
    uint64_t                    cWrites;
    /** Number of reads observed. */
    uint64_t                    cReads;
} PSPREG;
/** Pointer to a PSP register. */
typedef PSPREG *PPSPREG;
/** Pointer to a const PSP register. */
typedef const PSPREG *PCPSPREG;


/**
 * A register map.
 */
typedef struct PSPREGMAP
{
    /** Number of registers observed. */
    uint32_t                    cRegs;
    /** Number of entries allocated in the register map. */
    uint32_t                    cRegsAlloc;
    /** The register map sorted by address. */
    PPSPREG                     paRegs;
} PSPREGMAP;
/** Pointer to a register map. */
typedef PSPREGMAP *PPSPREGMAP;
/** Pointer to a const register map. */
typedef const PSPREGMAP *PCPSPREGMAP;


/*********************************************************************************************************************************
*   Global Variables                                                                                                             *
*********************************************************************************************************************************/

/**
 * Available options for PSPEmu.
 */
static struct option g_aOptions[] =
{
    {"iolog-input",                  required_argument, 0, 'i'},
    {"mode",                         required_argument, 0, 'm'},

    {"help",                         no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

/**
 * Initializes a register map.
 *
 * @returns nothing.
 * @param   pRegMap                 The register map to initialize.
 */
static void pspIoLogToolRegMapInit(PPSPREGMAP pRegMap)
{
    pRegMap->cRegs      = 0;
    pRegMap->cRegsAlloc = 0;
    pRegMap->paRegs     = NULL;
}


/**
 * Dumps the content of the given register map.
 *
 * @returns nothing.
 * @param   pRegMap                 The register map to dump.
 * @param   pszPrefix               The prefix/address space to use.
 */
static void pspIoLogToolRegMapDump(PCPSPREGMAP pRegMap, const char *pszPrefix)
{
    printf("%s:\n", pszPrefix);
    for (uint32_t i = 0; i < pRegMap->cRegs; i++)
    {
        PCPSPREG pReg = &pRegMap->paRegs[i];
        printf("    0x%08llx    %02u    READS: %04u    WRITES: %04u\n",
               pReg->uAddr, pReg->cbReg, pReg->cReads, pReg->cWrites);
    }

    printf("\n");
}


/**
 * Ensures there is at least enough space for the given amount of additional registers in the given
 * register map.
 *
 * @returns Status code.
 * @param   pRegMap                 The register map.
 * @param   cRegs                   Number of additional register to fit in there.
 */
static int pspIoLogToolRegMapEnsureSpace(PPSPREGMAP pRegMap, uint32_t cRegs)
{
    /* Fast path. */
    if (pRegMap->cRegs + cRegs <= pRegMap->cRegsAlloc)
        return STS_INF_SUCCESS;

    int rc = STS_INF_SUCCESS;
    uint32_t cRegsNew = pRegMap->cRegsAlloc + cRegs + 128;
    PPSPREG paRegsNew = (PPSPREG)realloc(pRegMap->paRegs, cRegsNew * sizeof(PSPREG));
    if (paRegsNew)
    {
        pRegMap->paRegs     = paRegsNew;
        pRegMap->cRegsAlloc = cRegsNew;
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


/**
 * Tries to find the rgeister with the given address.
 *
 * @returns Pointer to the register or NULL if not found.
 * @param   pRegMap                 The register map.
 * @param   uAddr                   The address to look for.
 * @param   ppRegBelow              Where to store the register coming before the one looked for, optional.
 *                                  Returns NULL if the address is even before the first known one.
 * @param   pidxRegBelow            Index of the register before - UINT32_MAX if even before the first register.
 */
static PPSPREG pspIoLogToolRegMapFind(PCPSPREGMAP pRegMap, uint64_t uAddr, PCPSPREG *ppRegBelow, uint32_t *pidxRegBelow)
{
    PPSPREG pReg = NULL;

    if (ppRegBelow)
        *ppRegBelow = NULL;

    if (pRegMap->cRegs)
    {
        /* Do a binary search here. */
        uint32_t idxCur   = pRegMap->cRegs / 2;
        uint32_t idxEnd   = pRegMap->cRegs - 1;
        uint32_t idxStart = 0;

        for (;;)
        {
            PPSPREG pCur = &pRegMap->paRegs[idxCur];
            if (   uAddr >= pCur->uAddr
                && uAddr < pCur->uAddr + pCur->cbReg)
            {
                pReg = pCur;
                break;
            }
            else if (uAddr < pCur->uAddr)
            {
                if (idxCur == idxStart) /* Nothing left to look for. */
                    break;

                idxEnd = idxCur - 1;
            }
            else if (uAddr >= pCur->uAddr + pCur->cbReg)
            {
                if (idxCur == idxEnd) /* Nothing left to look for. */
                    break;

                idxStart = idxCur + 1;
            }

            idxCur = idxStart + (idxEnd - idxStart) / 2;
        }

        if (   idxCur
            && ppRegBelow)
            *ppRegBelow = &pRegMap->paRegs[idxCur - 1];
        if (pidxRegBelow)
        {
            if (idxCur)
                *pidxRegBelow = idxCur - 1;
            else
                *pidxRegBelow = UINT32_MAX;
        }
    }

    return pReg;
}


/**
 * Adds the given register address to the register map if not known already, updating access statistics.
 *
 * @returns Status code.
 * @param   pRegMap                 The register map to update.
 * @param   uAddr                   The address to add.
 * @param   fWrite                  Flag whether this was a read or write.
 * @param   cbAcc                   Register access width.
 */
static int pspIoLoToolRegMapAdd(PPSPREGMAP pRegMap, uint64_t uAddr, bool fWrite, size_t cbAcc)
{
    int rc = STS_INF_SUCCESS;
    PCPSPREG pRegBelow = NULL;
    uint32_t idxRegBelow = 0;
    PPSPREG pReg = pspIoLogToolRegMapFind(pRegMap, uAddr, &pRegBelow, &idxRegBelow);
    if (!pReg)
    {
        /* Register not know, add it. */
        rc = pspIoLogToolRegMapEnsureSpace(pRegMap, 1 /*cRegs*/);
        if (STS_SUCCESS(rc))
        {
            if (pRegBelow)
            {
                size_t cbMove = (pRegMap->cRegs - (idxRegBelow + 2)) * sizeof(PSPREG);
                memmove(&pRegMap->paRegs[idxRegBelow + 2], &pRegMap->paRegs[idxRegBelow + 1], cbMove);
                pReg = &pRegMap->paRegs[idxRegBelow + 1];
            }
            else
            {
                if (pRegMap->cRegs)
                    memmove(&pRegMap->paRegs[1], &pRegMap->paRegs[0], pRegMap->cRegs * sizeof(PSPREG));
                pReg = &pRegMap->paRegs[0];
            }

            pReg->uAddr   = uAddr;
            pReg->cbReg   = cbAcc;
            pReg->cReads  = 0;
            pReg->cWrites = 0;
            pRegMap->cRegs++;
        }
    }

    if (STS_SUCCESS(rc))
    {
        if (fWrite)
            pReg->cWrites++;
        else
            pReg->cReads++;
    }

    return rc;
}


/**
 * Dumps the given I/O event.
 *
 * @returns nothing.
 * @param   pIoEvt                  The I/O event to dump.
 */
static void pspIoLogToolEvtDump(PCPSPIOLOGRDREVT pIoEvt)
{
    const char *pszAddrSpace = "<INVALID>"; 
    uint64_t uAddr;

    switch (pIoEvt->enmAddrSpace)
    {
        case PSPADDRSPACE_SMN:
            uAddr = pIoEvt->u.SmnAddr;
            pszAddrSpace = "SMN     ";
            break;
        case PSPADDRSPACE_PSP:
            uAddr = pIoEvt->u.PspAddrMmio;
            pszAddrSpace = "PSP/MMIO";
            break;
        case PSPADDRSPACE_X86:
            uAddr = pIoEvt->u.PhysX86Addr;
            pszAddrSpace = "X86     ";
            break;
    }

    fprintf(stdout, "%02u 0x%08lx %s %16s %#16lx %u",
            pIoEvt->idCcd,
            pIoEvt->PspAddrPc,
            pszAddrSpace,
            pIoEvt->fWrite ? "WRITE" : "READ ",
            uAddr, pIoEvt->cbAcc);

    if (   pIoEvt->cbAcc == 1
        || pIoEvt->cbAcc == 2
        || pIoEvt->cbAcc == 4
        || pIoEvt->cbAcc == 8)
    {
        uint64_t uVal = 0;

        switch (pIoEvt->cbAcc)
        {
            case 1:
                uVal = *(const uint8_t *)pIoEvt->pvData;
                break;
            case 2:
                uVal = *(const uint16_t *)pIoEvt->pvData;
                break;
            case 4:
                uVal = *(const uint32_t *)pIoEvt->pvData;
                break;
            case 8:
                uVal = *(const uint64_t *)pIoEvt->pvData;
                break;
            default: /* Paranoia */
                return;
        }

        fprintf(stdout, " 0x%.*lx", pIoEvt->cbAcc * 2, uVal);
    }

    fprintf(stdout, "\n");
}


/**
 * Dumps the content of the given I/O log.
 *
 * @returns Status code.
 * @param   hIoLogRdr               The I/O log reader instance to dump.
 */
static int pspIoLogToolDump(PSPIOLOGRDR hIoLogRdr)
{
    int rc = STS_INF_SUCCESS;

    do
    {
        PCPSPIOLOGRDREVT pIoEvt = NULL;
        rc = PSPEmuIoLogRdrEvtQueryNext(hIoLogRdr, &pIoEvt);
        if (STS_SUCCESS(rc))
        {
            pspIoLogToolEvtDump(pIoEvt);
            PSPEmuIoLogRdrEvtFree(hIoLogRdr, pIoEvt);
        }
        else
            fprintf(stderr, "Reading I/O event failed with %d\n", rc);
    } while (STS_SUCCESS(rc));

    return rc;
}


/**
 * Creates a register map from the given I/O log.
 *
 * @returns Status code.
 * @param   hIoLogRdr               The I/O log reader instance to use.
 */
static int pspIoLogToolRegMap(PSPIOLOGRDR hIoLogRdr)
{
    int rc = STS_INF_SUCCESS;
    PSPREGMAP RegMapSmn;
    PSPREGMAP RegMapMmio;
    PSPREGMAP RegMapX86;

    pspIoLogToolRegMapInit(&RegMapSmn);
    pspIoLogToolRegMapInit(&RegMapMmio);
    pspIoLogToolRegMapInit(&RegMapX86);

    do
    {
        PCPSPIOLOGRDREVT pIoEvt = NULL;
        rc = PSPEmuIoLogRdrEvtQueryNext(hIoLogRdr, &pIoEvt);
        if (STS_SUCCESS(rc))
        {
            uint64_t uAddr = 0;
            PPSPREGMAP pRegMap = NULL;

            switch (pIoEvt->enmAddrSpace)
            {
                case PSPADDRSPACE_SMN:
                    uAddr = pIoEvt->u.SmnAddr;
                    pRegMap = &RegMapSmn;
                    break;
                case PSPADDRSPACE_PSP:
                    uAddr = pIoEvt->u.PspAddrMmio;
                    pRegMap = &RegMapMmio;
                    break;
                case PSPADDRSPACE_X86:
                    uAddr = pIoEvt->u.PhysX86Addr;
                    pRegMap = &RegMapX86;
                    break;
            }

            rc = pspIoLoToolRegMapAdd(pRegMap, uAddr, pIoEvt->fWrite, pIoEvt->cbAcc);
            PSPEmuIoLogRdrEvtFree(hIoLogRdr, pIoEvt);
        }
        else
            fprintf(stderr, "Reading I/O event failed with %d\n", rc);
    } while (STS_SUCCESS(rc));

    pspIoLogToolRegMapDump(&RegMapSmn, "SMN");
    pspIoLogToolRegMapDump(&RegMapMmio, "MMIO");
    pspIoLogToolRegMapDump(&RegMapX86, "X86");

    return rc;
}


int main(int argc, char *argv[])
{
    int ch = 0;
    int idxOption = 0;
    const char *pszFilename = NULL;
    const char *pszMode = "dump";
    IOLOGTOOLMODE enmMode = IOLOGTOOLMODE_DUMP;

    while ((ch = getopt_long (argc, argv, "Hvi:m:", &g_aOptions[0], &idxOption)) != -1)
    {
        switch (ch)
        {
            case 'h':
            case 'H':
                printf("%s: I/O log dump tool\n"
                       "    --iolog-input <path/to/iolog>\n"
                       "    --mode [dump|reg-map]\n",
                       argv[0]);
                return 0;
            case 'i':
                pszFilename = optarg;
                break;
            case 'm':
                pszMode = optarg;
                break;

            default:
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                return 1;
        }
    }

    if (!pszFilename)
    {
        fprintf(stderr, "A filepath to the I/O log is required!\n");
        return 1;
    }

    if (!strcmp(pszMode, "dump"))
        enmMode = IOLOGTOOLMODE_DUMP;
    else if (!strcmp(pszMode, "reg-map"))
        enmMode = IOLOGTOOLMODE_REG_MAP;
    else
    {
        fprintf(stderr, "Invalid mode %s\n", pszMode);
        return 1;
    }

    PSPIOLOGRDR hIoLogRdr = NULL;
    int rc = PSPEmuIoLogRdrCreate(&hIoLogRdr, pszFilename);
    if (STS_SUCCESS(rc))
    {
        switch (enmMode)
        {
            case IOLOGTOOLMODE_DUMP:
                rc = pspIoLogToolDump(hIoLogRdr);
                break;
            case IOLOGTOOLMODE_REG_MAP:
                rc = pspIoLogToolRegMap(hIoLogRdr);
                break;
        }

        PSPEmuIoLogRdrDestroy(hIoLogRdr);
    }
    else
        fprintf(stderr, "The file '%s' could not be opened\n", pszFilename);

    return 0;
}

