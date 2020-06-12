/** @file
 * PSP Emulator - CCD API.
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
/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/types.h>
#include <common/cdefs.h>
#include <common/status.h>

#include <psp-iolog-replay.h>
#include <psp-iolog.h>
#include <psp-trace.h>
#include <psp-iom.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/** Forward declaration of the pointer to the internal I/O log replay instance data. */
typedef struct PSPIOLOGREPLAYINT *PPSPIOLOGREPLAYINT;

/**
 * PSP combined address.
 */
typedef struct PSPCOMBADDR
{
    /** The address space type. */
    PSPADDRSPACE                enmAddrSpace;
    /** Type dependent data. */
    union
    {
        /** PSP address. */
        PSPADDR                 PspAddr;
        /** SMN address. */
        SMNADDR                 SmnAddr;
        /** x86 address dependent data. */
        struct
        {
            /** Physical x86 address. */
            X86PADDR            PhysX86Addr;
            /** Caching information associated with that address. */
            uint32_t            fCaching;
        } X86;
    } u;
} PSPCOMBADDR;
/** Pointer to a PSP proxy address. */
typedef PSPCOMBADDR *PPSPCOMBADDR;
/** Pointer to a const PSP proxy address. */
typedef const PSPCOMBADDR *PCPSPCOMBADDR;


/**
 * CCD registration record.
 */
typedef struct PSPIOLOGREPLAYCCD
{
    /** Pointer to the next record. */
    struct PSPIOLOGREPLAYCCD    *pNext;
    /** Pointer to the owning proxy instance. */
    PPSPIOLOGREPLAYINT          pThis;
    /** The CCD handle. */
    PSPCCD                      hCcd;
} PSPIOLOGREPLAYCCD;
/** Pointer to a CCD registration record. */
typedef PSPIOLOGREPLAYCCD *PPSPIOLOGREPLAYCCD;


/**
 * I/O log replay instance data.
 */
typedef struct PSPIOLOGREPLAYINT
{
    /** The I/O log reader handle. */
    PSPIOLOGRDR                 hIoLogRdr;
    /** Head of CCDs registered with this proxy instance. */
    PPSPIOLOGREPLAYCCD          pCcdsHead;
} PSPIOLOGREPLAYINT;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/


/**
 * Checks whether two PSP addresses are considered equal.
 *
 * @returns Flag whether the addresses are considered equal or not.
 * @param   pIoEvt                  The first address to check from the I/O event.
 * @param   pAddr                   The address to check against.
 */
static inline bool pspIoLogReplayAddrIsEqual(PCPSPIOLOGRDREVT pIoEvt, PCPSPCOMBADDR pAddr)
{
    if (pIoEvt->enmAddrSpace != pAddr->enmAddrSpace)
        return false;

    switch (pAddr->enmAddrSpace)
    {
        case PSPADDRSPACE_PSP:
        case PSPADDRSPACE_PSP_MEM:
        case PSPADDRSPACE_PSP_MMIO:
            if (pIoEvt->u.PspAddrMmio != pAddr->u.PspAddr)
                return false;
            break;
        case PSPADDRSPACE_SMN:
            if (pIoEvt->u.SmnAddr != pAddr->u.SmnAddr)
                return false;
            break;
        case PSPADDRSPACE_X86:
        case PSPADDRSPACE_X86_MEM:
        case PSPADDRSPACE_X86_MMIO:
            if (pIoEvt->u.PhysX86Addr != pAddr->u.X86.PhysX86Addr)
                return false;
            break;
        default:
            return false;
    }

    return true;
}


/**
 * Tries to find the given read with the given address and size in the I/O log and returns the value contained in there.
 *
 * @returns Status code.
 * @param   pThis                   The I/O log replay instance data.
 * @param   idCcd                   The CCD ID to look for.
 * @param   pAddr                   The combined address to look for.
 * @param   cbRead                  Number of bytes being read.
 * @param   pvVal                   Where to store the read data.
 */
static int pspIoLogReplayReadFind(PPSPIOLOGREPLAYINT pThis, uint32_t idCcd, PCPSPCOMBADDR pAddr, size_t cbRead, void *pvVal)
{
    int rc = STS_ERR_NOT_FOUND;

    /**
     * The current approach is dead simple, we just skip forward
     * to next matching address size and return the value
     *
     * This requires having the same setup as done when taking the log (i.e. same firmware version etc.)
     * to get deterministic results.
     *
     * More advanced approaches will be implemented later. One idea is read the whole log at the beginning and build
     * a register map with possible values and record writes from the "guest" so we can look up corresponding reads matching
     * a certain previous write in the log. That way we can also try to emulate newer firmware versions.
     */
    for (;;)
    {
        PCPSPIOLOGRDREVT pIoEvt = NULL;
        int rc2 = PSPEmuIoLogRdrEvtQueryNext(pThis->hIoLogRdr, &pIoEvt);
        if (STS_SUCCESS(rc2))
        {
            if (   !pIoEvt->fWrite
                && pspIoLogReplayAddrIsEqual(pIoEvt, pAddr)
                && pIoEvt->idCcd == idCcd
                && pIoEvt->cbAcc == cbRead)
            {
                /* Transfer the data. */
                memcpy(pvVal, pIoEvt->pvData, cbRead);
                PSPEmuIoLogRdrEvtFree(pThis->hIoLogRdr, pIoEvt);
                rc = STS_INF_SUCCESS;
                break; /* Stop searching. */
            }

            PSPEmuIoLogRdrEvtFree(pThis->hIoLogRdr, pIoEvt);
        }
        else
        {
            rc = rc2;
            break;
        }
    }

    return rc;
}


static void pspIoLogReplayCcdPspMmioUnassignedRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPIOLOGREPLAYCCD pCcdRec = (PPSPIOLOGREPLAYCCD)pvUser;
    PPSPIOLOGREPLAYINT pThis = pCcdRec->pThis;
    PSPCOMBADDR Addr;

    Addr.enmAddrSpace = PSPADDRSPACE_PSP;
    Addr.u.PspAddr    = offMmio;
    int rc = pspIoLogReplayReadFind(pThis, 0 /*idCcd*/, &Addr, cbRead, pvVal);
    if (STS_FAILURE(rc))
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_MMIO,
                                "pspIoLogReplayReadFind() failed with %d\n", rc);
}


static void pspIoLogReplayCcdPspMmioUnassignedWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOLOGREPLAYCCD pCcdRec = (PPSPIOLOGREPLAYCCD)pvUser;
    PPSPIOLOGREPLAYINT pThis = pCcdRec->pThis;

    /* Writes will get ignored for now. */
}


static void pspIoLogReplayCcdPspSmnUnassignedRead(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPIOLOGREPLAYCCD pCcdRec = (PPSPIOLOGREPLAYCCD)pvUser;
    PPSPIOLOGREPLAYINT pThis = pCcdRec->pThis;
    PSPCOMBADDR Addr;

    Addr.enmAddrSpace = PSPADDRSPACE_SMN;
    Addr.u.SmnAddr    = offSmn;
    int rc = pspIoLogReplayReadFind(pThis, 0 /*idCcd*/, &Addr, cbRead, pvVal);
    if (STS_FAILURE(rc))
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_SMN,
                                "pspIoLogReplayReadFind() failed with %d\n", rc);
}


static void pspIoLogReplayCcdPspSmnUnassignedWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOLOGREPLAYCCD pCcdRec = (PPSPIOLOGREPLAYCCD)pvUser;
    PPSPIOLOGREPLAYINT pThis = pCcdRec->pThis;

    /* Writes will get ignored for now. */
}


static void pspIoLogReplayCcdX86UnassignedRead(X86PADDR offX86Phys, size_t cbRead, void *pvVal, bool fMmio,
                                               uint32_t fCaching, void *pvUser)
{
    PPSPIOLOGREPLAYCCD pCcdRec = (PPSPIOLOGREPLAYCCD)pvUser;
    PPSPIOLOGREPLAYINT pThis = pCcdRec->pThis;
    PSPCOMBADDR Addr;

    Addr.enmAddrSpace      = PSPADDRSPACE_X86;
    Addr.u.X86.PhysX86Addr = offX86Phys;
    Addr.u.X86.fCaching    = fCaching;
    int rc = pspIoLogReplayReadFind(pThis, 0 /*idCcd*/, &Addr, cbRead, pvVal);
    if (STS_FAILURE(rc))
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_X86,
                                "pspIoLogReplayReadFind() failed with %d\n", rc);
}


static void pspIoLogReplayCcdX86UnassignedWrite(X86PADDR offX86Phys, size_t cbWrite, const void *pvVal, bool fMmio,
                                                uint32_t fCaching, void *pvUser)
{
    PPSPIOLOGREPLAYCCD pCcdRec = (PPSPIOLOGREPLAYCCD)pvUser;
    PPSPIOLOGREPLAYINT pThis = pCcdRec->pThis;

    /* Writes will get ignored for now. */
}


int PSPIoLogReplayCreate(PPSPIOLOGREPLAY phIoLogReplay, const char *pszIoLogFilename)
{
    int rc = STS_INF_SUCCESS;

    PPSPIOLOGREPLAYINT pThis = (PPSPIOLOGREPLAYINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->pCcdsHead = NULL;

        printf("PSP I/O log: Opening %s\n", pszIoLogFilename);
        rc = PSPEmuIoLogRdrCreate(&pThis->hIoLogRdr, pszIoLogFilename);
        if (STS_SUCCESS(rc))
        {
            printf("PSP I/O log: Opened %s\n", pszIoLogFilename);
            *phIoLogReplay = pThis;
            return STS_INF_SUCCESS;
        }
        else
            fprintf(stderr, "Opening the I/O log failed with %d\n", rc);

        free(pThis);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


void PSPIoLogReplayDestroy(PSPIOLOGREPLAY hIoLogReplay)
{
    PPSPIOLOGREPLAYINT pThis = hIoLogReplay;

    PPSPIOLOGREPLAYCCD pCcdRec = pThis->pCcdsHead;
    while (pCcdRec)
    {
        PPSPIOLOGREPLAYCCD pFree = pCcdRec;
        pCcdRec = pCcdRec->pNext;

        free(pFree);
    }

    PSPEmuIoLogRdrDestroy(pThis->hIoLogRdr);
    free(pThis);
}


int PSPIoLogReplayCcdRegister(PSPIOLOGREPLAY hIoLogReplay, PSPCCD hCcd)
{
    PPSPIOLOGREPLAYINT pThis = hIoLogReplay;

    /** @todo Check for duplicates. */
    int rc = 0;
    PPSPIOLOGREPLAYCCD pCcdRec = (PPSPIOLOGREPLAYCCD)calloc(1, sizeof(*pCcdRec));
    if (pCcdRec)
    {
        PSPIOM hIoMgr;
        rc = PSPEmuCcdQueryIoMgr(hCcd, &hIoMgr);
        if (STS_SUCCESS(rc))
        {
            /* Register the unassigned handlers for the various regions. */
            rc = PSPEmuIoMgrMmioUnassignedSet(hIoMgr, pspIoLogReplayCcdPspMmioUnassignedRead, pspIoLogReplayCcdPspMmioUnassignedWrite,
                                              "<IOLOG>", pCcdRec);
            if (STS_SUCCESS(rc))
                rc = PSPEmuIoMgrSmnUnassignedSet(hIoMgr, pspIoLogReplayCcdPspSmnUnassignedRead, pspIoLogReplayCcdPspSmnUnassignedWrite,
                                                 "<IOLOG>", pCcdRec);
            if (STS_SUCCESS(rc))
                rc = PSPEmuIoMgrX86UnassignedSet(hIoMgr, pspIoLogReplayCcdX86UnassignedRead, pspIoLogReplayCcdX86UnassignedWrite,
                                                 "<IOLOG>", pCcdRec);
            if (STS_SUCCESS(rc))
            {
                pCcdRec->pThis = pThis;
                pCcdRec->hCcd  = hCcd;
                pCcdRec->pNext = pThis->pCcdsHead;

                pThis->pCcdsHead = pCcdRec;
                return STS_INF_SUCCESS;
            }
        }

        free(pCcdRec);
    }
    else
        rc = -1;

    return rc;
}


int PSPIoLogReplayCcdDeregister(PSPIOLOGREPLAY hIoLogReplay, PSPCCD hCcd)
{
    /** @todo */
    return STS_ERR_INVALID_PARAMETER;
}

