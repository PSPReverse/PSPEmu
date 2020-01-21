/** @file
 * PSP Emulator - SMN devices interface.
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

#include <psp-smn-dev.h>


/**
 * The internal SMN manager state.
 */
typedef struct PSPSMNMINT
{
    /** The head of list of devices attached to the SMN space (@todo AVL tree?). */
    PPSPSMNDEV                  pDevsHead;
    /** Lowest SMN address assigned to a device (for faster lookup). */
    SMNADDR                     SmnAddrDevLowest;
    /** Highes SMN address assigned to a device (inclusive). */
    SMNADDR                     SmnAddrDevHighest;
    /** The MMIO manager handle this SMN manager is assigned to. */
    PSPMMIOM                    hMmioMgr;
    /** *The underlying PSP core handle this SMN manager is indirectly attached to through
     * the MMIO manager (for dumping state). */
    PSPCORE                     hPspCore;
    /** The MMIO device instance for the mapping slots. */
    PPSPMMIODEV                 pMmioDevSlots;
    /** The MMIO device instance for the control register interface. */
    PPSPMMIODEV                 pMmioDevCtrl;
    /** The currently mapped SMN base address for each slot (written by the control interface). */
    SMNADDR                     aSmnAddrBaseSlots[32];
} PSPSMNMINT;
/** Pointer to the internal SMN manager state. */
typedef PSPSMNMINT *PPSPSMNMINT;


/**
 * SMN device state.
 */
typedef struct PSPDEVSMN
{
    /** Pointer to the owning SMN manager instance. */
    PPSPSMNMINT                 pSmnMgr;
} PSPDEVSMN;
typedef PSPDEVSMN *PPSPDEVSMN;

static int pspDevSmnCtrlInit(PPSPMMIODEV pDev)
{
    /* Nothing to do. */
    return 0;
}

static void pspDevSmnCtrlDestruct(PPSPMMIODEV pDev)
{
    /* Nothing to do so far. */
}

static void pspDevSmnCtrlMmioRead(PPSPMMIODEV pDev, PSPADDR offMmio, size_t cbRead, void *pvVal)
{
    PPSPDEVSMN pSmnDev = (PPSPDEVSMN)&pDev->abInstance[0];
    PPSPSMNMINT pThis = pSmnDev->pSmnMgr;
}

static void pspDevSmnCtrlMmioWrite(PPSPMMIODEV pDev, PSPADDR offMmio, size_t cbWrite, const void *pvVal)
{
    PPSPDEVSMN pSmnDev = (PPSPDEVSMN)&pDev->abInstance[0];
    PPSPSMNMINT pThis = pSmnDev->pSmnMgr;

    switch (cbWrite)
    {
        case 4:
        {
            /* Each 4 byte access programs two slots. */
            uint32_t idxSlotBase = (offMmio / 4) * 2;
            uint32_t uSmnBaseVal = *(uint32_t *)pvVal;
            printf("MMIO/SMN: Mapping slot %u and %u to 0x%08x\n", idxSlotBase, idxSlotBase + 1, uSmnBaseVal);
            pThis->aSmnAddrBaseSlots[idxSlotBase]     = (uSmnBaseVal & 0xffff) << 20;
            pThis->aSmnAddrBaseSlots[idxSlotBase + 1] = (uSmnBaseVal >> 16) << 20;
            break;
        }
        default:
            printf("Invalid write size %zu\n", cbWrite);
    }
}


/**
 * Device registration structure for the SMN control interface.
 */
const PSPMMIODEVREG g_MmioDevRegSmnCtrl =
{
    /** pszName */
    "smn-ctrl",
    /** pszDesc */
    "SMN access control registers",
    /** cbInstance */
    sizeof(PSPDEVSMN),
    /** cbMmio */
    16 * sizeof(uint32_t),
    /** pfnInit */
    pspDevSmnCtrlInit,
    /** pfnDestruct */
    pspDevSmnCtrlDestruct,
    /** pfnMmioRead */
    pspDevSmnCtrlMmioRead,
    /** pfnMmioWrite */
    pspDevSmnCtrlMmioWrite
};


/**
 * Finds the device assigned to the given SMN address or NULL if there is nothing assigned.
 *
 * @returns Pointer to the device assigned to the SMN address or NULL if none was found.
 * @param   pThis                   The PSP SMN manager.
 * @param   SmnAddr                 The absolute SMN address to look for.
 */
static PPSPSMNDEV pspEmuSmnMgrFindDev(PPSPSMNMINT pThis, SMNADDR SmnAddr)
{
    if (   SmnAddr < pThis->SmnAddrDevLowest
        || SmnAddr > pThis->SmnAddrDevHighest)
        return NULL;

    /* Slow path. */
    PPSPSMNDEV pCur = pThis->pDevsHead;
    while (pCur)
    {
        if (   SmnAddr >= pCur->SmnStart
            && SmnAddr < pCur->SmnStart + pCur->pReg->cbSmn)
            return pCur;

        pCur = pCur->pNext;
    }

    return NULL;
}

static SMNADDR pspEmuSmnMgrGetSmnAddrFromSlotAndOffset(PPSPSMNMINT pThis, PSPADDR offMmio)
{
    /* Each slot is 1MB big, so get the slot number by shifting the appropriate bits to the right. */
    uint32_t idxSlot = offMmio >> 20;
    uint32_t offSlot = offMmio & (_1M - 1);

    if (idxSlot < ELEMENTS(pThis->aSmnAddrBaseSlots))
        return pThis->aSmnAddrBaseSlots[idxSlot] | offSlot;
    else
        printf("ERROR: SMN slot index out of range (is %u, max is %u)\n", idxSlot, ELEMENTS(pThis->aSmnAddrBaseSlots));

    return 0;
}

static int pspDevSmnSlotsInit(PPSPMMIODEV pDev)
{
    /* Nothing to do. */
    return 0;
}

static void pspDevSmnSlotsDestruct(PPSPMMIODEV pDev)
{
    /* Nothing to do so far. */
}

static void pspDevSmnSlotsMmioRead(PPSPMMIODEV pDev, PSPADDR offMmio, size_t cbRead, void *pvDst)
{
    PPSPDEVSMN pSmnSlots = (PPSPDEVSMN)&pDev->abInstance[0];
    PPSPSMNMINT pThis = pSmnSlots->pSmnMgr;


    SMNADDR SmnAddr = pspEmuSmnMgrGetSmnAddrFromSlotAndOffset(pThis, offMmio);
    PPSPSMNDEV pSmnDev = pspEmuSmnMgrFindDev(pThis, SmnAddr);
    if (pSmnDev)
        pSmnDev->pReg->pfnSmnRead(pSmnDev, SmnAddr - pSmnDev->SmnStart, cbRead, pvDst);
    else
    {
        /* Unassigned read, log and return 0. */
        printf("SMN: Unassigned read at 0x%08x (%zu bytes) -> returning 0\n", SmnAddr, cbRead);
        memset(pvDst, 0, cbRead);
        PSPEmuCoreStateDump(pThis->hPspCore);
    }
}

static void pspDevSmnSlotsMmioWrite(PPSPMMIODEV pDev, PSPADDR offMmio, size_t cbWrite, const void *pvSrc)
{
    PPSPDEVSMN pSmnSlots = (PPSPDEVSMN)&pDev->abInstance[0];
    PPSPSMNMINT pThis = pSmnSlots->pSmnMgr;

    SMNADDR SmnAddr = pspEmuSmnMgrGetSmnAddrFromSlotAndOffset(pThis, offMmio);
    PPSPSMNDEV pSmnDev = pspEmuSmnMgrFindDev(pThis, SmnAddr);
    if (pSmnDev)
        pSmnDev->pReg->pfnSmnWrite(pSmnDev, SmnAddr - pSmnDev->SmnStart, cbWrite, pvSrc);
    else
    {
        /* Unassigned read, log and return 0. */
        printf("SMN: Unassigned write at 0x%08x (%zu bytes) -> ignoring\n", SmnAddr, cbWrite);
        switch (cbWrite)
        {
            case 1:
                printf("SMN:    u8Val=%#x\n", *(uint8_t *)pvSrc);
                break;
            case 2:
                printf("SMN:    u16Val=%#x\n", *(uint16_t *)pvSrc);
                break;
            case 4:
                printf("SMN:    u32Val=%#x\n", *(uint32_t *)pvSrc);
                break;
            case 8:
                printf("SMN:    u64Val=%#llx\n", *(uint64_t *)pvSrc);
                break;
            default:
                printf("SMN:    Invalid write size!\n");
        }
        PSPEmuCoreStateDump(pThis->hPspCore);
    }
}


/**
 * Device registration structure for the SMN mapping slots.
 */
const PSPMMIODEVREG g_MmioDevRegSmnSlots =
{
    /** pszName */
    "smn-slots",
    /** pszDesc */
    "SMN access mapping slots",
    /** cbInstance */
    sizeof(PSPDEVSMN),
    /** cbMmio */
    32 * _1M,
    /** pfnInit */
    pspDevSmnSlotsInit,
    /** pfnDestruct */
    pspDevSmnSlotsDestruct,
    /** pfnMmioRead */
    pspDevSmnSlotsMmioRead,
    /** pfnMmioWrite */
    pspDevSmnSlotsMmioWrite
};

int PSPEmuSmnMgrCreate(PPSPSMNM phSmnMgr, PSPMMIOM hMmioMgr)
{
    int rc = 0;
    PPSPSMNMINT pThis = calloc(1, sizeof(*pThis));

    if (pThis)
    {
        pThis->pDevsHead         = NULL;
        pThis->SmnAddrDevLowest  = 0xffffffff;
        pThis->SmnAddrDevHighest = 0x00000000;
        pThis->hMmioMgr          = hMmioMgr;

        rc = PSPEmuMmioMgrQueryCore(hMmioMgr, &pThis->hPspCore);
        if (!rc)
        {
            rc = PSPEmuMmioDevCreate(hMmioMgr, &g_MmioDevRegSmnCtrl, 0x03220000, &pThis->pMmioDevCtrl);
            if (!rc)
            {
                rc = PSPEmuMmioDevCreate(hMmioMgr, &g_MmioDevRegSmnSlots, 0x01000000, &pThis->pMmioDevSlots);
                if (!rc)
                {
                    /* XXX Directly accessing the MMIO device instance data to set the SMN manager handle. */
                    PPSPDEVSMN pMmioDev = (PPSPDEVSMN)&pThis->pMmioDevCtrl->abInstance[0];
                    pMmioDev->pSmnMgr = pThis;
                    pMmioDev = (PPSPDEVSMN)&pThis->pMmioDevSlots->abInstance[0];
                    pMmioDev->pSmnMgr = pThis;

                    *phSmnMgr = pThis;
                    return 0;
                }
            }
        }
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuSmnMgrDestroy(PSPSMNM hSmnMgr)
{
    PPSPSMNMINT pThis = hSmnMgr;

    /** @todo Free  devices. */
    free(pThis);
    return 0;
}

int PSPEmuSmnDevCreate(PSPSMNM hSmnMgr, PCPSPSMNDEVREG pDevReg, SMNADDR SmnAddrStart, PPSPSMNDEV *ppSmnDev)
{
    int rc = 0;
    PPSPSMNMINT pThis = hSmnMgr;
    PPSPSMNDEV pDev = (PPSPSMNDEV)calloc(1, sizeof(*pDev) + pDevReg->cbInstance);
    if (pDev)
    {
        pDev->pReg      = pDevReg;
        pDev->hSmnMgr   = hSmnMgr;
        pDev->SmnStart  = SmnAddrStart;

        /* Initialize the device instance and add to the list of known devices. */
        rc = pDev->pReg->pfnInit(pDev);
        if (!rc)
        {
            PPSPSMNDEV pPrev = NULL;
            PPSPSMNDEV pCur = pThis->pDevsHead;

            /* Search where to insert the new device, sorted by starting SMN address. */
            while (pCur)
            {
                if (pCur->SmnStart > SmnAddrStart)
                    break;
                pPrev = pCur;
                pCur = pCur->pNext;
            }

            /* Do some sanity checks, the new SMN range must not overlap with the previous and current device. */
            if (   (   !pPrev
                    || pPrev->SmnStart + pPrev->pReg->cbSmn <= SmnAddrStart)
                && (   !pCur
                    || SmnAddrStart + pDevReg->cbSmn <= pCur->SmnStart))
            {
                pDev->pNext = pCur;
                if (pPrev)
                    pPrev->pNext = pDev;
                else
                    pThis->pDevsHead = pDev;

                /* Adjust the lowest and highest device range. */
                if (SmnAddrStart < pThis->SmnAddrDevLowest)
                    pThis->SmnAddrDevLowest = SmnAddrStart;
                if (SmnAddrStart + pDevReg->cbSmn - 1 > pThis->SmnAddrDevHighest)
                    pThis->SmnAddrDevHighest = SmnAddrStart + pDevReg->cbSmn - 1;

                *ppSmnDev = pDev;
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

int PSPEmuSmnDevDestroy(PPSPSMNDEV pSmnDev)
{
    /** @todo Unlink from list. */
    pSmnDev->pReg->pfnDestruct(pSmnDev);
    free(pSmnDev);
}

