/** @file
 * PSP Emulator - I/O manager.
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

#include <psp-iom.h>


/**
 * A region type
 */
typedef enum PSPIOMREGIONTYPE
{
    /** Invalid type, do not use. */
    PSPIOMREGIONTYPE_INVALID = 0,
    /** PSP MMIO region. */
    PSPIOMREGIONTYPE_PSP_MMIO,
    /** SMN region. */
    PSPIOMREGIONTYPE_SMN,
    /** X86 MMIO region. */
    PSPIOMREGIONTYPE_X86_MMIO,
    /** 32bit hack. */
    PSPIOMREGIONTYPE_32BIT_HACK = 0x7fffffff
} PSPIOMREGIONTYPE;
/** Pointer to a region type. */
typedef PSPIOMREGIONTYPE *PPSPIOMREGIONTYPE;


/**
 * A internal region handle.
 */
typedef struct PSPIOMREGIONHANDLEINT
{
    /** Region type. */
    PSPIOMREGIONTYPE                enmType;
    /** Pointer to the next region. */
    struct PSPIOMREGIONHANDLEINT    *pNext;
    /** Opaque user data to pass in the callbacks. */
    void                            *pvUser;
    /** Type dependent data. */
    union
    {
        /** MMIO region. */
        struct
        {
            /** Start address. */
            PSPADDR                 PspAddrMmioStart;
            /** Size of the region. */
            size_t                  cbMmio;
            /** Read callback. */
            PFNPSPIOMMMIOREAD       pfnRead;
            /** Write callback. */
            PFNPSPIOMMMIOWRITE      pfnWrite;
        } Mmio;
        /** SMN region. */
        struct
        {
            /** Start address. */
            SMNADDR                 SmnAddrStart;
            /** Size of the region. */
            size_t                  cbSmn;
            /** Read callback. */
            PFNPSPIOMSMNREAD        pfnRead;
            /** Write callback. */
            PFNPSPIOMSMNWRITE       pfnWrite;
        } Smn;
        /** X86 MMIO region. */
        struct
        {
            /** Start address. */
            X86PADDR                PhysX86AddrMmioStart;
            /** Size of the region. */
            size_t                  cbX86Mmio;
            /** Read callback. */
            PFNPSPIOMX86MMIOREAD    pfnRead;
            /** Write callback. */
            PFNPSPIOMX86MMIOWRITE   pfnWrite;
        } X86Mmio;
    } u;
} PSPIOMREGIONHANDLEINT;
/** Pointer to an internal region handle. */
typedef PSPIOMREGIONHANDLEINT *PPSPIOMREGIONHANDLEINT;


/**
 * The internal I/O manager manager state.
 */
typedef struct PSPIOMINT
{
    /** The head of list of MMIO regions (@todo AVL tree?). */
    PPSPIOMREGIONHANDLEINT      pMmioHead;
    /** The head of list of SMN regions (@todo AVL tree?). */
    PPSPIOMREGIONHANDLEINT      pSmnHead;
    /** The head of list of X86 MMIO regions (@todo AVL tree?). */
    PPSPIOMREGIONHANDLEINT      pX86MmioHead;
    /** Lowest MMIO address assigned to a region (for faster lookup). */
    PSPADDR                     PspAddrMmioLowest;
    /** Highes MMIO address assigned to a region (inclusive). */
    PSPADDR                     PspAddrMmioHighest;
    /** Lowest SMN address assigned to a device (for faster lookup). */
    SMNADDR                     SmnAddrLowest;
    /** Highes SMN address assigned to a device (inclusive). */
    SMNADDR                     SmnAddrHighest;
    /** Lowest X86 MMIO address assigned to a region (for faster lookup). */
    X86PADDR                    PhysX86AddrMmioLowest;
    /** Highes X86 MMIO address assigned to a region (inclusive). */
    X86PADDR                    PhysX86AddrMmioHighest;
    /** The PSP core handle this I/O manager is assigned to. */
    PSPCORE                     hPspCore;
    /** The currently mapped SMN base address for each slot (written by the control interface). */
    SMNADDR                     aSmnAddrBaseSlots[32];
    /** The MMIO region handle for the SMN control register interface. */
    PPSPIOMREGIONHANDLEINT      pMmioRegionSmnCtrl;
    /** The MMIO region handle for the X86 mapping control register interface. */
    PPSPIOMREGIONHANDLEINT      pMmioRegionX86MapCtrl;
    /** The MMIO region handle for the X86 mapping control register interface - second part. */
    PPSPIOMREGIONHANDLEINT      pMmioRegionX86MapCtrl2;
    /** The MMIO region handle for the X86 mapping control register interface - third part. */
    PPSPIOMREGIONHANDLEINT      pMmioRegionX86MapCtrl3;
} PSPIOMINT;
/** Pointer to the internal I/O manager state. */
typedef PSPIOMINT *PPSPIOMINT;


/**
 * Finds the device assigned to the given MMIO address or NULL if there is nothing assigned.
 *
 * @returns Pointer to the device assigned to the MMIO address or NULL if none was found.
 * @param   pThis                   The I/O manager.
 * @param   PspAddrMmio             The absolute MMIO address to look for.
 */
static PPSPIOMREGIONHANDLEINT pspEmuIomMmioFindRegion(PPSPIOMINT pThis, PSPADDR PspAddrMmio)
{
    if (   PspAddrMmio < pThis->PspAddrMmioLowest
        || PspAddrMmio > pThis->PspAddrMmioHighest)
        return NULL;

    /* Slow path. */
    PPSPIOMREGIONHANDLEINT pCur = pThis->pMmioHead;
    while (pCur)
    {
        if (   PspAddrMmio >= pCur->u.Mmio.PspAddrMmioStart
            && PspAddrMmio < pCur->u.Mmio.PspAddrMmioStart + pCur->u.Mmio.cbMmio)
            return pCur;

        pCur = pCur->pNext;
    }

    return NULL;
}


/**
 * Finds the device assigned to the given SMN address or NULL if there is nothing assigned.
 *
 * @returns Pointer to the device assigned to the SMN address or NULL if none was found.
 * @param   pThis                   The I/O manager.
 * @param   SmnAddr                 The absolute SMN address to look for.
 */
static PPSPIOMREGIONHANDLEINT pspEmuIomSmnFindRegion(PPSPIOMINT pThis, SMNADDR SmnAddr)
{
    if (   SmnAddr < pThis->SmnAddrLowest
        || SmnAddr > pThis->SmnAddrHighest)
        return NULL;

    /* Slow path. */
    PPSPIOMREGIONHANDLEINT pCur = pThis->pSmnHead;
    while (pCur)
    {
        if (   SmnAddr >= pCur->u.Smn.SmnAddrStart
            && SmnAddr < pCur->u.Smn.SmnAddrStart + pCur->u.Smn.cbSmn)
            return pCur;

        pCur = pCur->pNext;
    }

    return NULL;
}


static SMNADDR pspEmuIomGetSmnAddrFromSlotAndOffset(PPSPIOMINT pThis, PSPADDR offMmio)
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


static void pspEmuIomUnassignedRegionRead(PPSPIOMINT pThis, const char *pszSrc, uint64_t u64Addr, void *pvDst, size_t cbRead)
{
    /* Unassigned read, log and return 0. */
    printf("%s: Unassigned read at 0x%08llx (%zu bytes) -> returning 0\n", pszSrc, u64Addr, cbRead);
    memset(pvDst, 0, cbRead);
    PSPEmuCoreStateDump(pThis->hPspCore);
}


static void pspEmuIomUnassignedRegionWrite(PPSPIOMINT pThis, const char *pszSrc, uint64_t u64Addr, const void *pvSrc, size_t cbWrite)
{
    /* Unassigned write, log and ignre. */
    printf("%s: Unassigned write at 0x%08llx (%zu bytes) -> ignoring\n", pszSrc, u64Addr, cbWrite);
    switch (cbWrite)
    {
        case 1:
            printf("%s:    u8Val=%#x\n", pszSrc, *(uint8_t *)pvSrc);
            break;
        case 2:
            printf("%s:    u16Val=%#x\n", pszSrc, *(uint16_t *)pvSrc);
            break;
        case 4:
            printf("%s:    u32Val=%#x\n", pszSrc, *(uint32_t *)pvSrc);
            break;
        case 8:
            printf("%s:    u64Val=%#llx\n", pszSrc, *(uint64_t *)pvSrc);
            break;
        default:
            printf("%s:    Invalid write size!\n", pszSrc);
    }
    PSPEmuCoreStateDump(pThis->hPspCore);
}


static void pspEmuIomSmnSlotsRead(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    SMNADDR SmnAddr = pspEmuIomGetSmnAddrFromSlotAndOffset(pThis, uPspAddr);
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomSmnFindRegion(pThis, SmnAddr);
    if (   pRegion
        && pRegion->u.Smn.pfnRead)
        pRegion->u.Smn.pfnRead(SmnAddr - pRegion->u.Smn.SmnAddrStart, cbRead, pvDst, pRegion->pvUser);
    else
        pspEmuIomUnassignedRegionRead(pThis, "SMN", SmnAddr, pvDst, cbRead);
}


static void pspEmuIomSmnSlotsWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    SMNADDR SmnAddr = pspEmuIomGetSmnAddrFromSlotAndOffset(pThis, uPspAddr);
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomSmnFindRegion(pThis, SmnAddr);
    if (   pRegion
        && pRegion->u.Smn.pfnWrite)
        pRegion->u.Smn.pfnWrite(SmnAddr - pRegion->u.Smn.SmnAddrStart, cbWrite, pvSrc, pRegion->pvUser);
    else
        pspEmuIomUnassignedRegionWrite(pThis, "SMN", SmnAddr, pvSrc, cbWrite);
}


static void pspEmuIomMmioRead(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uPspAddr += 0x01000000 + 32 * _1M; /* The address contains the offset from the beginning of the registered range */
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomMmioFindRegion(pThis, uPspAddr);
    if (   pRegion
        && pRegion->u.Mmio.pfnRead)
        pRegion->u.Mmio.pfnRead(uPspAddr - pRegion->u.Mmio.PspAddrMmioStart, cbRead, pvDst, pRegion->pvUser);
    else
        pspEmuIomUnassignedRegionRead(pThis, "MMIO", uPspAddr, pvDst, cbRead);
}


static void pspEmuIomMmioWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uPspAddr += 0x01000000 + 32 * _1M; /* The address contains the offset from the beginning of the registered range */
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomMmioFindRegion(pThis, uPspAddr);
    if (   pRegion
        && pRegion->u.Mmio.pfnWrite)
        pRegion->u.Mmio.pfnWrite(uPspAddr - pRegion->u.Mmio.PspAddrMmioStart, cbWrite, pvSrc, pRegion->pvUser);
    else
        pspEmuIomUnassignedRegionWrite(pThis, "MMIO", uPspAddr, pvSrc, cbWrite);
}


static void pspEmuIomX86MapRead(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    /** @todo */
    pspEmuIomUnassignedRegionRead(pThis, "X86/MMIO", uPspAddr, pvDst, cbRead);
}


static void pspEmuIomX86MapWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    /** @todo */
    pspEmuIomUnassignedRegionWrite(pThis, "X86/MMIO", uPspAddr, pvSrc, cbWrite);
}


static void pspEmuIoMgrMmioSmnCtrlWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

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


static void pspEmuIoMgrX86MapCtrlRead(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;
    printf("MMIO/X86: Mapping control read offMmio=%x cbRead=%zu\n", offMmio, cbRead);
}


static void pspEmuIoMgrX86MapCtrlWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;
    printf("MMIO/X86: Mapping control write offMmio=%x cbWrite=%zu\n", offMmio, cbWrite);
}


static void pspEmuIoMgrX86MapCtrl2Read(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;
    printf("MMIO/X86: Mapping control 2 read offMmio=%x cbRead=%zu\n", offMmio, cbRead);
}


static void pspEmuIoMgrX86MapCtrl2Write(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;
    printf("MMIO/X86: Mapping control 2 write offMmio=%x cbWrite=%zu\n", offMmio, cbWrite);
}


static void pspEmuIoMgrX86MapCtrl3Read(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;
    printf("MMIO/X86: Mapping control 3 read offMmio=%x cbRead=%zu\n", offMmio, cbRead);
}


static void pspEmuIoMgrX86MapCtrl3Write(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;
    printf("MMIO/X86: Mapping control 3 write offMmio=%x cbWrite=%zu\n", offMmio, cbWrite);
}


static int pspEmuIomMmioRegionRegister(PPSPIOMINT pThis, PSPADDR PspAddrMmioStart, size_t cbMmio,
                                       PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, void *pvUser,
                                       PPSPIOMREGIONHANDLEINT *ppMmio)
{
    int rc = 0;
    PPSPIOMREGIONHANDLEINT pRegion = (PPSPIOMREGIONHANDLEINT)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->enmType                 = PSPIOMREGIONTYPE_PSP_MMIO;
        pRegion->pvUser                  = pvUser;
        pRegion->u.Mmio.PspAddrMmioStart = PspAddrMmioStart;
        pRegion->u.Mmio.cbMmio           = cbMmio;
        pRegion->u.Mmio.pfnRead          = pfnRead;
        pRegion->u.Mmio.pfnWrite         = pfnWrite;

        PPSPIOMREGIONHANDLEINT pPrev = NULL;
        PPSPIOMREGIONHANDLEINT pCur = pThis->pMmioHead;

        /* Search where to insert the new device, sorted by starting MMIO address. */
        while (pCur)
        {
            if (pCur->u.Mmio.PspAddrMmioStart > PspAddrMmioStart)
                break;
            pPrev = pCur;
            pCur = pCur->pNext;
        }

        /* Do some sanity checks, the new MMIO range must not overlap with the previous and current device. */
        if (   (   !pPrev
                || pPrev->u.Mmio.PspAddrMmioStart + cbMmio <= PspAddrMmioStart)
            && (   !pCur
                || PspAddrMmioStart + cbMmio <= pCur->u.Mmio.PspAddrMmioStart))
        {
            pRegion->pNext = pCur;
            if (pPrev)
                pPrev->pNext = pRegion;
            else
                pThis->pMmioHead = pRegion;

            /* Adjust the lowest and highest device range. */
            if (PspAddrMmioStart < pThis->PspAddrMmioLowest)
                pThis->PspAddrMmioLowest = PspAddrMmioStart;
            if (PspAddrMmioStart + cbMmio - 1 > pThis->PspAddrMmioHighest)
                pThis->PspAddrMmioHighest = PspAddrMmioStart + cbMmio - 1;

            *ppMmio = pRegion;
            return 0;
        }
        else
            rc = -1;

        free(pRegion);
    }
    else
        rc = -1;

    return rc;
}


int PSPEmuIoMgrCreate(PPSPIOM phIoMgr, PSPCORE hPspCore)
{
    int rc = 0;
    PPSPIOMINT pThis = calloc(1, sizeof(*pThis));

    if (pThis)
    {
        pThis->pMmioHead              = NULL;
        pThis->pSmnHead               = NULL;
        pThis->pX86MmioHead           = NULL;
        pThis->PspAddrMmioLowest      = 0xffffffff;
        pThis->PspAddrMmioHighest     = 0x00000000;
        pThis->SmnAddrLowest          = 0xffffffff;
        pThis->SmnAddrHighest         = 0x00000000;
        pThis->PhysX86AddrMmioLowest  = 0xffffffffffffffff;
        pThis->PhysX86AddrMmioHighest = 0x0000000000000000;
        pThis->hPspCore               = hPspCore;
        pThis->pMmioRegionSmnCtrl     = NULL;

        /* Register the MMIO region, where the SMN devices get mapped to (32 slots each 1MiB wide). */
        rc = PSPEmuCoreMmioRegister(hPspCore, 0x01000000, 32 * _1M,
                                    pspEmuIomSmnSlotsRead, pspEmuIomSmnSlotsWrite,
                                    pThis);
        if (!rc)
        {
            /* Register the remaining standard MMIO region. */
            rc = PSPEmuCoreMmioRegister(hPspCore, 0x03000000, 0x04000000 - 0x03000000,
                                        pspEmuIomMmioRead, pspEmuIomMmioWrite,
                                        pThis);
            if (!rc)
            {
                /* Register the region where the X86 memory mappings appear in. */
                rc = PSPEmuCoreMmioRegister(hPspCore, 0x04000000, 15 * 64 * _1M,
                                            pspEmuIomX86MapRead, pspEmuIomX86MapWrite,
                                            pThis);
                if (!rc)
                {
                    /* Register our SMN mapping control registers into the MMIO region. */
                    rc = pspEmuIomMmioRegionRegister(pThis, 0x03220000, 16 * sizeof(uint32_t),
                                                     NULL /*pfnRead*/, pspEmuIoMgrMmioSmnCtrlWrite,
                                                     pThis, &pThis->pMmioRegionSmnCtrl);
                    if (!rc)
                    {
                        /* Register our X86 mapping control registers into the MMIO region. */
                        rc = pspEmuIomMmioRegionRegister(pThis, 0x03230000, 15 * 4 * sizeof(uint32_t),
                                                         pspEmuIoMgrX86MapCtrlRead, pspEmuIoMgrX86MapCtrlWrite,
                                                         pThis, &pThis->pMmioRegionX86MapCtrl);
                        if (!rc)
                            rc = pspEmuIomMmioRegionRegister(pThis, 0x032303e0, 15 * sizeof(uint32_t),
                                                             pspEmuIoMgrX86MapCtrl2Read, pspEmuIoMgrX86MapCtrl2Write,
                                                             pThis, &pThis->pMmioRegionX86MapCtrl2);
                        if (!rc)
                            rc = pspEmuIomMmioRegionRegister(pThis, 0x032304d8, 15 * sizeof(uint32_t),
                                                             pspEmuIoMgrX86MapCtrl3Read, pspEmuIoMgrX86MapCtrl3Write,
                                                             pThis, &pThis->pMmioRegionX86MapCtrl3);
                        if(!rc)
                        {
                            *phIoMgr = pThis;
                            return 0;
                        }

                        if (pThis->pMmioRegionX86MapCtrl3)
                            PSPEmuIoMgrDeregister(pThis->pMmioRegionX86MapCtrl3);
                        if (pThis->pMmioRegionX86MapCtrl2)
                            PSPEmuIoMgrDeregister(pThis->pMmioRegionX86MapCtrl2);
                        if (pThis->pMmioRegionX86MapCtrl)
                            PSPEmuIoMgrDeregister(pThis->pMmioRegionX86MapCtrl);
                    }

                    PSPEmuCoreMmioDeregister(pThis->hPspCore, 0x04000000, 15 * 64 * _1M);
                }

                PSPEmuCoreMmioDeregister(pThis->hPspCore, 0x03000000, 0x04000000 - 0x03000000);
            }

            PSPEmuCoreMmioDeregister(pThis->hPspCore, 0x01000000, 32 * _1M);
        }

        free(pThis);
    }
    else
        rc = -1;

    return rc;
}


int PSPEmuIoMgrDestroy(PSPIOM hIoMgr)
{
    PPSPIOMINT pThis = hIoMgr;

    int rc = PSPEmuCoreMmioDeregister(pThis->hPspCore, 0x01000000, 0x01000000 + 32 * _1M);
    if (!rc)
        rc = PSPEmuCoreMmioDeregister(pThis->hPspCore, 0x01000000 + 32 * _1M, 0x44000000);
    /** @todo Free devices. */
    free(pThis);
    return rc;
}


int PSPEmuIoMgrMmioRegister(PSPIOM hIoMgr, PSPADDR PspAddrMmioStart, size_t cbMmio,
                            PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, void *pvUser,
                            PPSPIOMREGIONHANDLE phMmio)
{
    PPSPIOMINT pThis = hIoMgr;

    return pspEmuIomMmioRegionRegister(pThis, PspAddrMmioStart, cbMmio,
                                       pfnRead, pfnWrite, pvUser, phMmio);
}


int PSPEmuIoMgrSmnRegister(PSPIOM hIoMgr, SMNADDR SmnAddrStart, size_t cbSmn,
                           PFNPSPIOMSMNREAD pfnRead, PFNPSPIOMSMNWRITE pfnWrite, void *pvUser,
                           PPSPIOMREGIONHANDLE phSmn)
{
    int rc = 0;
    PPSPIOMINT pThis = hIoMgr;
    PPSPIOMREGIONHANDLEINT pRegion = (PPSPIOMREGIONHANDLEINT)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->enmType            = PSPIOMREGIONTYPE_SMN;
        pRegion->pvUser             = pvUser;
        pRegion->u.Smn.SmnAddrStart = SmnAddrStart;
        pRegion->u.Smn.cbSmn        = cbSmn;
        pRegion->u.Smn.pfnRead      = pfnRead;
        pRegion->u.Smn.pfnWrite     = pfnWrite;

        PPSPIOMREGIONHANDLEINT pPrev = NULL;
        PPSPIOMREGIONHANDLEINT pCur = pThis->pSmnHead;

        /* Search where to insert the new device, sorted by starting SMN address. */
        while (pCur)
        {
            if (pCur->u.Smn.SmnAddrStart > SmnAddrStart)
                break;
            pPrev = pCur;
            pCur = pCur->pNext;
        }

        /* Do some sanity checks, the new SMN range must not overlap with the previous and current device. */
        if (   (   !pPrev
                || pPrev->u.Smn.SmnAddrStart + cbSmn <= SmnAddrStart)
            && (   !pCur
                || SmnAddrStart + cbSmn <= pCur->u.Smn.SmnAddrStart))
        {
            pRegion->pNext = pCur;
            if (pPrev)
                pPrev->pNext = pRegion;
            else
                pThis->pSmnHead = pRegion;

            /* Adjust the lowest and highest device range. */
            if (SmnAddrStart < pThis->SmnAddrLowest)
                pThis->SmnAddrLowest = SmnAddrStart;
            if (SmnAddrStart + cbSmn - 1 > pThis->SmnAddrHighest)
                pThis->SmnAddrHighest = SmnAddrStart + cbSmn - 1;

            *phSmn = pRegion;
            return 0;
        }
        else
            rc = -1;

        free(pRegion);
    }
    else
        rc = -1;

    return rc;
}


int PSPEmuIoMgrX86MmioRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrMmioStart, size_t cbX86Mmio,
                               PFNPSPIOMX86MMIOREAD pfnRead, PFNPSPIOMX86MMIOWRITE pfnWrite, void *pvUser,
                               PPSPIOMREGIONHANDLE phX86Mmio)
{
    int rc = 0;
    PPSPIOMINT pThis = hIoMgr;
    PPSPIOMREGIONHANDLEINT pRegion = (PPSPIOMREGIONHANDLEINT)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->enmType                        = PSPIOMREGIONTYPE_X86_MMIO;
        pRegion->pvUser                         = pvUser;
        pRegion->u.X86Mmio.PhysX86AddrMmioStart = PhysX86AddrMmioStart;
        pRegion->u.X86Mmio.cbX86Mmio            = cbX86Mmio;
        pRegion->u.X86Mmio.pfnRead              = pfnRead;
        pRegion->u.X86Mmio.pfnWrite             = pfnWrite;

        PPSPIOMREGIONHANDLEINT pPrev = NULL;
        PPSPIOMREGIONHANDLEINT pCur = pThis->pX86MmioHead;

        /* Search where to insert the new device, sorted by starting SMN address. */
        while (pCur)
        {
            if (pCur->u.X86Mmio.PhysX86AddrMmioStart > PhysX86AddrMmioStart)
                break;
            pPrev = pCur;
            pCur = pCur->pNext;
        }

        /* Do some sanity checks, the new X86 mapping range must not overlap with the previous and current device. */
        if (   (   !pPrev
                || pPrev->u.X86Mmio.PhysX86AddrMmioStart + cbX86Mmio <= PhysX86AddrMmioStart)
            && (   !pCur
                || PhysX86AddrMmioStart + cbX86Mmio <= pCur->u.X86Mmio.PhysX86AddrMmioStart))
        {
            pRegion->pNext = pCur;
            if (pPrev)
                pPrev->pNext = pRegion;
            else
                pThis->pSmnHead = pRegion;

            /* Adjust the lowest and highest device range. */
            if (PhysX86AddrMmioStart < pThis->PhysX86AddrMmioLowest)
                pThis->PhysX86AddrMmioLowest = PhysX86AddrMmioStart;
            if (PhysX86AddrMmioStart + cbX86Mmio - 1 > pThis->PhysX86AddrMmioHighest)
                pThis->PhysX86AddrMmioHighest = PhysX86AddrMmioStart + cbX86Mmio - 1;

            *phX86Mmio = pRegion;
            return 0;
        }
        else
            rc = -1;

        free(pRegion);
    }
    else
        rc = -1;

    return rc;
}


int PSPEmuIoMgrDeregister(PSPIOMREGIONHANDLE hRegion)
{
    /** @todo */
    return -1;
}
