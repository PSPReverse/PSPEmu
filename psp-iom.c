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
#include <psp-trace.h>


/** Pointer to the internal I/O manager state. */
typedef struct PSPIOMINT *PPSPIOMINT;


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
    /** X86 memory region. */
    PSPIOMREGIONTYPE_X86_MEM,
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
    /** Owning I/O manager instance. */
    PPSPIOMINT                      pIoMgr;
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
        /** X86 MMIO/Memory region. */
        struct
        {
            /** Start address. */
            X86PADDR                PhysX86AddrStart;
            /** Size of the region. */
            size_t                  cbX86;
            /** Type dependent data. */
            union
            {
                /** MMIO specific data. */
                struct
                {
                    /** Read callback. */
                    PFNPSPIOMX86MMIOREAD    pfnRead;
                    /** Write callback. */
                    PFNPSPIOMX86MMIOWRITE   pfnWrite;
                } Mmio;
                /** Memory specific data. */
                struct
                {
                    /** Fetch callback. */
                    PFNPSPIOMX86MEMFETCH    pfnFetch;
                    /** Pointer to memory backing this region. */
                    void                    *pvMapping;
                    /** Amount of memory currently allocated. */
                    size_t                  cbAlloc;
                    /** Size of the region initialized with valid data so far. */
                    size_t                  cbValid;
                    /** Size of the highest written area so far (exclusive, defines range of memory to sync back). */
                    size_t                  cbWritten;
                } Mem;
            } u;
        } X86;
    } u;
} PSPIOMREGIONHANDLEINT;
/** Pointer to an internal region handle. */
typedef PSPIOMREGIONHANDLEINT *PPSPIOMREGIONHANDLEINT;


/**
 * X86 mapping control slot.
 */
typedef struct PSPIOMX86MAPCTRLSLOT
{
    uint32_t                        u32RegX86BaseAddr;
    uint32_t                        u32RegUnk1;
    uint32_t                        u32RegUnk2;
    uint32_t                        u32RegUnk3;
    uint32_t                        u32RegUnk4;
    uint32_t                        u32RegUnk5;
} PSPIOMX86MAPCTRLSLOT;
/** Pointer to a X86 mapping control slot. */
typedef PSPIOMX86MAPCTRLSLOT *PPSPIOMX86MAPCTRLSLOT;


/**
 * The internal I/O manager manager state.
 */
typedef struct PSPIOMINT
{
    /** The head of list of MMIO regions (@todo AVL tree?). */
    PPSPIOMREGIONHANDLEINT      pMmioHead;
    /** The head of list of SMN regions (@todo AVL tree?). */
    PPSPIOMREGIONHANDLEINT      pSmnHead;
    /** The head of list of X86 regions (@todo AVL tree?). */
    PPSPIOMREGIONHANDLEINT      pX86Head;
    /** Lowest MMIO address assigned to a region (for faster lookup). */
    PSPADDR                     PspAddrMmioLowest;
    /** Highes MMIO address assigned to a region (inclusive). */
    PSPADDR                     PspAddrMmioHighest;
    /** Lowest SMN address assigned to a device (for faster lookup). */
    SMNADDR                     SmnAddrLowest;
    /** Highes SMN address assigned to a device (inclusive). */
    SMNADDR                     SmnAddrHighest;
    /** Lowest X86 address assigned to a region (for faster lookup). */
    X86PADDR                    PhysX86AddrLowest;
    /** Highes X86 address assigned to a region (inclusive). */
    X86PADDR                    PhysX86AddrHighest;
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
    /** X86 mapping control slots. */
    PSPIOMX86MAPCTRLSLOT        aX86MapCtrlSlots[15];
} PSPIOMINT;


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


/**
 * Logs a read from the given region to the tracer.
 *
 * @returns nothing.
 * @param   pThis                   I/O manager instance.
 * @param   enmSeverity             The trace event severity.
 * @param   enmOrigin               The trace event origin.
 * @param   pszDevId                The device the read accessed, NULL means unknown.
 * @param   u64Addr                 The address of the region being read from.
 * @param   pvDst                   The data being read.
 * @param   cbRead                  Number of bytes read.
 */
static void pspEmuIomTraceRegionRead(PPSPIOMINT pThis, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                                     const char *pszDevId, uint64_t u64Addr, const void *pvDst, size_t cbRead)
{
    if (!pszDevId)
        pszDevId = "<UNKNOWN>";
    PSPEmuTraceEvtAddDevRead(NULL, enmSeverity, enmEvtOrigin, pszDevId, u64Addr, pvDst, cbRead);
}


/**
 * Logs a write to the given region to the tracer.
 *
 * @returns nothing.
 * @param   pThis                   I/O manager instance.
 * @param   enmSeverity             The trace event severity.
 * @param   enmOrigin               The trace event origin.
 * @param   pszDevId                The device the write accessed, NULL means unknown.
 * @param   u64Addr                 The address of the region being written to.
 * @param   pvData                  The data being written.
 * @param   cbWrite                 Number of bytes written.
 */
static void pspEmuIomTraceRegionWrite(PPSPIOMINT pThis, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                                      const char *pszDevId, uint64_t u64Addr, const void *pvData, size_t cbWrite)
{
    if (!pszDevId)
        pszDevId = "<UNKNOWN>";
    PSPEmuTraceEvtAddDevWrite(NULL, enmSeverity, enmEvtOrigin, pszDevId, u64Addr, pvData, cbWrite);
}


static void pspEmuIomUnassignedRegionRead(PPSPIOMINT pThis, PSPTRACEEVTORIGIN enmEvtOrigin, uint64_t u64Addr, void *pvDst, size_t cbRead)
{
    /* Unassigned read, log and return 0. */
    memset(pvDst, 0, cbRead);
    pspEmuIomTraceRegionRead(pThis, PSPTRACEEVTSEVERITY_WARNING, enmEvtOrigin, "<UNASSIGNED>", u64Addr, pvDst, cbRead);
}


static void pspEmuIomUnassignedRegionWrite(PPSPIOMINT pThis, PSPTRACEEVTORIGIN enmEvtOrigin, uint64_t u64Addr, const void *pvSrc, size_t cbWrite)
{
    pspEmuIomTraceRegionWrite(pThis, PSPTRACEEVTSEVERITY_WARNING, enmEvtOrigin, "<UNASSIGNED>", u64Addr, pvSrc, cbWrite);
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
        pspEmuIomUnassignedRegionRead(pThis, PSPTRACEEVTORIGIN_SMN, SmnAddr, pvDst, cbRead);
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
        pspEmuIomUnassignedRegionWrite(pThis, PSPTRACEEVTORIGIN_SMN, SmnAddr, pvSrc, cbWrite);
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
        pspEmuIomUnassignedRegionRead(pThis, PSPTRACEEVTORIGIN_MMIO, uPspAddr, pvDst, cbRead);
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
        pspEmuIomUnassignedRegionWrite(pThis, PSPTRACEEVTORIGIN_MMIO, uPspAddr, pvSrc, cbWrite);
}


/**
 * Finds the device assigned to the given SMN address or NULL if there is nothing assigned.
 *
 * @returns Pointer to the device assigned to the SMN address or NULL if none was found.
 * @param   pThis                   The I/O manager.
 * @param   PhysX86Addr             The absolute X86 physical address to look for.
 */
static PPSPIOMREGIONHANDLEINT pspEmuIomX86MapFindRegion(PPSPIOMINT pThis, X86PADDR PhysX86Addr)
{
    if (   PhysX86Addr < pThis->PhysX86AddrLowest
        || PhysX86Addr > pThis->PhysX86AddrHighest)
        return NULL;

    /* Slow path. */
    PPSPIOMREGIONHANDLEINT pCur = pThis->pX86Head;
    while (pCur)
    {
        if (   PhysX86Addr >= pCur->u.X86.PhysX86AddrStart
            && PhysX86Addr < pCur->u.X86.PhysX86AddrStart + pCur->u.X86.cbX86)
            return pCur;

        pCur = pCur->pNext;
    }

    return NULL;
}


static X86PADDR pspEmuIomGetPhysX86AddrFromSlotAndOffset(PPSPIOMINT pThis, PSPADDR offMmio)
{
    /* Each slot is 64MB big, so get the slot number by shifting the appropriate bits to the right. */
    uint32_t idxSlot = offMmio >> 26;
    uint32_t offSlot = offMmio & ((64 * _1M) - 1);

    if (idxSlot < ELEMENTS(pThis->aX86MapCtrlSlots))
    {
        uint32_t u32RegX86BaseAddr = pThis->aX86MapCtrlSlots[idxSlot].u32RegX86BaseAddr;
        X86PADDR PhysX86Base = (X86PADDR)(u32RegX86BaseAddr & 0x3f) << 26 | ((X86PADDR)(u32RegX86BaseAddr >> 6)) << 32;
        return PhysX86Base | offSlot;
    }
    else
        printf("ERROR: X86 mapping slot index out of range (is %u, max is %u)\n", idxSlot, ELEMENTS(pThis->aX86MapCtrlSlots));

    return 0;
}


/**
 * Ensures that the mapping is initialized properly for the given access.
 *
 * @returns Status code.
 * @param   pX86Region              The region being acccessed.
 * @param   offX86Mem               Offset where the access starts.
 * @param   cbAccess                Number of bytes being accessed.
 */
static int pspEmuIoMgrX86MemEnsureMapping(PPSPIOMREGIONHANDLEINT pX86Region, X86PADDR offX86Mem, size_t cbAccess)
{
    int rc = 0;

    /* Check whether the data at that address is already in memory and fetch it if required. */
    if (offX86Mem + cbAccess > pX86Region->u.X86.u.Mem.cbValid)
    {
        /* We cache always at 1K aligned segments. */
        size_t cbFetch = offX86Mem + cbAccess - pX86Region->u.X86.u.Mem.cbValid;

        /* Increase the mapping memory. */
        void *pvNew = realloc(pX86Region->u.X86.u.Mem.pvMapping, pX86Region->u.X86.u.Mem.cbAlloc + cbFetch);
        if (pvNew)
        {
            void *pvInit = (uint8_t *)pvNew + pX86Region->u.X86.u.Mem.cbValid;

            pX86Region->u.X86.u.Mem.pvMapping = pvNew;
            pX86Region->u.X86.u.Mem.cbAlloc   += cbFetch;

            /* Fetch initial memory content or just zero the memory if no callback is provided. */
            if (pX86Region->u.X86.u.Mem.pfnFetch)
                pX86Region->u.X86.u.Mem.pfnFetch(pX86Region->u.X86.u.Mem.cbValid, cbFetch, pvInit,
                                                 pX86Region->pvUser);
            else
                memset(pvInit, 0, cbFetch);

            pX86Region->u.X86.u.Mem.cbValid += cbFetch;
            return rc;
        }
        else
            rc = -1;
    }

    return rc;
}


/**
 * Read worker for a given X86 memory region, doing the fetching etc.
 *
 * @returns Status code.
 * @param   pThis                   The I/O manager instance owning the given X86 region.
 * @param   pX86Region              The X86 memory region to read from.
 * @param   offX86Mem               Offset from the start of the region to read from.
 * @param   pvDst                   Where to read into.
 * @param   cbRead                  Number of bytes to read.
 */
static int pspEmuIoMgrX86MemReadWorker(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pX86Region, X86PADDR offX86Mem, void *pvDst, size_t cbRead)
{
    int rc = pspEmuIoMgrX86MemEnsureMapping(pX86Region, offX86Mem, cbRead);
    if (!rc)
        memcpy(pvDst, (uint8_t *)pX86Region->u.X86.u.Mem.pvMapping + offX86Mem, cbRead);

    return rc;
}


/**
 * Write worker for a given X86 memory region.
 *
 * @returns Status code.
 * @param   pThis                   The I/O manager instance owning the given X86 region.
 * @param   pX86Region              The X86 memory region to write to.
 * @param   offX86Mem               Offset from the start of the region to write to.
 * @param   pvSrc                   What to write.
 * @param   cbWrite                 Number of bytes to write.
 */
static int pspEmuIoMgrX86MemWriteWorker(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pX86Region, X86PADDR offX86Mem, const void *pvSrc, size_t cbWrite)
{
    int rc = pspEmuIoMgrX86MemEnsureMapping(pX86Region, offX86Mem, cbWrite);
    if (!rc)
    {
        memcpy((uint8_t *)pX86Region->u.X86.u.Mem.pvMapping + offX86Mem, pvSrc, cbWrite);
        if (offX86Mem + cbWrite > pX86Region->u.X86.u.Mem.cbWritten)
            pX86Region->u.X86.u.Mem.cbWritten = offX86Mem + cbWrite;
    }

    return rc;
}


static void pspEmuIomX86MapRead(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    X86PADDR PhysX86Addr = pspEmuIomGetPhysX86AddrFromSlotAndOffset(pThis, uPspAddr);
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomX86MapFindRegion(pThis, PhysX86Addr);
    if (pRegion)
    {
        if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MMIO)
        {
            if (pRegion->u.X86.u.Mmio.pfnRead)
                pRegion->u.X86.u.Mmio.pfnRead(PhysX86Addr - pRegion->u.X86.PhysX86AddrStart, cbRead, pvDst, pRegion->pvUser);
            else
                pspEmuIomUnassignedRegionRead(pThis, PSPTRACEEVTORIGIN_X86_MMIO, PhysX86Addr, pvDst, cbRead);
        }
        else if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MEM)
            pspEmuIoMgrX86MemReadWorker(pThis, pRegion, PhysX86Addr - pRegion->u.X86.PhysX86AddrStart, pvDst, cbRead);
        else /* Huh? */
            pspEmuIomUnassignedRegionRead(pThis, PSPTRACEEVTORIGIN_X86_MMIO, PhysX86Addr, pvDst, cbRead); /** @todo assert or throw an error. */
    }
    else
        pspEmuIomUnassignedRegionRead(pThis, PSPTRACEEVTORIGIN_X86, PhysX86Addr, pvDst, cbRead);
}


static void pspEmuIomX86MapWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    X86PADDR PhysX86Addr = pspEmuIomGetPhysX86AddrFromSlotAndOffset(pThis, uPspAddr);
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomX86MapFindRegion(pThis, PhysX86Addr);
    if (pRegion)
    {
        if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MMIO)
        {
            if (pRegion->u.X86.u.Mmio.pfnWrite)
                pRegion->u.X86.u.Mmio.pfnWrite(PhysX86Addr - pRegion->u.X86.PhysX86AddrStart, cbWrite, pvSrc, pRegion->pvUser);
            else
                pspEmuIomUnassignedRegionWrite(pThis, PSPTRACEEVTORIGIN_X86_MMIO, PhysX86Addr, pvSrc, cbWrite);
        }
        else if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MEM)
            pspEmuIoMgrX86MemWriteWorker(pThis, pRegion, PhysX86Addr - pRegion->u.X86.PhysX86AddrStart, pvSrc, cbWrite);
        else /* Huh? */
            pspEmuIomUnassignedRegionWrite(pThis, PSPTRACEEVTORIGIN_X86_MMIO, PhysX86Addr, pvSrc, cbWrite); /** @todo assert or throw an error. */
    }
    else
        pspEmuIomUnassignedRegionWrite(pThis, PSPTRACEEVTORIGIN_X86, PhysX86Addr, pvSrc, cbWrite);
}


static void pspEmuIoMgrMmioSmnCtrlRead(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    switch (cbRead)
    {
        case 4:
        {
            /* Each 4 byte access programs two slots. */
            uint32_t idxSlotBase = (offMmio / 4) * 2;
            *(uint32_t *)pvDst = ((pThis->aSmnAddrBaseSlots[idxSlotBase + 1] >> 20) << 16) | (pThis->aSmnAddrBaseSlots[idxSlotBase] >> 20);
            break;
        }
        default:
            printf("Invalid read size %zu\n", cbRead);
    }
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
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_SMN,
                                    "MMIO/SMN: Mapping slot %u and %u to 0x%08x", idxSlotBase, idxSlotBase + 1, uSmnBaseVal);
            pThis->aSmnAddrBaseSlots[idxSlotBase]     = (uSmnBaseVal & 0xffff) << 20;
            pThis->aSmnAddrBaseSlots[idxSlotBase + 1] = (uSmnBaseVal >> 16) << 20;
            break;
        }
        case 2:
        {
            /* Each 4 byte access programs two slots. */
            uint32_t idxSlotBase = offMmio / 2;
            uint16_t uSmnBaseVal = *(uint16_t *)pvVal;
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_SMN,
                                    "MMIO/SMN: Mapping slot %u to 0x%08x", idxSlotBase, uSmnBaseVal);
            pThis->aSmnAddrBaseSlots[idxSlotBase] = uSmnBaseVal << 20;
            break;
        }
        default:
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_SMN,
                                    "Invalid write size %zu", cbWrite);
    }
}


static void pspEmuIoMgrX86MapSlotDump(PPSPIOMX86MAPCTRLSLOT pX86Slot, uint32_t idxSlot)
{
    printf("MMIO/X86: Slot %u\n"
           "    u32RegX86BaseAddr: 0x%08x\n"
           "    u32RegUnk1:        0x%08x\n"
           "    u32RegUnk2:        0x%08x\n"
           "    u32RegUnk3:        0x%08x\n"
           "    u32RegUnk4:        0x%08x\n"
           "    u32RegUnk5:        0x%08x\n", idxSlot,
           pX86Slot->u32RegX86BaseAddr, pX86Slot->u32RegUnk1, pX86Slot->u32RegUnk2,
           pX86Slot->u32RegUnk3, pX86Slot->u32RegUnk4, pX86Slot->u32RegUnk5);
}


static void pspEmuIoMgrX86MapCtrlRead(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uint32_t idxX86Slot = offMmio / (4 * sizeof(uint32_t));
    uint32_t offSlot = offMmio % (4 * sizeof(uint32_t));
    if (   idxX86Slot < ELEMENTS(pThis->aX86MapCtrlSlots)
        && cbRead == sizeof(uint32_t))
    {
        PPSPIOMX86MAPCTRLSLOT pX86Slot = &pThis->aX86MapCtrlSlots[idxX86Slot];

        switch (offSlot)
        {
            case 0:
            {
                *(uint32_t *)pvDst = pX86Slot->u32RegX86BaseAddr;
                break;
            }
            case 4:
            {
                *(uint32_t *)pvDst = pX86Slot->u32RegUnk1;
                break;
            }
            case 8:
            {
                *(uint32_t *)pvDst = pX86Slot->u32RegUnk2;
                break;
            }
            case 12:
            {
                *(uint32_t *)pvDst = pX86Slot->u32RegUnk3;
                break;
            }
            default:
                printf("MMIO/X86: Impossible slot offset offSlot=%u\n!", offSlot);
        }
    }
    else
        printf("MMIO/X86: Mapping control read offMmio=%x cbRead=%zu\n", offMmio, cbRead);
}


static void pspEmuIoMgrX86MapCtrlWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uint32_t idxX86Slot = offMmio / (4 * sizeof(uint32_t));
    uint32_t offSlot = offMmio % (4 * sizeof(uint32_t));
    if (   idxX86Slot < ELEMENTS(pThis->aX86MapCtrlSlots)
        && cbWrite == sizeof(uint32_t))
    {
        PPSPIOMX86MAPCTRLSLOT pX86Slot = &pThis->aX86MapCtrlSlots[idxX86Slot];

        switch (offSlot)
        {
            case 0:
            {
                pX86Slot->u32RegX86BaseAddr = *(uint32_t *)pvVal;
                break;
            }
            case 4:
            {
                pX86Slot->u32RegUnk1 = *(uint32_t *)pvVal;
                break;
            }
            case 8:
            {
                pX86Slot->u32RegUnk2 = *(uint32_t *)pvVal;
                break;
            }
            case 12:
            {
                pX86Slot->u32RegUnk3 = *(uint32_t *)pvVal;
                break;
            }
            default:
                printf("MMIO/X86: Impossible slot offset offSlot=%u\n!", offSlot);
        }
    }
    else
        printf("MMIO/X86: Mapping control write offMmio=%x cbWrite=%zu\n", offMmio, cbWrite);
}


static void pspEmuIoMgrX86MapCtrl2Read(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uint32_t idxX86Slot = offMmio / sizeof(uint32_t);
    if (   idxX86Slot < ELEMENTS(pThis->aX86MapCtrlSlots)
        && cbRead == sizeof(uint32_t))
    {
        PPSPIOMX86MAPCTRLSLOT pX86Slot = &pThis->aX86MapCtrlSlots[idxX86Slot];
        *(uint32_t *)pvDst = pX86Slot->u32RegUnk4;
    }
    else
        printf("MMIO/X86: Mapping control 2 read offMmio=%x cbRead=%zu\n", offMmio, cbRead);
}


static void pspEmuIoMgrX86MapCtrl2Write(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uint32_t idxX86Slot = offMmio / sizeof(uint32_t);
    if (   idxX86Slot < ELEMENTS(pThis->aX86MapCtrlSlots)
        && cbWrite == sizeof(uint32_t))
    {
        PPSPIOMX86MAPCTRLSLOT pX86Slot = &pThis->aX86MapCtrlSlots[idxX86Slot];
        pX86Slot->u32RegUnk4 = *(uint32_t *)pvVal;
    }
    else
        printf("MMIO/X86: Mapping control 2 write offMmio=%x cbWrite=%zu\n", offMmio, cbWrite);
}


static void pspEmuIoMgrX86MapCtrl3Read(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uint32_t idxX86Slot = offMmio / sizeof(uint32_t);
    if (   idxX86Slot < ELEMENTS(pThis->aX86MapCtrlSlots)
        && cbRead == sizeof(uint32_t))
    {
        PPSPIOMX86MAPCTRLSLOT pX86Slot = &pThis->aX86MapCtrlSlots[idxX86Slot];
        *(uint32_t *)pvDst = pX86Slot->u32RegUnk5;
    }
    else
        printf("MMIO/X86: Mapping control 3 read offMmio=%x cbRead=%zu\n", offMmio, cbRead);
}


static void pspEmuIoMgrX86MapCtrl3Write(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uint32_t idxX86Slot = offMmio / sizeof(uint32_t);
    if (   idxX86Slot < ELEMENTS(pThis->aX86MapCtrlSlots)
        && cbWrite == sizeof(uint32_t))
    {
        PPSPIOMX86MAPCTRLSLOT pX86Slot = &pThis->aX86MapCtrlSlots[idxX86Slot];
        pX86Slot->u32RegUnk5 = *(uint32_t *)pvVal;

        /* Dump the slot state as it is the last written register in the mapping method. */
        pspEmuIoMgrX86MapSlotDump(pX86Slot, idxX86Slot);
    }
    else
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
        pRegion->pIoMgr                  = pThis;
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


/**
 * Inserts the given X86 region (MMIO or memory) into the list of X86 regions.
 *
 * @returns Status code.
 * @param   pThis                   The I/O manager.
 * @param   pRegion                 The X86 region to insert.
 */
static int pspEmuIomX86RegionInsert(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pRegion)
{
    X86PADDR PhysX86AddrStart = pRegion->u.X86.PhysX86AddrStart;
    size_t cbX86 = pRegion->u.X86.cbX86;
    int rc = 0;

    PPSPIOMREGIONHANDLEINT pPrev = NULL;
    PPSPIOMREGIONHANDLEINT pCur = pThis->pX86Head;

    /* Search where to insert the new device, sorted by starting X86 address. */
    while (pCur)
    {
        if (pCur->u.X86.PhysX86AddrStart > PhysX86AddrStart)
            break;
        pPrev = pCur;
        pCur = pCur->pNext;
    }

    /* Do some sanity checks, the new X86 mapping range must not overlap with the previous and current device. */
    if (   (   !pPrev
            || pPrev->u.X86.PhysX86AddrStart + cbX86 <= PhysX86AddrStart)
        && (   !pCur
            || PhysX86AddrStart + cbX86 <= pCur->u.X86.PhysX86AddrStart))
    {
        pRegion->pNext = pCur;
        if (pPrev)
            pPrev->pNext = pRegion;
        else
            pThis->pX86Head = pRegion;

        /* Adjust the lowest and highest device range. */
        if (PhysX86AddrStart < pThis->PhysX86AddrLowest)
            pThis->PhysX86AddrLowest = PhysX86AddrStart;
        if (PhysX86AddrStart + cbX86 - 1 > pThis->PhysX86AddrHighest)
            pThis->PhysX86AddrHighest = PhysX86AddrStart + cbX86 - 1;
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
        pThis->pX86Head               = NULL;
        pThis->PspAddrMmioLowest      = 0xffffffff;
        pThis->PspAddrMmioHighest     = 0x00000000;
        pThis->SmnAddrLowest          = 0xffffffff;
        pThis->SmnAddrHighest         = 0x00000000;
        pThis->PhysX86AddrLowest      = 0xffffffffffffffff;
        pThis->PhysX86AddrHighest     = 0x0000000000000000;
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
                                                     pspEmuIoMgrMmioSmnCtrlRead, pspEmuIoMgrMmioSmnCtrlWrite,
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
        pRegion->pIoMgr             = pThis;
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
        pRegion->pIoMgr                 = pThis;
        pRegion->enmType                = PSPIOMREGIONTYPE_X86_MMIO;
        pRegion->pvUser                 = pvUser;
        pRegion->u.X86.PhysX86AddrStart = PhysX86AddrMmioStart;
        pRegion->u.X86.cbX86            = cbX86Mmio;
        pRegion->u.X86.u.Mmio.pfnRead   = pfnRead;
        pRegion->u.X86.u.Mmio.pfnWrite  = pfnWrite;

        rc = pspEmuIomX86RegionInsert(pThis, pRegion);
        if (!rc)
        {
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


int PSPEmuIoMgrX86MemRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrMemStart, size_t cbX86Mem,
                              PFNPSPIOMX86MEMFETCH pfnFetch, void *pvUser,
                              PPSPIOMREGIONHANDLE phX86Mem)
{
    int rc = 0;
    PPSPIOMINT pThis = hIoMgr;
    PPSPIOMREGIONHANDLEINT pRegion = (PPSPIOMREGIONHANDLEINT)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->pIoMgr                 = pThis;
        pRegion->enmType                = PSPIOMREGIONTYPE_X86_MEM;
        pRegion->pvUser                 = pvUser;
        pRegion->u.X86.PhysX86AddrStart = PhysX86AddrMemStart;
        pRegion->u.X86.cbX86            = cbX86Mem;
        pRegion->u.X86.u.Mem.pfnFetch   = pfnFetch;
        pRegion->u.X86.u.Mem.pvMapping  = NULL;
        pRegion->u.X86.u.Mem.cbAlloc    = 0;
        pRegion->u.X86.u.Mem.cbValid    = 0;
        pRegion->u.X86.u.Mem.cbWritten  = 0;

        rc = pspEmuIomX86RegionInsert(pThis, pRegion);
        if (!rc)
        {
            *phX86Mem = pRegion;
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


int PSPEmuIoMgrX86MemRead(PSPIOMREGIONHANDLE hX86Mem, X86PADDR offX86Mem, void *pvDst, size_t cbRead)
{
    PPSPIOMREGIONHANDLEINT pX86Region = hX86Mem;
    int rc = 0;

    if (pX86Region->enmType == PSPIOMREGIONTYPE_X86_MEM)
        rc = pspEmuIoMgrX86MemReadWorker(pX86Region->pIoMgr, pX86Region, offX86Mem, pvDst, cbRead);
    else
        rc = -1;

    return rc;
}


int PSPEmuIoMgrX86MemWrite(PSPIOMREGIONHANDLE hX86Mem, X86PADDR offX86Mem, const void *pvSrc, size_t cbWrite)
{
    PPSPIOMREGIONHANDLEINT pX86Region = hX86Mem;
    int rc = 0;

    if (pX86Region->enmType == PSPIOMREGIONTYPE_X86_MEM)
        rc = pspEmuIoMgrX86MemWriteWorker(pX86Region->pIoMgr, pX86Region, offX86Mem, pvSrc, cbWrite);
    else
        rc = -1;

    return rc;
}


int PSPEmuIoMgrDeregister(PSPIOMREGIONHANDLE hRegion)
{
    PPSPIOMREGIONHANDLEINT pRegion = hRegion;
    PPSPIOMINT pThis = pRegion->pIoMgr;
    PPSPIOMREGIONHANDLEINT *ppList = NULL;

    /* Get correct list head pointer from the region type. */
    switch (pRegion->enmType)
    {
        case PSPIOMREGIONTYPE_PSP_MMIO:
            ppList = &pThis->pMmioHead;
            break;
        case PSPIOMREGIONTYPE_SMN:
            ppList = &pThis->pSmnHead;
            break;
        case PSPIOMREGIONTYPE_X86_MMIO:
        case PSPIOMREGIONTYPE_X86_MEM:
            ppList = &pThis->pX86Head;
            break;
        default:
            return -1;
    }

    /* Search for the region in the list and unlink it. */
    PPSPIOMREGIONHANDLEINT pPrev = NULL;
    PPSPIOMREGIONHANDLEINT pCur = *ppList;

    while (   pCur
           && pCur != pRegion)
    {
        pPrev = pCur;
        pCur = pCur->pNext;
    }

    if (pCur)
    {
        /* Found */
        if (pPrev)
            pPrev->pNext = pCur->pNext;
        else
            *ppList = pCur->pNext;

        /* For X86 memory regions we have to destroy the backing memory. */
        /** @todo Sync mapping? */
        if (   pRegion->enmType == PSPIOMREGIONTYPE_X86_MEM
            && pRegion->u.X86.u.Mem.pvMapping)
            free(pRegion->u.X86.u.Mem.pvMapping);
        free(pRegion);
    }
    else /* Not found? */
        return -1;

    return 0;
}


int PSPEmuIoMgrPspAddrRead(PSPIOM hIoMgr, PSPADDR PspAddr, void *pvDst, size_t cbRead)
{
    PPSPIOMINT pThis = hIoMgr;

    /** @todo Access handlers. */
    return PSPEmuCoreMemRead(pThis->hPspCore, PspAddr, pvDst, cbRead);
}


int PSPEmuIoMgrPspAddrWrite(PSPIOM hIoMgr, PSPADDR PspAddr, const void *pvSrc, size_t cbWrite)
{
    PPSPIOMINT pThis = hIoMgr;

    /** @todo Access handlers. */
    return PSPEmuCoreMemWrite(pThis->hPspCore, PspAddr, pvSrc, cbWrite);
}

