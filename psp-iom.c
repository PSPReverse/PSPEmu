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
 * Trace handler type.
 */
typedef enum PSPIOMTRACETYPE
{
    /** Invalid type. */
    PSPIOMTRACETYPE_INVALID = 0,
    /** MMIO trace handler. */
    PSPIOMTRACETYPE_MMIO,
    /** SMN trace handler. */
    PSPIOMTRACETYPE_SMN,
    /** X86 trace handler. */
    PSPIOMTRACETYPE_X86,
    /** 32bit hack. */
    PSPIOMTRACETYPE_32BIT_HACK = 0x7fffffff
} PSPIOMTRACETYPE;
/** Pointer to a trace handler type. */
typedef PSPIOMTRACETYPE *PPSPIOMTRACETYPE;


/**
 * Trace handler record.
 */
typedef struct PSPIOMTPINT
{
    /** Pointer to the next record. */
    struct PSPIOMTPINT              *pNext;
    /** I/O manager this belongs to. */
    PPSPIOMINT                      pIoMgr;
    /** Access size. */
    size_t                          cbAccess;
    /** Flags given during registration. */
    uint32_t                        fFlags;
    /** Opaque user data to pass to the handler. */
    void                            *pvUser;
    /** Trace type. */
    PSPIOMTRACETYPE                 enmType;
    /** Type dependent data. */
    union
    {
        /** MMIO trace. */
        struct
        {
            /** The start MMIO address to hit at. */
            PSPADDR                 PspAddrMmioStart;
            /** The start MMIO address to stop hitting at. */
            PSPADDR                 PspAddrMmioEnd;
            /** The handler to call. */
            PFNPSPIOMMMIOTRACE      pfnTrace;
        } Mmio;
        /** SMN trace. */
        struct
        {
            /** The start SMN address to hit at. */
            SMNADDR                 SmnAddrStart;
            /** The start SMN address to stop hitting at. */
            SMNADDR                 SmnAddrEnd;
            /** The handler to call. */
            PFNPSPIOMSMNTRACE       pfnTrace;
        } Smn;
        /** x86 trace. */
        struct
        {
            /** The start x86 physical address to hit at. */
            X86PADDR                PhysX86AddrStart;
            /** The start x86 physical address to stop hitting at. */
            X86PADDR                PhysX86AddrEnd;
            /** The handler to call. */
            PFNPSPIOMX86TRACE       pfnTrace;
        } X86;
    } u;
} PSPIOMTPINT;
/** Pointer to a trace handler record. */
typedef PSPIOMTPINT *PPSPIOMTPINT;
/** Pointer to a const trace handler record. */
typedef const PSPIOMTPINT *PCPSPIOMTPINT;


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
    /** Description for this region. */
    const char                      *pszDesc;
    /** Flags for this region. */
    uint32_t                        fFlags;
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
                    /** Pointer to the next exectuable memory region (only valid if  fCanExec is true). */
                    struct PSPIOMREGIONHANDLEINT *pExecNext;
                    /** Fetch callback. */
                    PFNPSPIOMX86MEMFETCH         pfnFetch;
                    /** Pointer to memory backing this region. */
                    void                         *pvMapping;
                    /** Amount of memory currently allocated. */
                    size_t                       cbAlloc;
                    /** Size of the region initialized with valid data so far. */
                    size_t                       cbValid;
                    /** Size of the highest written area so far (exclusive, defines range of memory to sync back). */
                    size_t                       cbWritten;
                    /** Flag whether the memory should be made executable to the core. */
                    bool                         fCanExec;
                } Mem;
            } u;
        } X86;
    } u;
} PSPIOMREGIONHANDLEINT;
/** Pointer to an internal region handle. */
typedef PSPIOMREGIONHANDLEINT *PPSPIOMREGIONHANDLEINT;

/** The region has a read handler. */
#define PSP_IOM_REGION_F_READ           BIT(0)
/** The region has a write handler. */
#define PSP_IOM_REGION_F_WRITE          BIT(1)


/** Forward declaration of a X86 mapping control slot pointer. */
typedef struct PSPIOMX86MAPCTRLSLOT *PPSPIOMX86MAPCTRLSLOT;

/**
 * X86 split MMIO descriptor.
 */
typedef struct PSPIOMX86MMIOSPLIT
{
    /** Owning x86 mapping control slot. */
    PPSPIOMX86MAPCTRLSLOT       pX86MapSlot;
    /** Start PSP MMIO address of the split region. */
    PSPADDR                     PspAddrMmioStart;
    /** Size of the split region. */
    size_t                      cbMmio;
} PSPIOMX86MMIOSPLIT;
/** Pointer to a X86 split MMIO descriptor. */
typedef PSPIOMX86MMIOSPLIT *PPSPIOMX86MMIOSPLIT;
/** Pointer to a const X86 split MMIO descriptor. */
typedef const PSPIOMX86MMIOSPLIT *PCPSPIOMX86MMIOSPLIT;


/**
 * X86 mapping control slot.
 */
typedef struct PSPIOMX86MAPCTRLSLOT
{
    /** Pointer to the owning I/O manager instance. */
    PPSPIOMINT                      pIoMgr;
    /** Base MMIO address this slot starts at. */
    PSPADDR                         PspAddrMmioStart;
    /** Size of the slot (should be equal for all). */
    size_t                          cbMmio;
    /** The x86 physical base address currently mapped. */
    X86PADDR                        PhysX86Base;

    /** The x86 memory region mapped executable,
     * We only allow only one for now. */
    PPSPIOMREGIONHANDLEINT          pX86MemExec;
    /** PSP address the memory region is mapped to. */
    PSPADDR                         PspAddrMemExecStart;
    /** Size of the executable memory region. */
    size_t                          cbMemExec;

    /* Split MMIO region data if any (before and after executable region). */
    PSPIOMX86MMIOSPLIT              aSplitMmio[2];

    /** @name Register interface accessible from MMIO space.
     * @{ */
    uint32_t                        u32RegX86BaseAddr;
    uint32_t                        u32RegUnk1;
    uint32_t                        u32RegUnk2;
    uint32_t                        u32RegUnk3;
    uint32_t                        u32RegUnk4;
    uint32_t                        u32RegUnk5;
    /** @} */
} PSPIOMX86MAPCTRLSLOT;


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
    /** The head of list of X86 memory regions with exec permissions. */
    PPSPIOMREGIONHANDLEINT      pX86MemExecHead;
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

    /** Callback for unassigned MMIO reads. */
    PFNPSPIOMMMIOREAD           pfnMmioUnassignedRead;
    /** Callback for unassigned MMIO writes. */
    PFNPSPIOMMMIOWRITE          pfnMmioUnassignedWrite;
    /** Opaque user data for the unassigned MMIO read/write callbacks. */
    void                        *pvUserMmioUnassigned;

    /** Callback for unassigned SMN reads. */
    PFNPSPIOMSMNREAD            pfnSmnUnassignedRead;
    /** Callback for unassigned SMN writes. */
    PFNPSPIOMSMNWRITE           pfnSmnUnassignedWrite;
    /** Opaque user data for the unassigned SMN read/write callbacks. */
    void                        *pvUserSmnUnassigned;

    /** Callback for unassigned x86 reads. */
    PFNPSPIOMX86MMIOREAD        pfnX86UnassignedRead;
    /** Callback for unassigned x86 writes. */
    PFNPSPIOMX86MMIOWRITE       pfnX86UnassignedWrite;
    /** Opaque user data for the unassigned x86 read/write callbacks. */
    void                        *pvUserX86Unassigned;

    /** Registered trace points. */
    PPSPIOMTPINT                pTpHead;
    /** Flag whether to log all accesses or only ones to unassigned regions. */
    bool                        fLogAllAccesses;
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


/**
 * Returns the next trace point from the given start matching the given parameters.
 *
 * @returns Pointer to matching trace point or NULL if none exists.
 * @param   pFirst                  The first trace pint record to check.
 * @param   enmType                 Trace point should match the given type.
 * @param   cbAccess                Access width, 1, 2 or 4 byte.
 * @param   fFlagsRw                Read/Write flags matching the trace point.
 * @param   fFlagsAp                Access point (before/after) flags matching the trace point.
 */
static PCPSPIOMTPINT pspEmuIomTpFindNext(PCPSPIOMTPINT pFirst, PSPIOMTRACETYPE enmType, size_t cbAccess,
                                         uint32_t fFlagsRw, uint32_t fFlagsAp)
{
    while (pFirst)
    {
        if (   pFirst->enmType == enmType
            && (   pFirst->cbAccess == cbAccess
                || !pFirst->cbAccess) /* 0 matches all access widths. */
            && (pFirst->fFlags & fFlagsRw) != 0
            && (pFirst->fFlags & fFlagsAp) != 0)
            return pFirst;

        pFirst = pFirst->pNext;
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
 * @param   pRegion                 The region or NULL if unassigned.
 * @param   enmOrigin               The trace event origin.
 * @param   u64Addr                 The address of the region being read from.
 * @param   pvDst                   The data being read.
 * @param   cbRead                  Number of bytes read.
 */
static void pspEmuIomTraceRegionRead(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pRegion, PSPTRACEEVTORIGIN enmEvtOrigin,
                                     uint64_t u64Addr, const void *pvDst, size_t cbRead)
{
    PSPTRACEEVTSEVERITY enmSeverity = PSPTRACEEVTSEVERITY_INFO;
    const char *pszRegId = NULL;

    if (   !pRegion
        || !(pRegion->fFlags & PSP_IOM_REGION_F_READ)) /* Writeonly regions get treated as unassigned for now. */
    {
        pszRegId = "<UNASSIGNED>";
        enmSeverity = PSPTRACEEVTSEVERITY_WARNING;
    }
    else if (pThis->fLogAllAccesses)
    {
        if (!pRegion->pszDesc)
            pszRegId = "<UNKNOWN>";
        else
            pszRegId = pRegion->pszDesc;
    }

    if (pszRegId)
        PSPEmuTraceEvtAddDevRead(NULL, enmSeverity, enmEvtOrigin, pszRegId, u64Addr, pvDst, cbRead);
}


/**
 * Logs a write to the given region to the tracer.
 *
 * @returns nothing.
 * @param   pThis                   I/O manager instance.
 * @param   pRegion                 The region or NULL if unassigned.
 * @param   enmOrigin               The trace event origin.
 * @param   u64Addr                 The address of the region being written to.
 * @param   pvData                  The data being written.
 * @param   cbWrite                 Number of bytes written.
 */
static void pspEmuIomTraceRegionWrite(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pRegion, PSPTRACEEVTORIGIN enmEvtOrigin,
                                      uint64_t u64Addr, const void *pvData, size_t cbWrite)
{
    PSPTRACEEVTSEVERITY enmSeverity = PSPTRACEEVTSEVERITY_INFO;
    const char *pszRegId = NULL;

    if (   !pRegion
        || !(pRegion->fFlags & PSP_IOM_REGION_F_WRITE)) /* Readonly regions get treated as unassigned for now. */
    {
        pszRegId = "<UNASSIGNED>";
        enmSeverity = PSPTRACEEVTSEVERITY_WARNING;
    }
    else if (pThis->fLogAllAccesses)
    {
        if (!pRegion->pszDesc)
            pszRegId = "<UNKNOWN>";
        else
            pszRegId = pRegion->pszDesc;
    }

    if (pszRegId)
        PSPEmuTraceEvtAddDevWrite(NULL, enmSeverity, enmEvtOrigin, pszRegId, u64Addr, pvData, cbWrite);
}


/**
 * Calls all matching SMN trace points for the given access pattern.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager.
 * @param   SmnAddr                 SMN address which got hit.
 * @param   pRegion                 The region registered for this address if any, NULL if unassigned.
 * @param   cbAccess                Access width.
 * @param   pvVal                   The value for the access.
 * @param   fFlagsRw                Read/Write flags matching the trace point.
 * @param   fFlagsAp                Access point (before/after) flags matching the trace point.
 */
static void pspEmuIomSmnTpCall(PPSPIOMINT pThis, SMNADDR SmnAddr, PPSPIOMREGIONHANDLEINT pRegion, size_t cbAccess, const void *pvVal,
                               uint32_t fFlagsRw, uint32_t fFlagsAp)
{
    PCPSPIOMTPINT pTp = pThis->pTpHead;
    for (;;)
    {
        pTp = pspEmuIomTpFindNext(pTp, PSPIOMTRACETYPE_SMN, cbAccess, fFlagsRw, fFlagsAp);
        if (!pTp)
            break;
        if (   SmnAddr >= pTp->u.Smn.SmnAddrStart
            && SmnAddr <= pTp->u.Smn.SmnAddrEnd)
            pTp->u.Smn.pfnTrace(SmnAddr,
                                pRegion ? NULL : NULL, /** @todo Description */
                                pRegion ? SmnAddr - pRegion->u.Smn.SmnAddrStart : 0,
                                cbAccess,
                                pvVal,
                                fFlagsRw | fFlagsAp,
                                pTp->pvUser);

        pTp = pTp->pNext;
    }
}


/**
 * Calls all matching MMIO trace points for the given access pattern.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager.
 * @param   PspAddrMmio             MMIO address which got hit.
 * @param   pRegion                 The region registered for this address if any, NULL if unassigned.
 * @param   cbAccess                Access width.
 * @param   pvVal                   The value for the access.
 * @param   fFlagsRw                Read/Write flags matching the trace point.
 * @param   fFlagsAp                Access point (before/after) flags matching the trace point.
 */
static void pspEmuIomMmioTpCall(PPSPIOMINT pThis, PSPADDR PspAddrMmio, PPSPIOMREGIONHANDLEINT pRegion, size_t cbAccess, const void *pvVal,
                                uint32_t fFlagsRw, uint32_t fFlagsAp)
{
    PCPSPIOMTPINT pTp = pThis->pTpHead;
    for (;;)
    {
        pTp = pspEmuIomTpFindNext(pTp, PSPIOMTRACETYPE_MMIO, cbAccess, fFlagsRw, fFlagsAp);
        if (!pTp)
            break;
        if (   PspAddrMmio >= pTp->u.Mmio.PspAddrMmioStart
            && PspAddrMmio <= pTp->u.Mmio.PspAddrMmioEnd)
            pTp->u.Mmio.pfnTrace(PspAddrMmio,
                                 pRegion ? NULL : NULL, /** @todo Description */
                                 pRegion ? PspAddrMmio - pRegion->u.Mmio.PspAddrMmioStart : 0,
                                 cbAccess,
                                 pvVal,
                                 fFlagsRw | fFlagsAp,
                                 pTp->pvUser);

        pTp = pTp->pNext;
    }
}


/**
 * Calls all matching x86 trace points for the given access pattern.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager.
 * @param   PhysX86Addr             Physical X86 address which got hit.
 * @param   pRegion                 The region registered for this address if any, NULL if unassigned.
 * @param   cbAccess                Access width.
 * @param   pvVal                   The value for the access.
 * @param   fFlagsRw                Read/Write flags matching the trace point.
 * @param   fFlagsAp                Access point (before/after) flags matching the trace point.
 */
static void pspEmuIomX86TpCall(PPSPIOMINT pThis, X86PADDR PhysX86Addr, PPSPIOMREGIONHANDLEINT pRegion, size_t cbAccess, const void *pvVal,
                               uint32_t fFlagsRw, uint32_t fFlagsAp)
{
    PCPSPIOMTPINT pTp = pThis->pTpHead;
    for (;;)
    {
        pTp = pspEmuIomTpFindNext(pTp, PSPIOMTRACETYPE_X86, cbAccess, fFlagsRw, fFlagsAp);
        if (!pTp)
            break;
        if (   PhysX86Addr >= pTp->u.X86.PhysX86AddrStart
            && PhysX86Addr <= pTp->u.X86.PhysX86AddrEnd)
            pTp->u.X86.pfnTrace(PhysX86Addr,
                                pRegion ? NULL : NULL, /** @todo Description */
                                pRegion ? PhysX86Addr - pRegion->u.X86.PhysX86AddrStart : 0,
                                cbAccess,
                                pvVal,
                                fFlagsRw | fFlagsAp,
                                pTp->pvUser);

        pTp = pTp->pNext;
    }
}


/**
 * Reads from the given SMN based region.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager instance data.
 * @param   pRegion                 The region to read from.
 * @param   SmnAddr                 Absolute SMN address being read from.
 * @param   cbRead                  How much to read.
 * @param   pvDst                   Where to store the read data.
 */
static void pspEmuIomSmnRegionRead(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pRegion, SMNADDR SmnAddr, size_t cbRead, void *pvDst)
{
    pspEmuIomSmnTpCall(pThis, SmnAddr, pRegion, cbRead, pvDst, PSPEMU_IOM_TRACE_F_READ, PSPEMU_IOM_TRACE_F_BEFORE);
    if (pRegion)
    {
        if (pRegion->u.Smn.pfnRead)
            pRegion->u.Smn.pfnRead(SmnAddr - pRegion->u.Smn.SmnAddrStart, cbRead, pvDst, pRegion->pvUser);
        else
            memset(pvDst, 0, cbRead);
    }
    else if (pThis->pfnSmnUnassignedRead)
        pThis->pfnSmnUnassignedRead(SmnAddr, cbRead, pvDst, pThis->pvUserSmnUnassigned);
    else
        memset(pvDst, 0, cbRead);

    pspEmuIomTraceRegionRead(pThis, pRegion, PSPTRACEEVTORIGIN_SMN, SmnAddr, pvDst, cbRead);
    pspEmuIomSmnTpCall(pThis, SmnAddr, pRegion, cbRead, pvDst, PSPEMU_IOM_TRACE_F_READ, PSPEMU_IOM_TRACE_F_AFTER);
}


/**
 * Writes to the given SMN based region.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager instance data.
 * @param   pRegion                 The region to read from.
 * @param   SmnAddr                 Absolute SMN address being written to.
 * @param   cbWrite                 How much to write.
 * @param   pvSrc                   The data to write.
 */
static void pspEmuIomSmnRegionWrite(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pRegion, SMNADDR SmnAddr, size_t cbWrite, const void *pvSrc)
{
    pspEmuIomTraceRegionWrite(pThis, pRegion, PSPTRACEEVTORIGIN_SMN, SmnAddr, pvSrc, cbWrite);
    pspEmuIomSmnTpCall(pThis, SmnAddr, pRegion, cbWrite, pvSrc, PSPEMU_IOM_TRACE_F_WRITE, PSPEMU_IOM_TRACE_F_BEFORE);
    if (pRegion)
    {
        if (pRegion->u.Smn.pfnWrite)
            pRegion->u.Smn.pfnWrite(SmnAddr - pRegion->u.Smn.SmnAddrStart, cbWrite, pvSrc, pRegion->pvUser);
    }
    else if (pThis->pfnSmnUnassignedWrite)
        pThis->pfnSmnUnassignedWrite(SmnAddr, cbWrite, pvSrc, pThis->pvUserSmnUnassigned);

    pspEmuIomSmnTpCall(pThis, SmnAddr, pRegion, cbWrite, pvSrc, PSPEMU_IOM_TRACE_F_WRITE, PSPEMU_IOM_TRACE_F_AFTER);
}


/**
 * Reads from the given MMIO based region.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager instance data.
 * @param   pRegion                 The region to read from.
 * @param   PspAddrMmio             Absolute MMIO address being read from.
 * @param   cbRead                  How much to read.
 * @param   pvDst                   Where to store the read data.
 */
static void pspEmuIomMmioRegionRead(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pRegion, PSPADDR PspAddrMmio, size_t cbRead, void *pvDst)
{
    pspEmuIomMmioTpCall(pThis, PspAddrMmio, pRegion, cbRead, pvDst, PSPEMU_IOM_TRACE_F_READ, PSPEMU_IOM_TRACE_F_BEFORE);
    if (pRegion)
    {
        if (pRegion->u.Mmio.pfnRead)
            pRegion->u.Mmio.pfnRead(PspAddrMmio - pRegion->u.Mmio.PspAddrMmioStart, cbRead, pvDst, pRegion->pvUser);
        else
            memset(pvDst, 0, cbRead);
    }
    else if (pThis->pfnMmioUnassignedRead)
        pThis->pfnMmioUnassignedRead(PspAddrMmio, cbRead, pvDst, pThis->pvUserMmioUnassigned);
    else
        memset(pvDst, 0, cbRead);

    pspEmuIomTraceRegionRead(pThis, pRegion, PSPTRACEEVTORIGIN_MMIO, PspAddrMmio, pvDst, cbRead);
    pspEmuIomMmioTpCall(pThis, PspAddrMmio, pRegion, cbRead, pvDst, PSPEMU_IOM_TRACE_F_READ, PSPEMU_IOM_TRACE_F_AFTER);
}


/**
 * Writes to the given MMIO based region.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager instance data.
 * @param   pRegion                 The region to read from.
 * @param   PspAddrMmio             Absolute MMIO address being written to.
 * @param   cbWrite                 How much to write.
 * @param   pvSrc                   The data to write.
 */
static void pspEmuIomMmioRegionWrite(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pRegion, PSPADDR PspAddrMmio, size_t cbWrite, const void *pvSrc)
{
    pspEmuIomTraceRegionWrite(pThis, pRegion, PSPTRACEEVTORIGIN_MMIO, PspAddrMmio, pvSrc, cbWrite);
    pspEmuIomMmioTpCall(pThis, PspAddrMmio, pRegion, cbWrite, pvSrc, PSPEMU_IOM_TRACE_F_WRITE, PSPEMU_IOM_TRACE_F_BEFORE);
    if (pRegion)
    {
        if (pRegion->u.Mmio.pfnWrite)
            pRegion->u.Mmio.pfnWrite(PspAddrMmio - pRegion->u.Mmio.PspAddrMmioStart, cbWrite, pvSrc, pRegion->pvUser);
    }
    else if (pThis->pfnMmioUnassignedWrite)
        pThis->pfnMmioUnassignedWrite(PspAddrMmio, cbWrite, pvSrc, pThis->pvUserMmioUnassigned);

    pspEmuIomMmioTpCall(pThis, PspAddrMmio, pRegion, cbWrite, pvSrc, PSPEMU_IOM_TRACE_F_WRITE, PSPEMU_IOM_TRACE_F_AFTER);
}


static void pspEmuIomSmnSlotsRead(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    SMNADDR SmnAddr = pspEmuIomGetSmnAddrFromSlotAndOffset(pThis, uPspAddr);
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomSmnFindRegion(pThis, SmnAddr);

    pspEmuIomSmnRegionRead(pThis, pRegion, SmnAddr, cbRead, pvDst);
}


static void pspEmuIomSmnSlotsWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    SMNADDR SmnAddr = pspEmuIomGetSmnAddrFromSlotAndOffset(pThis, uPspAddr);
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomSmnFindRegion(pThis, SmnAddr);

    pspEmuIomSmnRegionWrite(pThis, pRegion, SmnAddr, cbWrite, pvSrc);
}


static void pspEmuIomMmioRead(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uPspAddr += 0x01000000 + 32 * _1M; /* The address contains the offset from the beginning of the registered range */
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomMmioFindRegion(pThis, uPspAddr);

    pspEmuIomMmioRegionRead(pThis, pRegion, uPspAddr, cbRead, pvDst);
}


static void pspEmuIomMmioWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPIOMINT pThis = (PPSPIOMINT)pvUser;

    uPspAddr += 0x01000000 + 32 * _1M; /* The address contains the offset from the beginning of the registered range */
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomMmioFindRegion(pThis, uPspAddr);

    pspEmuIomMmioRegionWrite(pThis, pRegion, uPspAddr, cbWrite, pvSrc);
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


/**
 * Finds an executable memory region within the given range.
 *
 * @returns Pointer to the executable memory region or NULL if none was found.
 * @param   pThis                   The I/O manager.
 * @param   PhysX86Addr             The absolute X86 physical address marking the start of the region.
 * @param   cbX86                   Size of the region.
 */
static PPSPIOMREGIONHANDLEINT pspEmuIomX86MapMemExecFindRegion(PPSPIOMINT pThis, X86PADDR PhysX86Addr, size_t cbX86)
{
    X86PADDR PhysX86AddrEnd = PhysX86Addr + cbX86;
    PPSPIOMREGIONHANDLEINT pCur = pThis->pX86MemExecHead;

    while (pCur)
    {
        X86PADDR PhysX86AddrEndCur = pCur->u.X86.PhysX86AddrStart + pCur->u.X86.cbX86;
        if (   PhysX86Addr < PhysX86AddrEndCur
            && pCur->u.X86.PhysX86AddrStart < PhysX86AddrEnd)
            return pCur;

        pCur = pCur->u.X86.u.Mem.pExecNext;
    }

    return NULL;
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
        cbFetch = MIN((cbFetch + _1K) & ~(_1K - 1), pX86Region->u.X86.cbX86 - pX86Region->u.X86.u.Mem.cbValid);

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
    PPSPIOMX86MAPCTRLSLOT pX86MapSlot = (PPSPIOMX86MAPCTRLSLOT)pvUser;
    PPSPIOMINT pThis = (PPSPIOMINT)pX86MapSlot->pIoMgr;

    X86PADDR PhysX86Addr = pX86MapSlot->PhysX86Base | uPspAddr;
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomX86MapFindRegion(pThis, PhysX86Addr);
    PSPTRACEEVTORIGIN enmEvtOrigin = PSPTRACEEVTORIGIN_X86;

    pspEmuIomX86TpCall(pThis, PhysX86Addr, pRegion, cbRead, pvDst, PSPEMU_IOM_TRACE_F_READ, PSPEMU_IOM_TRACE_F_BEFORE);
    if (pRegion)
    {
        if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MMIO)
        {
            enmEvtOrigin = PSPTRACEEVTORIGIN_X86_MMIO;

            if (pRegion->u.X86.u.Mmio.pfnRead)
                pRegion->u.X86.u.Mmio.pfnRead(PhysX86Addr - pRegion->u.X86.PhysX86AddrStart, cbRead, pvDst, pRegion->pvUser);
            else
                memset(pvDst, 0, cbRead);
        }
        else if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MEM)
        {
            enmEvtOrigin = PSPTRACEEVTORIGIN_X86_MEM;
            pspEmuIoMgrX86MemReadWorker(pThis, pRegion, PhysX86Addr - pRegion->u.X86.PhysX86AddrStart, pvDst, cbRead);
        }
    }
    else if (pThis->pfnX86UnassignedRead)
        pThis->pfnX86UnassignedRead(PhysX86Addr, cbRead, pvDst, pThis->pvUserX86Unassigned);
    else
        memset(pvDst, 0, cbRead);

    pspEmuIomTraceRegionRead(pThis, pRegion, enmEvtOrigin, PhysX86Addr, pvDst, cbRead);
    pspEmuIomX86TpCall(pThis, PhysX86Addr, pRegion, cbRead, pvDst, PSPEMU_IOM_TRACE_F_READ, PSPEMU_IOM_TRACE_F_AFTER);
}


static void pspEmuIomX86MapWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPIOMX86MAPCTRLSLOT pX86MapSlot = (PPSPIOMX86MAPCTRLSLOT)pvUser;
    PPSPIOMINT pThis = (PPSPIOMINT)pX86MapSlot->pIoMgr;

    X86PADDR PhysX86Addr = pX86MapSlot->PhysX86Base | uPspAddr;
    PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomX86MapFindRegion(pThis, PhysX86Addr);

    PSPTRACEEVTORIGIN enmEvtOrigin = PSPTRACEEVTORIGIN_X86;
    if (pRegion)
    {
        if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MMIO)
            enmEvtOrigin = PSPTRACEEVTORIGIN_X86_MMIO;
        else if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MEM)
            enmEvtOrigin = PSPTRACEEVTORIGIN_X86_MEM;
    }
    pspEmuIomTraceRegionWrite(pThis, pRegion, enmEvtOrigin, PhysX86Addr, pvSrc, cbWrite);

    pspEmuIomX86TpCall(pThis, PhysX86Addr, pRegion, cbWrite, pvSrc, PSPEMU_IOM_TRACE_F_WRITE, PSPEMU_IOM_TRACE_F_BEFORE);
    if (pRegion)
    {
        if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MMIO)
        {
            if (pRegion->u.X86.u.Mmio.pfnWrite)
                pRegion->u.X86.u.Mmio.pfnWrite(PhysX86Addr - pRegion->u.X86.PhysX86AddrStart, cbWrite, pvSrc, pRegion->pvUser);
        }
        else if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MEM)
            pspEmuIoMgrX86MemWriteWorker(pThis, pRegion, PhysX86Addr - pRegion->u.X86.PhysX86AddrStart, pvSrc, cbWrite);
    }
    else if (pThis->pfnX86UnassignedWrite)
        pThis->pfnX86UnassignedWrite(PhysX86Addr, cbWrite, pvSrc, pThis->pvUserX86Unassigned);

    pspEmuIomX86TpCall(pThis, PhysX86Addr, pRegion, cbWrite, pvSrc, PSPEMU_IOM_TRACE_F_WRITE, PSPEMU_IOM_TRACE_F_AFTER);
}


static void pspEmuIomX86MapReadSplit(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PCPSPIOMX86MMIOSPLIT pX86MmioSplit = (PCPSPIOMX86MMIOSPLIT)pvUser;
    PPSPIOMX86MAPCTRLSLOT pX86MapSlot = pX86MmioSplit->pX86MapSlot;

    /* Recalculate the MMIO offset. */
    uPspAddr += pX86MmioSplit->PspAddrMmioStart - pX86MapSlot->PspAddrMmioStart;

    /* Do the call to the worker. */
    pspEmuIomX86MapRead(hCore, uPspAddr, cbRead, pvDst, pX86MapSlot);
}


static void pspEmuIomX86MapWriteSplit(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PCPSPIOMX86MMIOSPLIT pX86MmioSplit = (PCPSPIOMX86MMIOSPLIT)pvUser;
    PPSPIOMX86MAPCTRLSLOT pX86MapSlot = pX86MmioSplit->pX86MapSlot;

    /* Recalculate the MMIO offset. */
    uPspAddr += pX86MmioSplit->PspAddrMmioStart - pX86MapSlot->PspAddrMmioStart;

    /* Do the call to the worker. */
    pspEmuIomX86MapWrite(hCore, uPspAddr, cbWrite, pvSrc, pX86MapSlot);
}


/**
 * Unmaps any directly mapped x86 memory regions.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager instance.
 * @param   pX86MapSlot             The x86 mapping slot being restored.
 */
static void pspEmuIoMgrX86MapExecMemoryRegionsUnmap(PPSPIOMINT pThis, PPSPIOMX86MAPCTRLSLOT pX86MapSlot)
{
    if (pX86MapSlot->pX86MemExec)
    {
        int rc = PSPEmuCoreMemRegionRemove(pThis->hPspCore, pX86MapSlot->PspAddrMemExecStart, pX86MapSlot->cbMemExec);
        /** @todo Assert rc */

        /* Deregister the possibly split MMIO region. */
        if (pX86MapSlot->aSplitMmio[0].cbMmio)
            rc = PSPEmuCoreMmioDeregister(pThis->hPspCore, pX86MapSlot->aSplitMmio[0].PspAddrMmioStart,
                                          pX86MapSlot->aSplitMmio[0].cbMmio);
        if (pX86MapSlot->aSplitMmio[1].cbMmio)
            rc = PSPEmuCoreMmioDeregister(pThis->hPspCore, pX86MapSlot->aSplitMmio[1].PspAddrMmioStart,
                                          pX86MapSlot->aSplitMmio[1].cbMmio);

        /* Restore the old MMIO region. */
        rc = PSPEmuCoreMmioRegister(pThis->hPspCore, pX86MapSlot->PspAddrMmioStart, pX86MapSlot->cbMmio,
                                    pspEmuIomX86MapRead, pspEmuIomX86MapWrite,
                                    pX86MapSlot);
        /** @todo Assert rc */

        /* Clear important members. */
        pX86MapSlot->pX86MemExec                    = NULL;
        pX86MapSlot->PspAddrMemExecStart            = 0;
        pX86MapSlot->cbMemExec                      = 0;
        pX86MapSlot->aSplitMmio[0].pX86MapSlot      = NULL;
        pX86MapSlot->aSplitMmio[0].cbMmio           = 0;
        pX86MapSlot->aSplitMmio[0].PspAddrMmioStart = 0;
        pX86MapSlot->aSplitMmio[1].pX86MapSlot      = NULL;
        pX86MapSlot->aSplitMmio[1].cbMmio           = 0;
        pX86MapSlot->aSplitMmio[1].PspAddrMmioStart = 0;
    }
}


/**
 * Maps any directly mapped x86 memory regions.
 *
 * @returns nothing.
 * @param   pThis                   The I/O manager instance.
 * @param   pX86MapSlot             The x86 mapping slot being changed.
 */
static void pspEmuIoMgrX86MapExecMemoryRegionsMapMaybe(PPSPIOMINT pThis, PPSPIOMX86MAPCTRLSLOT pX86MapSlot)
{
    /* Check whether the mapping covers an exectuable memory region, otherwise we can skip the shenanigans... */
    PPSPIOMREGIONHANDLEINT pX86MemExec = pspEmuIomX86MapMemExecFindRegion(pThis, pX86MapSlot->PhysX86Base, pX86MapSlot->cbMmio);
    if (pX86MemExec)
    {
        /* Oh boy, here it goes... */

        /* Ensure that the whole memory region is valid. */
        int rc = pspEmuIoMgrX86MemEnsureMapping(pX86MemExec, 0, pX86MemExec->u.X86.cbX86);
        if (!rc)
        {
            /* Unmap the default handler for this region first. */
            rc = PSPEmuCoreMmioDeregister(pThis->hPspCore, pX86MapSlot->PspAddrMmioStart, pX86MapSlot->cbMmio);
            /** @todo Assert */

            /* Check whether we have to insert a split MMIO handler before the memory region. */
            X86PADDR offMemExec = pX86MemExec->u.X86.PhysX86AddrStart - pX86MapSlot->PhysX86Base;
            size_t cbMemExec = pX86MemExec->u.X86.cbX86; /** @todo Handle cut off regions don't fitting into the complete slot. */

            if (offMemExec)
            {
                rc = PSPEmuCoreMmioRegister(pThis->hPspCore, pX86MapSlot->PspAddrMmioStart, offMemExec,
                                            pspEmuIomX86MapReadSplit, pspEmuIomX86MapWriteSplit,
                                            &pX86MapSlot->aSplitMmio[0]);
                /** @todo Assert */

                pX86MapSlot->aSplitMmio[0].pX86MapSlot      = pX86MapSlot;
                pX86MapSlot->aSplitMmio[0].cbMmio           = offMemExec;
                pX86MapSlot->aSplitMmio[0].PspAddrMmioStart = pX86MapSlot->PspAddrMmioStart;
            }

            /* Now insert the executable memory region. */
            rc = PSPEmuCoreMemRegionAdd(pThis->hPspCore, pX86MapSlot->PspAddrMmioStart + offMemExec, cbMemExec,
                                        PSPEMU_CORE_MEM_REGION_PROT_F_EXEC | PSPEMU_CORE_MEM_REGION_PROT_F_READ | PSPEMU_CORE_MEM_REGION_PROT_F_WRITE,
                                        pX86MemExec->u.X86.u.Mem.pvMapping);
            /** @todo Assert */

            /* Insert split MMIO region coming after the executable memory region. */
            if (offMemExec + cbMemExec < pX86MapSlot->cbMmio)
            {
                PSPADDR PspAddrMmioAfter = pX86MapSlot->PspAddrMmioStart + offMemExec + cbMemExec;
                size_t cbMmioAfter = pX86MapSlot->cbMmio - (PspAddrMmioAfter - pX86MapSlot->PspAddrMmioStart);

                rc = PSPEmuCoreMmioRegister(pThis->hPspCore, PspAddrMmioAfter, cbMmioAfter,
                                            pspEmuIomX86MapReadSplit, pspEmuIomX86MapWriteSplit,
                                            &pX86MapSlot->aSplitMmio[1]);
                /** @todo Assert */

                pX86MapSlot->aSplitMmio[1].pX86MapSlot      = pX86MapSlot;
                pX86MapSlot->aSplitMmio[1].cbMmio           = cbMmioAfter;
                pX86MapSlot->aSplitMmio[1].PspAddrMmioStart = PspAddrMmioAfter;
            }

            pX86MapSlot->pX86MemExec                    = pX86MemExec;
            pX86MapSlot->PspAddrMemExecStart            = pX86MapSlot->PspAddrMmioStart + offMemExec;
            pX86MapSlot->cbMemExec                      = cbMemExec;
        }
        /** @todo else add fatal trace event. */
    }
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
                uint32_t u32RegX86BaseAddrNew = *(uint32_t *)pvVal;

                if (u32RegX86BaseAddrNew != pX86Slot->u32RegX86BaseAddr)
                {
                    /* Restore the original mapping in case there is an executable memory region mapped right now. */
                    pspEmuIoMgrX86MapExecMemoryRegionsUnmap(pThis, pX86Slot);

                    pX86Slot->u32RegX86BaseAddr = u32RegX86BaseAddrNew;
                    pX86Slot->PhysX86Base = (X86PADDR)(pX86Slot->u32RegX86BaseAddr & 0x3f) << 26 | ((X86PADDR)(pX86Slot->u32RegX86BaseAddr >> 6)) << 32;

                    /*
                     * In case of executable memory regions in the covered range we have to re-arrange the mapping and
                     * map the executable memory directly.
                     */
                    pspEmuIoMgrX86MapExecMemoryRegionsMapMaybe(pThis, pX86Slot);
                }
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


/**
 * Creates and links a new trace point with the given config.
 *
 * @returns Status code.
 * @param   pThis                   I/O manager instance.
 * @param   enmType                 The trace point type.
 * @param   cbAccess                Access width.
 * @param   fFlags                  Flags controlling the trace point behavior.
 * @param   pvUser                  Opaque user data to pass to the handler.
 * @param   ppTp                    Where to store the pointer to the created trace point on success.
 */
static int pspEmuIomTpCreate(PPSPIOMINT pThis, PSPIOMTRACETYPE enmType, size_t cbAccess, uint32_t fFlags,
                             void *pvUser, PPSPIOMTPINT *ppTp)
{
    if (cbAccess != 0 && cbAccess != 1 && cbAccess != 2 && cbAccess != 4)
        return -1;
    if (fFlags & ~PSPEMU_IOM_TRACE_F_VALID_MASK)
        return -1;
    if (!(fFlags & (PSPEMU_IOM_TRACE_F_READ | PSPEMU_IOM_TRACE_F_WRITE)))
        return -1;
    if (!(fFlags & (PSPEMU_IOM_TRACE_F_BEFORE | PSPEMU_IOM_TRACE_F_AFTER)))
        return -1;

    int rc = 0;
    PPSPIOMTPINT pTp = (PPSPIOMTPINT)calloc(1, sizeof(*pTp));
    if (pTp)
    {
        pTp->pIoMgr   = pThis;
        pTp->cbAccess = cbAccess;
        pTp->fFlags   = fFlags;
        pTp->pvUser   = pvUser;
        pTp->enmType  = enmType;
        pTp->pNext = pThis->pTpHead;
        pThis->pTpHead = pTp;
        *ppTp = pTp;
    }
    else
        rc = -1;

    return rc;
}


static int pspEmuIomMmioRegionRegister(PPSPIOMINT pThis, PSPADDR PspAddrMmioStart, size_t cbMmio,
                                       PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, void *pvUser,
                                       const char *pszDesc, PPSPIOMREGIONHANDLEINT *ppMmio)
{
    int rc = 0;
    PPSPIOMREGIONHANDLEINT pRegion = (PPSPIOMREGIONHANDLEINT)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->pIoMgr                  = pThis;
        pRegion->enmType                 = PSPIOMREGIONTYPE_PSP_MMIO;
        pRegion->pvUser                  = pvUser;
        pRegion->pszDesc                 = pszDesc;
        pRegion->u.Mmio.PspAddrMmioStart = PspAddrMmioStart;
        pRegion->u.Mmio.cbMmio           = cbMmio;
        pRegion->u.Mmio.pfnRead          = pfnRead;
        pRegion->u.Mmio.pfnWrite         = pfnWrite;

        if (pfnRead)
            pRegion->fFlags |= PSP_IOM_REGION_F_READ;
        if (pfnWrite)
            pRegion->fFlags |= PSP_IOM_REGION_F_WRITE;

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


/**
 * Inserts the given X86 memory region with exec permissions into the list of executable memory regions.
 *
 * @returns Status code.
 * @param   pThis                   The I/O manager.
 * @param   pRegion                 The X86 region to insert.
 */
static void pspEmuIomX86MemExecInsert(PPSPIOMINT pThis, PPSPIOMREGIONHANDLEINT pRegion)
{
    X86PADDR PhysX86AddrStart = pRegion->u.X86.PhysX86AddrStart;
    size_t cbX86 = pRegion->u.X86.cbX86;
    int rc = 0;

    PPSPIOMREGIONHANDLEINT pPrev = NULL;
    PPSPIOMREGIONHANDLEINT pCur = pThis->pX86MemExecHead;

    /* Search where to insert the new device, sorted by starting X86 address. */
    while (pCur)
    {
        if (pCur->u.X86.PhysX86AddrStart > PhysX86AddrStart)
            break;
        pPrev = pCur;
        pCur = pCur->u.X86.u.Mem.pExecNext;
    }

    /* No sanity checks needed here as it was already done in the general X86 region list insertion step. */
    pRegion->u.X86.u.Mem.pExecNext = pCur;
    if (pPrev)
        pPrev->u.X86.u.Mem.pExecNext = pRegion;
    else
        pThis->pX86MemExecHead = pRegion;
}


/**
 * Frees the given region list.
 *
 * @returns nothing.
 * @param   pHead                   Head of the region list to destroy.
 */
static void pspEmuIoMgrDestroyRegionList(PPSPIOMREGIONHANDLEINT pHead)
{
    while (pHead)
    {
        PPSPIOMREGIONHANDLEINT pFree = pHead;
        pHead = pHead->pNext;
        free(pFree);
    }
}


/**
 * Checks whether the given PSP address is inside the SMN region and returns the proper region handle
 * if asked for and the absolute SMN address being accessed.
 *
 * @returns Flag whether the given addres belongs to an SMN region.
 * @param   pThis                   The I/O manager instance.
 * @param   PspAddr                 The PSP address to check.
 * @param   ppRegion                Where to store the pointer to the region, optional.
 * @param   pSmnAddr                Where to store the SMN address on success.
 */
static bool pspEmuIoMgrAddrIsSmn(PPSPIOMINT pThis, PSPADDR PspAddr, PPSPIOMREGIONHANDLEINT *ppRegion,
                                 SMNADDR *pSmnAddr)
{
    if (PspAddr >= 0x01000000 && PspAddr < 0x01000000 + 32 * _1M)
    {
        /* SMN device region. */
        if (ppRegion)
        {
            PspAddr -= 0x01000000;

            SMNADDR SmnAddr = pspEmuIomGetSmnAddrFromSlotAndOffset(pThis, PspAddr);
            PPSPIOMREGIONHANDLEINT pRegion = pspEmuIomSmnFindRegion(pThis, SmnAddr);
            *ppRegion = pRegion;
            *pSmnAddr = SmnAddr;
        }
        return true;
    }

    return false;
}


/**
 * Checks whether the given PSP address is inside the MMIO region and returns the proper region handle
 * if asked for.
 *
 * @returns Flag whether the given addres belongs to an MMIO region.
 * @param   pThis                   The I/O manager instance.
 * @param   PspAddr                 The PSP address to check.
 * @param   ppRegion                Where to store the pointer to the region, optional.
 */
static bool pspEmuIoMgrAddrIsMmio(PPSPIOMINT pThis, PSPADDR PspAddr, PPSPIOMREGIONHANDLEINT *ppRegion)
{
    if (PspAddr >= 0x03000000 && PspAddr < 0x04000000)
    {
        /* Standard MMIO region. */
        if (ppRegion)
            *ppRegion = pspEmuIomMmioFindRegion(pThis, PspAddr);
        return true;
    }

    return false;
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
        pThis->pX86MemExecHead        = NULL;
        pThis->PspAddrMmioLowest      = 0xffffffff;
        pThis->PspAddrMmioHighest     = 0x00000000;
        pThis->SmnAddrLowest          = 0xffffffff;
        pThis->SmnAddrHighest         = 0x00000000;
        pThis->PhysX86AddrLowest      = 0xffffffffffffffff;
        pThis->PhysX86AddrHighest     = 0x0000000000000000;
        pThis->hPspCore               = hPspCore;
        pThis->pMmioRegionSmnCtrl     = NULL;
        pThis->pfnMmioUnassignedRead  = NULL;
        pThis->pfnMmioUnassignedWrite = NULL;
        pThis->pvUserMmioUnassigned   = NULL;
        pThis->pfnSmnUnassignedRead   = NULL;
        pThis->pfnSmnUnassignedWrite  = NULL;
        pThis->pvUserSmnUnassigned    = NULL;
        pThis->pfnX86UnassignedRead   = NULL;
        pThis->pfnX86UnassignedWrite  = NULL;
        pThis->pvUserX86Unassigned    = NULL;
        pThis->pTpHead                = NULL;
        pThis->fLogAllAccesses        = false;

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
                /* Initialize the x86 memory mapping slots. */
                for (uint32_t i = 0; i < ELEMENTS(pThis->aX86MapCtrlSlots) && !rc; i++)
                {
                    PPSPIOMX86MAPCTRLSLOT pX86MapSlot = &pThis->aX86MapCtrlSlots[i];

                    pX86MapSlot->pIoMgr            = pThis;
                    pX86MapSlot->PspAddrMmioStart  = 0x04000000 + i * 64 * _1M;
                    pX86MapSlot->cbMmio            = 64 * _1M;
                    pX86MapSlot->PhysX86Base       = 0;
                    pX86MapSlot->pX86MemExec       = NULL;
                    pX86MapSlot->u32RegX86BaseAddr = 0;
                    pX86MapSlot->u32RegUnk1        = 0;
                    pX86MapSlot->u32RegUnk2        = 0;
                    pX86MapSlot->u32RegUnk3        = 0;
                    pX86MapSlot->u32RegUnk4        = 0;
                    pX86MapSlot->u32RegUnk5        = 0;

                    /* Register the region where the X86 memory mappings appear in. */
                    rc = PSPEmuCoreMmioRegister(hPspCore, pX86MapSlot->PspAddrMmioStart, pX86MapSlot->cbMmio,
                                                pspEmuIomX86MapRead, pspEmuIomX86MapWrite,
                                                pX86MapSlot);
                }

                if (!rc)
                {
                    /* Register our SMN mapping control registers into the MMIO region. */
                    rc = pspEmuIomMmioRegionRegister(pThis, 0x03220000, 16 * sizeof(uint32_t),
                                                     pspEmuIoMgrMmioSmnCtrlRead, pspEmuIoMgrMmioSmnCtrlWrite,
                                                     pThis, "SMN mapping control",
                                                     &pThis->pMmioRegionSmnCtrl);
                    if (!rc)
                    {
                        /* Register our X86 mapping control registers into the MMIO region. */
                        rc = pspEmuIomMmioRegionRegister(pThis, 0x03230000, 15 * 4 * sizeof(uint32_t),
                                                         pspEmuIoMgrX86MapCtrlRead, pspEmuIoMgrX86MapCtrlWrite,
                                                         pThis, "x86 mapping control 1",
                                                         &pThis->pMmioRegionX86MapCtrl);
                        if (!rc)
                            rc = pspEmuIomMmioRegionRegister(pThis, 0x032303e0, 15 * sizeof(uint32_t),
                                                             pspEmuIoMgrX86MapCtrl2Read, pspEmuIoMgrX86MapCtrl2Write,
                                                             pThis, "x86 mapping control 2",
                                                             &pThis->pMmioRegionX86MapCtrl2);
                        if (!rc)
                            rc = pspEmuIomMmioRegionRegister(pThis, 0x032304d8, 15 * sizeof(uint32_t),
                                                             pspEmuIoMgrX86MapCtrl3Read, pspEmuIoMgrX86MapCtrl3Write,
                                                             pThis, "x86 mapping control 3",
                                                             &pThis->pMmioRegionX86MapCtrl3);
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

                    /* Unregister everything, don't care about errors. */
                    for (uint32_t i = 0; i < ELEMENTS(pThis->aX86MapCtrlSlots); i++)
                    {
                        PPSPIOMX86MAPCTRLSLOT pX86MapSlot = &pThis->aX86MapCtrlSlots[i];

                        PSPEmuCoreMmioDeregister(pThis->hPspCore, pX86MapSlot->PspAddrMmioStart, pX86MapSlot->cbMmio);
                    }
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

    /* Free all trace points first. */
    PPSPIOMTPINT pCur = pThis->pTpHead;
    while (pCur)
    {
        PPSPIOMTPINT pFree = pCur;
        pCur = pCur->pNext;
        free(pFree);
    }

    pspEmuIoMgrDestroyRegionList(pThis->pMmioHead);
    pspEmuIoMgrDestroyRegionList(pThis->pSmnHead);
    pspEmuIoMgrDestroyRegionList(pThis->pX86Head);
    /* pX86MemExecHead is already part of pX86Head, so freed already. */

    int rc = PSPEmuCoreMmioDeregister(pThis->hPspCore, 0x01000000, 0x01000000 + 32 * _1M);
    if (!rc)
        rc = PSPEmuCoreMmioDeregister(pThis->hPspCore, 0x01000000 + 32 * _1M, 0x44000000);
    /** @todo Free devices. */
    free(pThis);
    return rc;
}


int PSPEmuIoMgrTraceAllAccessesSet(PSPIOM hIoMgr, bool fEnable)
{
    PPSPIOMINT pThis = hIoMgr;

    pThis->fLogAllAccesses = fEnable;
    return 0;
}


int PSPEmuIoMgrMmioUnassignedSet(PSPIOM hIoMgr, PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, void *pvUser)
{
    PPSPIOMINT pThis = hIoMgr;

    /* Allow only one registration currently. */
    if (pThis->pfnMmioUnassignedRead || pThis->pfnMmioUnassignedWrite)
        return -1;

    pThis->pfnMmioUnassignedRead  = pfnRead;
    pThis->pfnMmioUnassignedWrite = pfnWrite;
    pThis->pvUserMmioUnassigned   = pvUser;
    return 0;
}


int PSPEmuIoMgrSmnUnassignedSet(PSPIOM hIoMgr, PFNPSPIOMSMNREAD pfnRead, PFNPSPIOMSMNWRITE pfnWrite, void *pvUser)
{
    PPSPIOMINT pThis = hIoMgr;

    /* Allow only one registration currently. */
    if (pThis->pfnSmnUnassignedRead || pThis->pfnSmnUnassignedWrite)
        return -1;

    pThis->pfnSmnUnassignedRead  = pfnRead;
    pThis->pfnSmnUnassignedWrite = pfnWrite;
    pThis->pvUserSmnUnassigned   = pvUser;
    return 0;
}


int PSPEmuIoMgrX86UnassignedSet(PSPIOM hIoMgr, PFNPSPIOMX86MMIOREAD pfnRead, PFNPSPIOMX86MMIOWRITE pfnWrite, void *pvUser)
{
    PPSPIOMINT pThis = hIoMgr;

    /* Allow only one registration currently. */
    if (pThis->pfnX86UnassignedRead || pThis->pfnX86UnassignedWrite)
        return -1;

    pThis->pfnX86UnassignedRead  = pfnRead;
    pThis->pfnX86UnassignedWrite = pfnWrite;
    pThis->pvUserX86Unassigned   = pvUser;
    return 0;
}


int PSPEmuIoMgrMmioRegister(PSPIOM hIoMgr, PSPADDR PspAddrMmioStart, size_t cbMmio,
                            PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, void *pvUser,
                            const char *pszDesc, PPSPIOMREGIONHANDLE phMmio)
{
    PPSPIOMINT pThis = hIoMgr;

    return pspEmuIomMmioRegionRegister(pThis, PspAddrMmioStart, cbMmio,
                                       pfnRead, pfnWrite, pvUser, pszDesc, phMmio);
}


int PSPEmuIoMgrMmioTraceRegister(PSPIOM hIoMgr, PSPADDR PspAddrMmioStart, PSPADDR PspAddrMmioEnd,
                                 size_t cbAccess, uint32_t fFlags, PFNPSPIOMMMIOTRACE pfnTrace, void *pvUser,
                                 PPSPIOMTP phIoTp)
{
    PPSPIOMINT pThis = hIoMgr;

    if (!pfnTrace)
        return -1;

    PPSPIOMTPINT pTp = NULL;
    int rc = pspEmuIomTpCreate(pThis, PSPIOMTRACETYPE_MMIO, cbAccess, fFlags, pvUser, &pTp);
    if (!rc)
    {
        pTp->u.Mmio.PspAddrMmioStart = PspAddrMmioStart;
        pTp->u.Mmio.PspAddrMmioEnd   = PspAddrMmioEnd;
        pTp->u.Mmio.pfnTrace         = pfnTrace;
        *phIoTp = pTp;
    }

    return rc;
}


int PSPEmuIoMgrSmnRegister(PSPIOM hIoMgr, SMNADDR SmnAddrStart, size_t cbSmn,
                           PFNPSPIOMSMNREAD pfnRead, PFNPSPIOMSMNWRITE pfnWrite, void *pvUser,
                           const char *pszDesc, PPSPIOMREGIONHANDLE phSmn)
{
    int rc = 0;
    PPSPIOMINT pThis = hIoMgr;
    PPSPIOMREGIONHANDLEINT pRegion = (PPSPIOMREGIONHANDLEINT)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->pIoMgr             = pThis;
        pRegion->enmType            = PSPIOMREGIONTYPE_SMN;
        pRegion->pvUser             = pvUser;
        pRegion->pszDesc            = pszDesc;
        pRegion->u.Smn.SmnAddrStart = SmnAddrStart;
        pRegion->u.Smn.cbSmn        = cbSmn;
        pRegion->u.Smn.pfnRead      = pfnRead;
        pRegion->u.Smn.pfnWrite     = pfnWrite;

        if (pfnRead)
            pRegion->fFlags |= PSP_IOM_REGION_F_READ;
        if (pfnWrite)
            pRegion->fFlags |= PSP_IOM_REGION_F_WRITE;

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


int PSPEmuIoMgrSmnTraceRegister(PSPIOM hIoMgr, SMNADDR SmnAddrStart, SMNADDR SmnAddrEnd,
                                size_t cbAccess, uint32_t fFlags, PFNPSPIOMSMNTRACE pfnTrace, void *pvUser,
                                PPSPIOMTP phIoTp)
{
    PPSPIOMINT pThis = hIoMgr;

    if (!pfnTrace)
        return -1;

    PPSPIOMTPINT pTp = NULL;
    int rc = pspEmuIomTpCreate(pThis, PSPIOMTRACETYPE_SMN, cbAccess, fFlags, pvUser, &pTp);
    if (!rc)
    {
        pTp->u.Smn.SmnAddrStart = SmnAddrStart;
        pTp->u.Smn.SmnAddrEnd   = SmnAddrEnd;
        pTp->u.Smn.pfnTrace     = pfnTrace;
        *phIoTp = pTp;
    }

    return rc;
}


int PSPEmuIoMgrX86MmioRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrMmioStart, size_t cbX86Mmio,
                               PFNPSPIOMX86MMIOREAD pfnRead, PFNPSPIOMX86MMIOWRITE pfnWrite, void *pvUser,
                               const char *pszDesc, PPSPIOMREGIONHANDLE phX86Mmio)
{
    int rc = 0;
    PPSPIOMINT pThis = hIoMgr;
    PPSPIOMREGIONHANDLEINT pRegion = (PPSPIOMREGIONHANDLEINT)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->pIoMgr                 = pThis;
        pRegion->enmType                = PSPIOMREGIONTYPE_X86_MMIO;
        pRegion->pvUser                 = pvUser;
        pRegion->pszDesc                = pszDesc;
        pRegion->u.X86.PhysX86AddrStart = PhysX86AddrMmioStart;
        pRegion->u.X86.cbX86            = cbX86Mmio;
        pRegion->u.X86.u.Mmio.pfnRead   = pfnRead;
        pRegion->u.X86.u.Mmio.pfnWrite  = pfnWrite;

        if (pfnRead)
            pRegion->fFlags |= PSP_IOM_REGION_F_READ;
        if (pfnWrite)
            pRegion->fFlags |= PSP_IOM_REGION_F_WRITE;

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
                              bool fCanExec, PFNPSPIOMX86MEMFETCH pfnFetch, void *pvUser,
                              const char *pszDesc, PPSPIOMREGIONHANDLE phX86Mem)
{
    int rc = 0;
    PPSPIOMINT pThis = hIoMgr;
    PPSPIOMREGIONHANDLEINT pRegion = (PPSPIOMREGIONHANDLEINT)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->pIoMgr                 = pThis;
        pRegion->enmType                = PSPIOMREGIONTYPE_X86_MEM;
        pRegion->pvUser                 = pvUser;
        pRegion->pszDesc                = pszDesc;
        pRegion->fFlags                 = PSP_IOM_REGION_F_READ | PSP_IOM_REGION_F_WRITE;
        pRegion->u.X86.PhysX86AddrStart = PhysX86AddrMemStart;
        pRegion->u.X86.cbX86            = cbX86Mem;
        pRegion->u.X86.u.Mem.pExecNext  = NULL;
        pRegion->u.X86.u.Mem.pfnFetch   = pfnFetch;
        pRegion->u.X86.u.Mem.pvMapping  = NULL;
        pRegion->u.X86.u.Mem.cbAlloc    = 0;
        pRegion->u.X86.u.Mem.cbValid    = 0;
        pRegion->u.X86.u.Mem.cbWritten  = 0;
        pRegion->u.X86.u.Mem.fCanExec   = fCanExec;

        rc = pspEmuIomX86RegionInsert(pThis, pRegion);
        if (!rc)
        {
            if (fCanExec)
                pspEmuIomX86MemExecInsert(pThis, pRegion);
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


int PSPEmuIoMgrX86TraceRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrStart, X86PADDR PhysX86AddrEnd,
                                size_t cbAccess, uint32_t fFlags, PFNPSPIOMX86TRACE pfnTrace, void *pvUser,
                                PPSPIOMTP phIoTp)
{
    PPSPIOMINT pThis = hIoMgr;

    if (!pfnTrace)
        return -1;

    PPSPIOMTPINT pTp = NULL;
    int rc = pspEmuIomTpCreate(pThis, PSPIOMTRACETYPE_X86, cbAccess, fFlags, pvUser, &pTp);
    if (!rc)
    {
        pTp->u.X86.PhysX86AddrStart = PhysX86AddrStart;
        pTp->u.X86.PhysX86AddrEnd   = PhysX86AddrEnd;
        pTp->u.X86.pfnTrace         = pfnTrace;
        *phIoTp = pTp;
    }

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
        if (pRegion->enmType == PSPIOMREGIONTYPE_X86_MEM)
        {
            if (pRegion->u.X86.u.Mem.pvMapping)
                free(pRegion->u.X86.u.Mem.pvMapping);

            /* Remove from executable list if required. */
            if (pRegion->u.X86.u.Mem.fCanExec)
            {
                pPrev = NULL;
                pCur = pThis->pX86MemExecHead;

                while (   pCur
                       && pCur != pRegion)
                {
                    pPrev = pCur;
                    pCur = pCur->u.X86.u.Mem.pExecNext;
                }

                if (pCur)
                {
                    /* Found */
                    if (pPrev)
                        pPrev->u.X86.u.Mem.pExecNext = pCur->u.X86.u.Mem.pExecNext;
                    else
                        pThis->pX86MemExecHead = pCur->u.X86.u.Mem.pExecNext;
                }
                /** @todo else Assert() as it should never happen. */
            }
        }
        free(pRegion);
    }
    else /* Not found? */
        return -1;

    return 0;
}


int PSPEmuIoMgrTpDeregister(PSPIOMTP hIoTp)
{
    PPSPIOMTPINT pTp = hIoTp;
    PPSPIOMINT pThis = pTp->pIoMgr;

    /* Search for the trace point in the list and unlink it. */
    PPSPIOMTPINT pPrev = NULL;
    PPSPIOMTPINT pCur = pThis->pTpHead;

    while (   pCur
           && pCur != pTp)
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
            pThis->pTpHead = pCur->pNext;

        free(pTp);
    }
    else /* Not found? */
        return -1;

    return 0;
}


int PSPEmuIoMgrPspAddrRead(PSPIOM hIoMgr, PSPADDR PspAddr, void *pvDst, size_t cbRead)
{
    PPSPIOMINT pThis = hIoMgr;

    PPSPIOMREGIONHANDLEINT pRegion;
    SMNADDR SmnAddr;
    if (pspEmuIoMgrAddrIsMmio(pThis, PspAddr, &pRegion))
    {
        pspEmuIomMmioRegionRead(pThis, pRegion, PspAddr, cbRead, pvDst);
        return 0;
    }
    else if (pspEmuIoMgrAddrIsSmn(pThis, PspAddr, &pRegion, &SmnAddr))
    {
        pspEmuIomSmnRegionRead(pThis, pRegion, SmnAddr, cbRead, pvDst);
        return 0;
    }
    /** @todo x86 */

    return PSPEmuCoreMemRead(pThis->hPspCore, PspAddr, pvDst, cbRead);
}


int PSPEmuIoMgrPspAddrWrite(PSPIOM hIoMgr, PSPADDR PspAddr, const void *pvSrc, size_t cbWrite)
{
    PPSPIOMINT pThis = hIoMgr;

    PPSPIOMREGIONHANDLEINT pRegion;
    SMNADDR SmnAddr;
    if (pspEmuIoMgrAddrIsMmio(pThis, PspAddr, &pRegion))
    {
        pspEmuIomMmioRegionWrite(pThis, pRegion, PspAddr, cbWrite, pvSrc);
        return 0;
    }
    else if (pspEmuIoMgrAddrIsSmn(pThis, PspAddr, &pRegion, &SmnAddr))
    {
        pspEmuIomSmnRegionWrite(pThis, pRegion, SmnAddr, cbWrite, pvSrc);
        return 0;
    }
    /** @todo x86 */

    return PSPEmuCoreMemWrite(pThis->hPspCore, PspAddr, pvSrc, cbWrite);
}

