/** @file
 * PSP Emulator - API for the emulated supervisor part (SVC)
 */

/*
 * Copyright (C) 2019-2020 Alexander Eichner <alexander.eichner@campus.tu-berlin.de>
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

#include <stdio.h>
#include <stdlib.h>

#include <common/types.h>
#include <common/cdefs.h>

#include <psp-fw/svc_id.h>
#include <psp-fw/err.h>
#include <sev/sev.h>

#include <psp-svc.h>
#include <psp-core.h>
#include <psp-trace.h>
#include <libpspproxy.h>

/** Pointer to the emulated supervisor firmware state. */
typedef struct PSPSVCINT *PPSPSVCINT;

/**
 * x86 memory mapping slot.
 */
typedef struct PSPSVCX86MAPPING
{
    /** The base X86 address being mapped (aligned to a 64MB boundary). */
    X86PADDR                PhysX86AddrBase;
    /** The base PSP address returned from the proxied PSP (used for syncing the mappings). */
    PSPADDR                 PspAddrProxyBase;
    /** The memory type being used. */
    uint32_t                uMemType;
    /** Reference counter for this mapping, the mapping gets cleaned up if it reaches 0. */
    uint32_t                cRefs;
    /** The region handle associated with the active mapping. */
    PSPIOMREGIONHANDLE      hIoMgrRegion;
    /** Size of the mapping in bytes. */
    size_t                  cbMapping;
    /** Reference to the internal SVC state (used in the fetch callback). */
    PPSPSVCINT              pThis;
} PSPSVCX86MAPPING;
/** Pointer to an x86 memory mapping slot. */
typedef PSPSVCX86MAPPING *PPSPSVCX86MAPPING;
/** Pointer to a const x86 memory mapping slot. */
typedef const PSPSVCX86MAPPING *PCPSPSVCX86MAPPING;


/**
 * Emulated supervisor firmware state.
 */
typedef struct PSPSVCINT
{
    /** Pointer to the PSP emulation core. */
    PSPCORE                 hPspCore;
    /** The I/O manager handle to manage x86 memory mappings. */
    PSPIOM                  hIoMgr;
    /** The PSP proxy to forward requests to. */
    PSPPROXYCTX             hProxyCtx;
    /** Size of the state region. */
    uint32_t                cbStateRegion;
    /** x86 memory mapping slots. */
    PSPSVCX86MAPPING        aX86MapSlots[15];
} PSPSVCINT;

static bool pspEmuSvcTrace(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);


static bool pspEmuSvcAppExit(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcAppInit(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcSmnMapEx(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcSmnMap(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcSmnUnmap(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcDbgLog(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcX86MemMap(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcX86MemUnmap(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcX86CopyToPsp(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcX86CopyFromPsp(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcX86MemMapEx(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcSmuMsg(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvc0x32Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvc0x33Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvc0x35Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvc0x36Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvc0x38Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcRng(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcQuerySaveStateRegion(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvc0x41Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvc0x42Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcQuerySmmRegion(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);


#define PSPEMU_CORE_SVC_INIT_NULL                   { NULL, NULL, 0 }
#define PSPEMU_CORE_SVC_INIT_DEF(a_Name, a_Handler) { a_Name, a_Handler, PSPEMU_CORE_SVC_F_BEFORE }

/**
 * The SVC descriptors table.
 */
static PSPCORESVCDESC g_aSvcDescs[] =
{
    PSPEMU_CORE_SVC_INIT_DEF("SvcAppExit", pspEmuSvcAppExit),                                               /**< 0x00: Application exit. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcAppInit", pspEmuSvcAppInit),                                               /**< 0x01: Initialize application stack. */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x02: Load entry from flash. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcSmnMapEx", pspEmuSvcSmnMapEx),                                             /**< 0x03: Map SMN address into memory. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcSmnMap",   pspEmuSvcSmnMap),                                               /**< 0x04: Map SMN address into memory, extended version. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcSmnUnmap", pspEmuSvcSmnUnmap),                                             /**< 0x05: Unmap previously mapped SMN address. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcDbgLog",         pspEmuSvcDbgLog),                                         /**< 0x06: Debug log. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcX86MemMap",      pspEmuSvcX86MemMap),                                      /**< 0x07: Map x86 memory address into PSP memory space. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcX86MemUnmap",    pspEmuSvcX86MemUnmap),                                    /**< 0x08: Unmap previously mapped x86 memory address. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcX86CopyToPsp",   pspEmuSvcX86CopyToPsp),                                   /**< 0x09: Copy data from physical x86 memory space to PSP. */
    PSPEMU_CORE_SVC_INIT_DEF("SvcX86CopyFromPsp", pspEmuSvcX86CopyFromPsp),                                 /**< 0x0a: Write status code or data value to physical x86 memory space. */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x0b: Invalidate/Clean memory. */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x0c: Crypto request interfacing with CCP. */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x0d: Unknown. */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x0e: Unknown. */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x0f: Unknown. */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x10: Unknown. */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x11: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x12: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x13: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x14: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x15: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x16: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x17: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x18: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x19: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x1a: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x1b: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x1c: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x1d: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x1e: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x1f: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x20: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x21: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x22: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x23: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x24: */
    PSPEMU_CORE_SVC_INIT_DEF("SvcX86MemMapEx", pspEmuSvcX86MemMapEx),                                       /**< 0x25: Map physical x86 memory into PSP address space */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x26: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x27: */
    PSPEMU_CORE_SVC_INIT_DEF("SvcSmuMsg", pspEmuSvcSmuMsg),                                                 /**< 0x28: Execute request on SMU */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x29: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x2a: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x2b: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x2c: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x2d: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x2e: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x2f: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x30: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x31: */
    PSPEMU_CORE_SVC_INIT_DEF("Svc0x32Unk", pspEmuSvc0x32Unk),                                               /**< 0x32: */
    PSPEMU_CORE_SVC_INIT_DEF("Svc0x33Unk", pspEmuSvc0x33Unk),                                               /**< 0x33: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x34: */
    PSPEMU_CORE_SVC_INIT_DEF("Svc0x35Unk", pspEmuSvc0x35Unk),                                               /**< 0x35: */
    PSPEMU_CORE_SVC_INIT_DEF("Svc0x36Unk", pspEmuSvc0x36Unk),                                               /**< 0x36: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x37: */
    PSPEMU_CORE_SVC_INIT_DEF("Svc0x38Unk", pspEmuSvc0x38Unk),                                               /**< 0x38: */
    PSPEMU_CORE_SVC_INIT_DEF("SvcRng", pspEmuSvcRng),                                                       /**< 0x39: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x3a: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x3b: */
    PSPEMU_CORE_SVC_INIT_DEF("SvcQuerySaveStateRegion", pspEmuSvcQuerySaveStateRegion),                     /**< 0x3c: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x3d: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x3e: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x3f: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x40: */
    PSPEMU_CORE_SVC_INIT_DEF("Svc0x41Unk", pspEmuSvc0x41Unk),                                               /**< 0x41: */
    PSPEMU_CORE_SVC_INIT_DEF("Svc0x42Unk", pspEmuSvc0x42Unk),                                               /**< 0x42: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x43: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x44: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x45: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x46: */
    PSPEMU_CORE_SVC_INIT_NULL,                                                                              /**< 0x47: */
    PSPEMU_CORE_SVC_INIT_DEF("SvcQuerySmmRegion", pspEmuSvcQuerySmmRegion)                                  /**< 0x48: */
};


/**
 * SVC injection registration record.
 */
static const PSPCORESVCREG g_SvcReg =
{
    /** GlobalSvc */
    {
        /** pszName */
        "Trace",
        /** pfnSvcHnd */
        pspEmuSvcTrace,
        /** fFlags */
        PSPEMU_CORE_SVC_F_BEFORE | PSPEMU_CORE_SVC_F_AFTER
    },
    /** cSvcDescs */
    ELEMENTS(g_aSvcDescs),
    /** paSvcDescs */
    &g_aSvcDescs[0]
};


static bool pspEmuSvcTrace(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PSPEmuTraceEvtAddSvc(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_SVC, idxSyscall,
                           (fFlags & PSPEMU_CORE_SVC_F_BEFORE)
                         ? true
                         : false /* fEntry*/,
                         NULL /*pszMsg*/);
    return false;
}


static bool pspEmuSvcAppExit(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;
    (void)idxSyscall;

    /* Stop here as the app exited. */
    uint32_t PspAddrStateRegion = 0;

#if 0 /** @todo */
    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, SVC_GET_STATE_BUFFER, pThis->cbStateRegion, 0, 0, 0, &PspAddrStateRegion);
    if (rc)
        printf("Mapping memory region state failed with %d\n", rc);

    rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrStateRegion, pThis->X86MappingPrivState.pvMapping, pThis->cbStateRegion);
    if (rc)
        printf("Syncing SEV state to privileged DRAM failed with %d\n", rc);
#endif

    PSPEmuCoreExecStop(hCore);
    return true;
}


static bool pspEmuSvcAppInit(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;
    (void)idxSyscall;

    uint32_t uSts = 0;
    PSPADDR  uStackTop = 0x62000;
    PSPADDR  UsrPtrStackAddr = 0;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R2, &UsrPtrStackAddr);
    if (!rc)
    {
        /* Map stack. */
        /*rc = PSPEmuCoreMemAddRegion(pThis->hPspCore, 0x60000, 2 * _4K);*/ /** @todo Done already in the core for the other emulation modes. */
        if (!rc)
            rc = PSPEmuCoreMemWrite(pThis->hPspCore, UsrPtrStackAddr, &uStackTop, sizeof(uStackTop));
        else
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    if (!rc)
        rc = PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);

    return true;
}

static bool pspEmuSvcSmnMapEx(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t uSmnAddr = 0;
    uint32_t idCcdTgt = 0;
    uint32_t uSmnAddrMapped = 0;
    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &uSmnAddr);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &idCcdTgt);
    if (!rc)
    {
        printf("Mapping SMN address %#x on CCD %#x\n", uSmnAddr, idCcdTgt);

        rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uSmnAddr, idCcdTgt, 0, 0, &uSmnAddrMapped);
        if (rc)
            printf("Mapping SMN address failed with %d\n", rc);
    }

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSmnAddrMapped);
    return true;
}

static bool pspEmuSvcSmnMap(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t uSmnAddr = 0;
    uint32_t uSmnAddrMapped = 0;
    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &uSmnAddr);
    if (!rc)
    {
        printf("Mapping SMN address %#x\n", uSmnAddr);

        rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uSmnAddr, 0, 0, 0, &uSmnAddrMapped);
        if (rc)
            printf("Mapping SMN address failed with %d\n", rc);
    }

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSmnAddrMapped);
    return true;
}

static bool pspEmuSvcSmnUnmap(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t uAddr = 0;
    uint32_t uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &uAddr);
    if (!rc)
    {
        printf("Unmapping SMN address %#x\n", uAddr);

        rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uAddr, 0, 0, 0, &uSts);
        if (rc)
            printf("Unmapping SMN address failed with %d\n", rc);
    }

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}

static bool pspEmuSvcDbgLog(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    /* Log the string. */
    PSPADDR PspAddrStr = 0;
    char achStr[512];
    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &PspAddrStr);
    if (!rc)
    {
        PSPEmuCoreMemRead(pThis->hPspCore, PspAddrStr, &achStr[0], 512);
        achStr[512 - 1] = '\0'; /* Ensure termination. */
        printf("PSP Log: %s\n", &achStr[0]);
    }

    return true;
}


/**
 * The fetch callback for an existing x86 memory backing.
 *
 * @returns nothing.
 * @param   offX86Mem               Offset to fetch from the beginning of the mapping.
 * @param   cbFetch                 Number of bytes to fetch.
 * @param   pvDst                   Where to store the fetched data.
 * @param   pvUser                  Opqaue user data passed during region creation.
 */
static void pspEmuIoMgrX86MappingFetch(X86PADDR offX86Mem, size_t cbFetch, void *pvDst, void *pvUser)
{
    PPSPSVCX86MAPPING pMapping = (PPSPSVCX86MAPPING)pvUser;

    int rc = PSPProxyCtxPspMemRead(pMapping->pThis->hProxyCtx, pMapping->PspAddrProxyBase + (uint32_t)offX86Mem, pvDst, cbFetch);
    if (rc)
        printf("Fetching memory content from %#lx failed with %rc\n", pMapping->PspAddrProxyBase + (uint32_t)offX86Mem, rc);
}


/**
 * Worker for the x86 memory mapping syscalls.
 *
 * @returns Status code.
 * @param   pThis                   The SVC state instance.
 * @param   u32PhysX86AddrLow       Low part of the physical x86 address to map.
 * @param   u32PhysX86AddrHigh      High part of the physical x86 address to map.
 * @param   uMemType                The type of memory to map (presumably).
 * @param   pPspAddrMapped          Where to store the virtual PSP address of the mapping on success.
 */
static int pspEmuSvcX86MemMapWorker(PPSPSVCINT pThis, uint32_t u32PhysX86AddrLow, uint32_t u32PhysX86AddrHigh, uint32_t uMemType,
                                    PSPADDR *pPspAddrMapped)
{
    int rc = -1;
    X86PADDR PhysX86Addr = (((uint64_t)u32PhysX86AddrLow << 32) | u32PhysX86AddrHigh);
    X86PADDR PhysX86AddrBase = (PhysX86Addr & ~(_64M - 1));
    uint32_t offStart = PhysX86Addr - PhysX86AddrBase;
    size_t cbMapping = (PhysX86AddrBase + _64M) - PhysX86Addr;
    printf("Mapping x86 address %#lx (64MB aligned base %#lx, memory target %u)\n", PhysX86Addr, PhysX86AddrBase, uMemType);

    /* Search for a free mapping slot (unlike the real off chip bootloader we treat all slots equal). */
    PPSPSVCX86MAPPING pMapping = NULL;
    uint32_t idxSlot = 0;
    for (uint32_t i = 0; i < ELEMENTS(pThis->aX86MapSlots); i++)
    {
        if (   pThis->aX86MapSlots[i].PhysX86AddrBase == NIL_X86PADDR
            && pThis->aX86MapSlots[i].cRefs == 0)
        {
            pMapping = &pThis->aX86MapSlots[i];
            idxSlot = i;
            break;
        }
    }

    if (pMapping)
    {
        /* Map the address into the proxied PSP before creating the actual mapping. */
        PSPADDR PspAddrProxyMap;
        rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, SVC_X86_HOST_MEMORY_MAP, u32PhysX86AddrLow, u32PhysX86AddrHigh, uMemType, 0, &PspAddrProxyMap);
        if (   !rc
            && PspAddrProxyMap != 0)
        {
            pMapping->cRefs            = 1;
            pMapping->uMemType         = uMemType;
            pMapping->PhysX86AddrBase  = PhysX86Addr; /* We cheat here and don't use the full 64MB mapping but cover only what the caller asked for. */
            pMapping->PspAddrProxyBase = PspAddrProxyMap;
            pMapping->cbMapping        = cbMapping;

            /* Create the x86 memory region. */
            rc = PSPEmuIoMgrX86MemRegister(pThis->hIoMgr, PhysX86Addr, cbMapping, false /*fCanExec*/,
                                           pspEmuIoMgrX86MappingFetch, pMapping, "SvcTmpMapping", &pMapping->hIoMgrRegion);
            if (!rc)
            {
                /*
                 * This emulates the real behavior of the off chip bootloader, we program the x86 mapping registers
                 * of the emulated x86 mapping engine to point to our created x86 memory mapping.
                 */
                PSPADDR PspAddrSlotBase = 0x03230000 + idxSlot * 4 * sizeof(uint32_t);
                uint32_t uTmp = 0;

                /* Program base address. */
                uTmp = ((PhysX86AddrBase >> 32) << 6) | ((PhysX86AddrBase >> 26) & 0x3f);
                rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, PspAddrSlotBase + 0, &uTmp, sizeof(uTmp));
                /* Unknown but fixed value. */
                uTmp = 0x12;
                if (!rc)
                    rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, PspAddrSlotBase + 4, &uTmp, sizeof(uTmp));
                if (!rc)
                    rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, PspAddrSlotBase + 8, &uMemType, sizeof(uMemType));
                if (!rc)
                    rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, PspAddrSlotBase + 12, &uMemType, sizeof(uMemType));

                uTmp = 0xffffffff;
                if (!rc)
                    rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, 0x032303e0 + idxSlot * sizeof(uint32_t), &uTmp, sizeof(uTmp));
                uTmp = 0xc0000000;
                if (!rc)
                    rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, 0x032304d8 + idxSlot * sizeof(uint32_t), &uTmp, sizeof(uTmp));
                if (!rc)
                    *pPspAddrMapped = 0x04000000 + idxSlot * _64M + offStart;
                else
                {
                    /* Something went wrong... */
                    /** @todo Undo everything. */
                    printf("Programming the x86 mapping control registers failed with %d\n", rc);
                }
            }
            else
            {
                uint32_t uSts = 0;
                int rc2 = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, SVC_X86_HOST_MEMORY_UNMAP, PspAddrProxyMap, 0, 0, 0, &uSts);
                printf("Creating the x86 memory region failed with %d (Unmapping proxied memory yielded rc=%d uSts=%#x)\n", rc, rc2, uSts);
            }
        }
        else
            printf("Mapping %#lx on the proxied PSP failed with rc=%d PspAddrProxyMap=%#x\n", rc, PspAddrProxyMap);
    }
    else
    {
        /* This should never happen as the real PSP has only 15 mapping slots. */
        /** @todo Unmap the mapping on the proxied PSP. */
        printf("Ran out of x86 mapping slots, impossible!\n");
        rc = -1;
    }

    return rc;
}


static bool pspEmuSvcX86MemMap(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t u32PhysX86AddrLow = 0;
    uint32_t u32PhysX86AddrHigh = 0;
    PSPADDR  PspAddrMap = 0;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &u32PhysX86AddrLow);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &u32PhysX86AddrHigh);
    if (!rc)
        rc = pspEmuSvcX86MemMapWorker(pThis, u32PhysX86AddrLow, u32PhysX86AddrHigh, 4 /*From off chip bootloader*/,
                                      &PspAddrMap);
    if (rc)
        PspAddrMap = 0;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, PspAddrMap);
    return true;
}

static bool pspEmuSvcX86MemUnmap(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    PSPADDR  PspAddrMap = 0;
    uint32_t uSts = PSPSTATUS_SUCCESS;
    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &PspAddrMap);
    if (!rc)
    {
        /* Extract slot and offset. */
        PspAddrMap -= 0x04000000; /* Get rid of base address. */
        uint32_t offMapping = PspAddrMap & (_64M - 1);
        PspAddrMap &= ~(_64M - 1); /* Mask out the mapping offset. */
        uint32_t idxSlot = PspAddrMap / _64M;

        printf("Unmapping x86 address mapped at %#x (slot %u)\n", PspAddrMap, idxSlot);
        if (idxSlot < ELEMENTS(pThis->aX86MapSlots))
        {
            PPSPSVCX86MAPPING pMapping = &pThis->aX86MapSlots[idxSlot];

            if (pMapping->cRefs > 0)
            {
                pMapping->cRefs--;

                /* If reference counter reached zero the mapping gets destroyed. */
                if (!pMapping->cRefs)
                {
                    /* Sync back memory content before unmapping on the proxied PSP. */
                    size_t cbSyncLeft = pMapping->cbMapping;
                    uint32_t offSync = 0;

                    while (   !rc
                           && cbSyncLeft)
                    {
                        uint8_t abData[_4K];
                        size_t cbThisSync = MIN(sizeof(abData), cbSyncLeft);

                        rc = PSPEmuIoMgrX86MemRead(pMapping->hIoMgrRegion, offSync, &abData[0], cbThisSync);
                        if (!rc)
                            rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, pMapping->PspAddrProxyBase, &abData[0], cbThisSync);

                        offSync    += cbThisSync;
                        cbSyncLeft -= cbThisSync;
                    }

                    if (rc)
                        printf("Syncing the memory to the proxied PSP memory failed with %d\n", rc);

                    /* Unmap on the proxied PSP. */
                    rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, pMapping->PspAddrProxyBase, 0, 0, 0, &uSts);
                    if (rc || uSts)
                        printf("Unmapping x86 address failed with rc=%d uSts=%d\n", rc, uSts);

                    /* Unmap the emulated x86 mapping. */
                    uint32_t uTmp = 0;
                    PSPADDR PspAddrSlotBase = 0x03230000 + idxSlot * 4 * sizeof(uint32_t);

                    rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, PspAddrSlotBase + 0, &uTmp, sizeof(uTmp));
                    if (!rc)
                        rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, PspAddrSlotBase + 4, &uTmp, sizeof(uTmp));
                    if (!rc)
                        rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, PspAddrSlotBase + 8, &uTmp, sizeof(uTmp));
                    if (!rc)
                        rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, PspAddrSlotBase + 12, &uTmp, sizeof(uTmp));
                    if (!rc)
                        rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, 0x032303e0 + idxSlot * sizeof(uint32_t), &uTmp, sizeof(uTmp));
                    if (!rc)
                        rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, 0x032304d8 + idxSlot * sizeof(uint32_t), &uTmp, sizeof(uTmp));
                    if (rc)
                    {
                        /* Something went wrong... */
                        printf("Programming the x86 mapping control registers failed with %d\n", rc);
                    }

                    /* Deregister the mapping. */
                    rc = PSPEmuIoMgrDeregister(pMapping->hIoMgrRegion);
                    if (rc)
                        printf("Deregistering the x86 memory region failed with %d\n");

                    /* Clear the mapping slot. */
                    pMapping->PhysX86AddrBase  = NIL_X86PADDR;
                    pMapping->PspAddrProxyBase = 0;
                    pMapping->uMemType         = 0;
                    pMapping->cRefs            = 0;
                    pMapping->hIoMgrRegion     = NULL;
                }
            }
            else
                uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
        }
        else
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}

static bool pspEmuSvcX86CopyToPsp(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
#if 0
#endif
}

static bool pspEmuSvcX86CopyFromPsp(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
#if 0
#endif
}


static bool pspEmuSvcX86MemMapEx(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t u32PhysX86AddrLow = 0;
    uint32_t u32PhysX86AddrHigh = 0;
    uint32_t uMemType = 0;
    PSPADDR  PspAddrMap = 0;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &u32PhysX86AddrLow);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &u32PhysX86AddrHigh);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R2, &uMemType);
    if (!rc)
        rc = pspEmuSvcX86MemMapWorker(pThis, u32PhysX86AddrLow, u32PhysX86AddrHigh, uMemType,
                                      &PspAddrMap);
    if (rc)
        PspAddrMap = 0;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, PspAddrMap);
    return true;
}

static bool pspEmuSvcSmuMsg(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t idMsg = 0;
    uint32_t uArg0 = 0;
    PSPADDR  UsrPtrReturnMsg;
    uint32_t uSts = 0;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &idMsg);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &uArg0);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R2, &UsrPtrReturnMsg);
    if (!rc)
    {
        PSPADDR PspAddrScratch;
        uint32_t u32Ret;

        rc = PSPProxyCtxScratchSpaceAlloc(pThis->hProxyCtx, sizeof(u32Ret), &PspAddrScratch);
        if (!rc)
        {
            rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, idMsg, uArg0,
                                         UsrPtrReturnMsg != 0
                                       ? PspAddrScratch
                                       : 0,
                                       0, &uSts);
            if (   !rc
                && UsrPtrReturnMsg != 0)
            {
                /* Sync back the return value. */
                rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrScratch, &u32Ret, sizeof(u32Ret));
                if (!rc)
                {
                    rc = PSPEmuCoreMemWrite(pThis->hPspCore, UsrPtrReturnMsg, &u32Ret, sizeof(u32Ret));
                    if (rc)
                        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                }
                else
                    uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
            }
            PSPProxyCtxScratchSpaceFree(pThis->hProxyCtx, PspAddrScratch, sizeof(u32Ret));
        }
        else
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}

static bool pspEmuSvc0x32Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    PSPADDR  PspAddrUnk = 0;
    uint32_t cbUnk = 0;
    uint32_t uSts = 0;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &PspAddrUnk);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &cbUnk);
    if (!rc)
    {
        void *pvTmp = malloc(cbUnk);
        if (pvTmp)
        {
            rc = PSPEmuCoreMemRead(pThis->hPspCore, PspAddrUnk, pvTmp, cbUnk);
            if (!rc)
            {
                PSPADDR PspAddrProxy;
                rc = PSPProxyCtxScratchSpaceAlloc(pThis->hProxyCtx, cbUnk, &PspAddrProxy);
                if (!rc)
                {
                    rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy, pvTmp, cbUnk);
                    if (!rc)
                    {
                        rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, PspAddrProxy, cbUnk, 0, 0, &uSts);
                        if (!rc && uSts == 0)
                        {
                            /* Sync memory back. */
                            rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy, pvTmp, cbUnk);
                            if (!rc)
                            {
                                rc = PSPEmuCoreMemWrite(pThis->hPspCore, PspAddrUnk, pvTmp, cbUnk);
                                if (rc)
                                    uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                            }
                            else
                                uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                        }
                        else
                        {
                            printf("Syscall failed with rc=%d uSts=%#x\n", rc, uSts);
                            if (rc)
                                uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                        }
                    }
                    else
                        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

                    PSPProxyCtxScratchSpaceFree(pThis->hProxyCtx, PspAddrProxy, cbUnk);
                }
                else
                    uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
            }
            else
                uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

            free(pvTmp);
        }
        else
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}

static bool pspEmuSvc0x33Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    PSPADDR  PspAddrUnk = 0;
    uint32_t cbUnk = 0;
    uint32_t uSts = 0;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &PspAddrUnk);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &cbUnk);
    if (!rc)
    {
        printf("Unknown syscall 0x33 with parameters: PspAddrUnk=%#x cbUnk=%#x\n", PspAddrUnk, cbUnk);

        void *pvTmp = malloc(cbUnk);
        if (pvTmp)
        {
            rc = PSPEmuCoreMemRead(pThis->hPspCore, PspAddrUnk, pvTmp, cbUnk);
            if (!rc)
            {
                PSPADDR PspAddrProxy;
                rc = PSPProxyCtxScratchSpaceAlloc(pThis->hProxyCtx, cbUnk, &PspAddrProxy);
                if (!rc)
                {
                    rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy, pvTmp, cbUnk);
                    if (!rc)
                    {
                        rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, PspAddrProxy, cbUnk, 0, 0, &uSts);
                        if (!rc && uSts == 0)
                        {
                            /* Sync memory back. */
                            rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy, pvTmp, cbUnk);
                            if (!rc)
                            {
                                rc = PSPEmuCoreMemWrite(pThis->hPspCore, PspAddrUnk, pvTmp, cbUnk);
                                if (rc)
                                    uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                            }
                            else
                                uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                        }
                        else
                        {
                            printf("Syscall failed with rc=%d uSts=%#x\n", rc, uSts);
                            if (rc)
                                uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                        }
                    }
                    else
                        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

                    PSPProxyCtxScratchSpaceFree(pThis->hProxyCtx, PspAddrProxy, cbUnk);
                }
                else
                    uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
            }
            else
                uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

            free(pvTmp);
        }
        else
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}

static bool pspEmuSvcPlatformReset(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t uArgUnk = 0;
    uint32_t uSts = 0;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &uArgUnk);
    if (!rc)
    {
        rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uArgUnk, 0, 0, 0, &uSts);
        if (rc)
        {
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
            printf("Platform reset failed with %d\n", rc);
        }
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}


static bool pspEmuSvc0x35Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
#if 0
    uint32_t au32Req[8];
    uint32_t uSts = 0;
    PSPADDR  PspAddrReq;

    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrReq);
    uc_mem_read(pThis->pUcEngine, PspAddrReq, &au32Req[0], sizeof(au32Req));

    printf("Syscall 0x35 request:\n"
           "au32Req[0]: %#x\n"
           "au32Req[1]: %#x\n"
           "au32Req[2]: %#x\n"
           "au32Req[3]: %#x\n"
           "au32Req[4]: %#x\n"
           "au32Req[5]: %#x\n"
           "au32Req[6]: %#x\n"
           "au32Req[7]: %#x\n",
           au32Req[0], au32Req[1], au32Req[2], au32Req[3],
           au32Req[4], au32Req[5], au32Req[6], au32Req[7]);

    if (au32Req[2] == 0 && au32Req[3] == 0)
    {
        uint32_t au32ReqProxy[8];
        uint8_t abTmp[128];
        PSPADDR PspAddrProxy1 = 0x20000;
        PSPADDR PspAddrProxy2 = PspAddrProxy1 + au32Req[1];
        PSPADDR PspAddrProxy3 = PspAddrProxy2 + au32Req[5];

        uc_mem_read(pThis->pUcEngine, au32Req[0], &abTmp[0], au32Req[1]);
        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy1, &abTmp[0], au32Req[1]);

        uc_mem_read(pThis->pUcEngine, au32Req[4], &abTmp[0], au32Req[5]);
        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy2, &abTmp[0], au32Req[5]);

        uc_mem_read(pThis->pUcEngine, au32Req[6], &abTmp[0], au32Req[7]);
        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy3, &abTmp[0], au32Req[7]);

        au32ReqProxy[0] = PspAddrProxy1;
        au32ReqProxy[1] = au32Req[1];
        au32ReqProxy[2] = au32Req[2];
        au32ReqProxy[3] = au32Req[3];
        au32ReqProxy[4] = PspAddrProxy2;
        au32ReqProxy[5] = au32Req[5];
        au32ReqProxy[6] = PspAddrProxy3;
        au32ReqProxy[7] = au32Req[7];

        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x23000, &au32ReqProxy[0], sizeof(au32ReqProxy));

        int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x23000, 0, 0, 0, &uSts);
        if (!rc && uSts == 0)
        {
            /* Sync memory back. */
            PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy1, &abTmp[0], au32Req[1]);
            uc_mem_write(pThis->pUcEngine, au32Req[0], &abTmp[0], au32Req[1]);

            PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy2, &abTmp[0], au32Req[5]);
            uc_mem_write(pThis->pUcEngine, au32Req[4], &abTmp[0], au32Req[5]);

            PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy3, &abTmp[0], au32Req[7]);
            uc_mem_write(pThis->pUcEngine, au32Req[6], &abTmp[0], au32Req[7]);
        }
        else
        {
            printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
            if (rc)
                uSts = 0x9;
        }
    }
    else
    {
        printf("Request not implemented\n");
        uSts = 0x9;
    }

    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
#endif
}

static bool pspEmuSvc0x36Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
#if 0
    uint32_t au32Req[13];
    uint32_t uSts = 0x9;
    PSPADDR  PspAddrReq;

    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrReq);
    uc_mem_read(pThis->pUcEngine, PspAddrReq, &au32Req[0], sizeof(au32Req));

    printf("Syscall 0x36 request:\n"
           "au32Req[0]: %#x\n"
           "au32Req[1]: %#x\n"
           "au32Req[2]: %#x\n"
           "au32Req[3]: %#x\n"
           "au32Req[4]: %#x\n"
           "au32Req[5]: %#x\n"
           "au32Req[6]: %#x\n"
           "au32Req[7]: %#x\n"
           "au32Req[8]: %#x\n"
           "au32Req[9]: %#x\n"
           "au32Req[10]: %#x\n"
           "au32Req[11]: %#x\n"
           "au32Req[12]: %#x\n",
           au32Req[0], au32Req[1], au32Req[2], au32Req[3],
           au32Req[4], au32Req[5], au32Req[6], au32Req[7],
           au32Req[8], au32Req[9], au32Req[10], au32Req[11],
           au32Req[12]);

    uint32_t au32ReqProxy[13];
    void *pvTmp = malloc(_256K);
    PSPADDR PspAddrProxy1 = 0x20000;
    PSPADDR PspAddrProxy2 = PspAddrProxy1 + au32Req[1];
    PSPADDR PspAddrProxy3 = PspAddrProxy2 + au32Req[3];
    PSPADDR PspAddrProxy4 = PspAddrProxy3 + au32Req[6];

    uc_mem_read(pThis->pUcEngine, au32Req[0], pvTmp, au32Req[1]);
    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy1, pvTmp, au32Req[1]);

    uc_mem_read(pThis->pUcEngine, au32Req[2], pvTmp, au32Req[3]);
    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy2, pvTmp, au32Req[3]);

    uc_mem_read(pThis->pUcEngine, au32Req[5], pvTmp, au32Req[6]);
    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy3, pvTmp, au32Req[6]);

    uc_mem_read(pThis->pUcEngine, au32Req[8], pvTmp, au32Req[9]);
    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy4, pvTmp, au32Req[9]);

    au32ReqProxy[0] = PspAddrProxy1;
    au32ReqProxy[1] = au32Req[1];
    au32ReqProxy[2] = PspAddrProxy2;
    au32ReqProxy[3] = au32Req[3];
    au32ReqProxy[4] = au32Req[4];
    au32ReqProxy[5] = PspAddrProxy3;
    au32ReqProxy[6] = au32Req[6];
    au32ReqProxy[7] = au32Req[7];
    au32ReqProxy[8] = PspAddrProxy4;
    au32ReqProxy[9] = au32Req[9];
    au32ReqProxy[10] = au32Req[10];
    au32ReqProxy[11] = au32Req[11];
    au32ReqProxy[12] = au32Req[12];

    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy4 + au32Req[9], &au32ReqProxy[0], sizeof(au32ReqProxy));

    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, PspAddrProxy4 + au32Req[9], 0, 0, 0, &uSts);
    if (!rc && uSts == 0)
    {
        /* Sync memory back. */
        PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy1, pvTmp, au32Req[1]);
        uc_mem_write(pThis->pUcEngine, au32Req[0], pvTmp, au32Req[1]);

        PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy2, pvTmp, au32Req[3]);
        uc_mem_write(pThis->pUcEngine, au32Req[2], pvTmp, au32Req[3]);

        PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy3, pvTmp, au32Req[6]);
        uc_mem_write(pThis->pUcEngine, au32Req[5], pvTmp, au32Req[6]);

        PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy4, pvTmp, au32Req[9]);
        uc_mem_write(pThis->pUcEngine, au32Req[8], pvTmp, au32Req[9]);
    }
    else
    {
        printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
        if (rc)
            uSts = 0x9;
    }

    free(pvTmp);
    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
#endif
}

static bool pspEmuSvcInvalidateMemory(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t uInvOp = 0;
    uint32_t fData = 0;
    PSPADDR  PspAddrStart = 0;
    uint32_t cbMem = 0;
    uint32_t uSts = 0;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &uInvOp);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &fData);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R2, &PspAddrStart);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R3, &cbMem);
    if (!rc)
    {
        rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uInvOp, fData, PspAddrStart, cbMem, &uSts);
        if (rc)
        {
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
            printf("Invalidating/cleaning PSP memory failed with %d\n", rc);
        }
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}

static bool pspEmuSvc0x38Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
#if 0
    PSPADDR PspAddrReq;
    PSPCCPREQSVC0X38 Req;
    uint32_t uSts = 0;

    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrReq);
    uc_mem_read(pThis->pUcEngine, PspAddrReq, &Req, sizeof(Req));

    /* Dump request structure. */
    printf("CCP Request:\n"
           "    PspAddrBufUnk0:  %#x\n"
           "    cbBufUnk0:       %#x\n"
           "    dwUnk1:          %#x\n"
           "    PspAddrBufUnk1:  %#x\n"
           "    cbBufUnk1:       %#x\n"
           "    PspAddrBufUnk2:  %#x\n"
           "    dwUnk3:          %#x\n"
           "    dwUnk4:          %#x\n"
           "    dwUnk5:          %#x\n",
           Req.PspAddrBufUnk0, Req.cbBufUnk0,
           Req.dwUnk1, Req.PspAddrBufUnk1, Req.cbBufUnk1,
           Req.PspAddrBufUnk2, Req.dwUnk3, Req.dwUnk4, Req.dwUnk5);
    if (   Req.dwUnk1 == 0x2
        && Req.cbBufUnk1 == 0x20)
    {
        PSPCCPREQSVC0X38 ReqProxy;
        void *pvTmp = malloc(_256K);
        memcpy(&ReqProxy, &Req, sizeof(Req));

        /* Sync inputs. */
        if (Req.PspAddrBufUnk0)
            ReqProxy.PspAddrBufUnk0 = 0x22000;
        ReqProxy.PspAddrBufUnk1 = 0x21100;
        if (Req.PspAddrBufUnk2)
            ReqProxy.PspAddrBufUnk2 = 0x21200;
        int rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x20000, &ReqProxy, sizeof(ReqProxy));
        if (!rc && Req.PspAddrBufUnk0)
        {
            uc_mem_read(pThis->pUcEngine, Req.PspAddrBufUnk0, pvTmp, Req.cbBufUnk0);
            rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk0, pvTmp, Req.cbBufUnk0);
        }
        if (!rc && Req.PspAddrBufUnk1)
        {
            uc_mem_read(pThis->pUcEngine, Req.PspAddrBufUnk1, pvTmp, Req.cbBufUnk1);
            rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk1, pvTmp, Req.cbBufUnk1);
        }
        if (!rc && Req.PspAddrBufUnk2)
        {
            uc_mem_read(pThis->pUcEngine, Req.PspAddrBufUnk2, pvTmp, 0x20);
            rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk2, pvTmp, 0x20);
        }
        if (!rc)
        {
            rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x20000, 0, 0, 0, &uSts);
            if (!rc && uSts == 0)
            {
                /* Sync memory back. */
                if (Req.PspAddrBufUnk0)
                {
                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk0, pvTmp, Req.cbBufUnk0);
                    uc_mem_write(pThis->pUcEngine, Req.PspAddrBufUnk0, pvTmp, Req.cbBufUnk0);
                }
                if (Req.PspAddrBufUnk1)
                {
                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk1, pvTmp, Req.cbBufUnk1);
                    uc_mem_write(pThis->pUcEngine, Req.PspAddrBufUnk1, pvTmp, Req.cbBufUnk1);
                }
                if (Req.PspAddrBufUnk2)
                {
                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk2, pvTmp, 0x20);
                    uc_mem_write(pThis->pUcEngine, Req.PspAddrBufUnk2, pvTmp, 0x20);
                }
            }
            else
            {
                printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
                if (rc)
                    uSts = 0x9;
            }
        }
        else
        {
            printf("Memory write failed with %d\n", rc);
            uSts = 0x9;
        }
        free(pvTmp);
    }
    else
    {
        printf("CCP request not implemented, failing\n");
        uSts = 0x9;
    }

    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
#endif
}

static bool pspEmuSvcRng(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    PSPADDR PspAddrBuf = 0;
    uint32_t cbBuf = 0;
    uint32_t uSts = PSPSTATUS_SUCCESS;
    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &PspAddrBuf);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &cbBuf);
    if (!rc)
    {
        printf("Filling %#x with %#x bytes of random data\n", PspAddrBuf, cbBuf);
        void *pvTmp = malloc(cbBuf);
        if (pvTmp)
        {
            PSPADDR PspAddrProxyBuf;

            int rc = PSPProxyCtxScratchSpaceAlloc(pThis->hProxyCtx, cbBuf, &PspAddrProxyBuf);
            if (!rc)
            {
                /* Execute syscall. */
                rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, PspAddrProxyBuf, cbBuf, 0, 0, &uSts);
                if (!rc && uSts == PSPSTATUS_SUCCESS)
                {
                    /* Sync stack buffers back. */
                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxyBuf, pvTmp, cbBuf);
                    rc = PSPEmuCoreMemWrite(pThis->hPspCore, PspAddrBuf, pvTmp, cbBuf);
                    if (rc)
                        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                }
                else
                {
                    printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
                    if (rc)
                        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                }

                PSPProxyCtxScratchSpaceFree(pThis->hProxyCtx, PspAddrProxyBuf, cbBuf);
            }

            free(pvTmp);
        }
        else
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}

static bool pspEmuSvcQuerySaveStateRegion(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
#if 0
    uint32_t uStateRegionAddr = 0;
    uint32_t cbStateRegion = 0;

    uc_reg_read(uc, UC_ARM_REG_R0, &cbStateRegion);
    printf("Querying state region of size %#x\n", cbStateRegion);

    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, cbStateRegion, 0, 0, 0, &uStateRegionAddr);
    if (rc)
        printf("Querying state address failed with %d\n", rc);

    printf("SEV app state address: %#x\n", uStateRegionAddr);

    /* Initialize mapping if not done already. */
    PPSPX86MEMCACHEDMAPPING pMapping = &pThis->X86MappingPrivState;
    if (pMapping->PhysX86AddrBase == NIL_X86PADDR)
    {
        pMapping->PhysX86AddrBase       = 0xdeadd0d0; /* Fake value because we don't know the real address (could retrieve it but why bother). */
        pMapping->PspAddrBase4K         = uStateRegionAddr & ~(uint32_t)0xfff;
        pMapping->PspAddrBase           = uStateRegionAddr;
        pMapping->PspAddrCached         = 0;
        pMapping->PspAddrHighestWritten = 0;
        pMapping->pPspCore              = pThis;
        pMapping->cbMapped              = ((uStateRegionAddr & ~(_64M - 1)) + _64M) - uStateRegionAddr;
        pMapping->cbMapped4K            = (pMapping->cbMapped + _4K) & ~(uint32_t)0xfff;
        pMapping->cbAlloc               = pMapping->cbMapped4K;
        pMapping->pvMapping             = malloc(pMapping->cbAlloc);
        pThis->cbStateRegion         = cbStateRegion;
        uc_mem_map_ptr(uc, pMapping->PspAddrBase4K, pMapping->cbMapped4K, UC_PROT_ALL, pMapping->pvMapping);
    }

    uc_reg_write(uc, UC_ARM_REG_R0, &uStateRegionAddr);
#endif
}

static bool pspEmuSvc0x41Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
#if 0
    PSPADDR PspAddrReq = 0;
    uint32_t uSts = 0;
    uint32_t au32Req[8];

    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrReq);
    uc_mem_read(pThis->pUcEngine, PspAddrReq, &au32Req, sizeof(au32Req));
    printf("Syscall 0x41 request:\n"
           "au32Req[0]: %#x\n"
           "au32Req[1]: %#x\n"
           "au32Req[2]: %#x\n"
           "au32Req[3]: %#x\n"
           "au32Req[4]: %#x\n"
           "au32Req[5]: %#x\n"
           "au32Req[6]: %#x\n"
           "au32Req[7]: %#x\n",
           au32Req[0], au32Req[1], au32Req[2], au32Req[3],
           au32Req[4], au32Req[5], au32Req[6], au32Req[7]);

    if (au32Req[0] == 1 || au32Req[0] == 5 || au32Req[0] == 3 || au32Req[0] == 2)
    {
        uint32_t au32ReqProxy[8];
        void *pvTmp = malloc(2*_4K);
        /* Sync the stack where the buffers are living. */
        uc_mem_read(pThis->pUcEngine, 0x60000, pvTmp, 2 * _4K);
        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x20000, pvTmp, 2 * _4K);

        memset(&au32ReqProxy[0], 0, sizeof(au32ReqProxy));

        if (au32Req[0] == 1)
        {
            /* Sync some part of the ECDH/ECDSA curve constants it seems. */
            uc_mem_read(pThis->pUcEngine, au32Req[2], pvTmp, 144);
            PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22000, pvTmp, 144);

            /* Set up the proxy request structure. */
            au32ReqProxy[0] = 1;
            au32ReqProxy[1] = 0x20000 + (au32Req[1] - 0x60000);
            au32ReqProxy[2] = 0x22000;
            au32ReqProxy[3] = 0x20000 + (au32Req[3] - 0x60000);
            au32ReqProxy[4] = 0x20000 + (au32Req[4] - 0x60000);
        }
        else if (au32Req[0] == 5)
        {
            /* Sync some part of the ECDH/ECDSA curve constants it seems. */
            uc_mem_read(pThis->pUcEngine, 0x1c6ac, pvTmp, 508);
            PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22000, pvTmp, 508);

            /* Set up the proxy request structure. */
            au32ReqProxy[0] = 5;
            au32ReqProxy[1] = 0x20000 + (au32Req[1] - 0x60000);
            au32ReqProxy[2] = 0x22000 + (au32Req[2] - 0x1c6ac);
            au32ReqProxy[3] = 0x22000 + (au32Req[3] - 0x1c6ac);
            au32ReqProxy[4] = 0x20000 + (au32Req[4] - 0x60000);
            au32ReqProxy[5] = 0x22000 + (au32Req[5] - 0x1c6ac);
        }
        else if (au32Req[0] == 3)
        {
            /* Sync some part of the ECDH/ECDSA curve constants it seems. */
            uc_mem_read(pThis->pUcEngine, 0x1c6ac, pvTmp, 508);
            PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22000, pvTmp, 508);

            /* Set up the proxy request structure. */
            au32ReqProxy[0] = 3;
            au32ReqProxy[1] = 0x20000 + (au32Req[1] - 0x60000);
            au32ReqProxy[2] = 0x22000 + (au32Req[2] - 0x1c6ac);
            au32ReqProxy[3] = 0x20000 + (au32Req[3] - 0x60000);
        }
        else if (au32Req[0] == 2)
        {
            /* Sync some part of the ECDH/ECDSA curve constants it seems. */
            uc_mem_read(pThis->pUcEngine, 0x1c6ac, pvTmp, 508);
            PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22000, pvTmp, 508);

            if (au32Req[3] < 0x60000)
            {
                /* Doesn't live on the stack. */
                uc_mem_read(pThis->pUcEngine, au32Req[3], pvTmp, 1024);
                PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22500, pvTmp, 1024);
                au32ReqProxy[3] = 0x22500;
            }
            else
                au32ReqProxy[3] = 0x20000 + (au32Req[3] - 0x60000);

            /* Set up the proxy request structure. */
            au32ReqProxy[0] = 2;
            au32ReqProxy[1] = 0x20000 + (au32Req[1] - 0x60000);
            au32ReqProxy[2] = 0x22000 + (au32Req[2] - 0x1c6ac);
            au32ReqProxy[4] = 0x20000 + (au32Req[4] - 0x60000);
        }

        printf("Proxied request:\n"
               "au32Req[0]: %#x\n"
               "au32Req[1]: %#x\n"
               "au32Req[2]: %#x\n"
               "au32Req[3]: %#x\n"
               "au32Req[4]: %#x\n"
               "au32Req[5]: %#x\n",
               au32ReqProxy[0], au32ReqProxy[1], au32ReqProxy[2], au32ReqProxy[3],
               au32ReqProxy[4], au32ReqProxy[5]);

        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x23000, &au32ReqProxy[0], sizeof(au32ReqProxy));

        /* Execute syscall. */
        int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x23000, 0, 0, 0, &uSts);
        if (!rc && uSts == 0)
        {
            /* Sync stack buffers back. */
            PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x20000, pvTmp, 2 * _4K);
            uc_mem_write(pThis->pUcEngine, 0x60000, pvTmp, 2 * _4K);

            if (au32Req[0] == 2 && au32Req[3] < 0x60000)
            {
                PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x22500, pvTmp, 1024);
                uc_mem_write(pThis->pUcEngine, au32Req[3], pvTmp, 1024);
            }
        }
        else
        {
            printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
            if (rc)
                uSts = 0x9;
        }
        free(pvTmp);
    }
    else
    {
        printf("Request not implemented, failing\n");
        uSts = 0x9;
    }

    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
#endif
}

static bool pspEmuSvc0x42Unk(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
#if 0
    PSPADDR PspAddrBufUnk = 0;
    PSPADDR PspAddrSizeUnk = 0;
    uint32_t cbUnk = 0;
    uint32_t uSts = 0;

    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrBufUnk);
    uc_reg_read(uc, UC_ARM_REG_R1, &PspAddrSizeUnk);
    uc_mem_read(pThis->pUcEngine, PspAddrSizeUnk, &cbUnk, sizeof(cbUnk));

    void *pvTmp = malloc(cbUnk);
    uc_mem_read(pThis->pUcEngine, PspAddrBufUnk, pvTmp, cbUnk);

    /* Sync input. */
    int rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x20000, pvTmp, cbUnk);
    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x21000, &cbUnk, sizeof(cbUnk));

    rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x20000, 0x21000, 0, 0, &uSts);
    if (rc)
        printf("Executing syscall 0x42 failed with %d\n", rc);

    /* Sync outputs. */
    PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x21000, &cbUnk, sizeof(cbUnk));
    PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x20000, pvTmp, cbUnk);
    uc_mem_write(pThis->pUcEngine, PspAddrSizeUnk, &cbUnk, sizeof(cbUnk));
    uc_mem_write(pThis->pUcEngine, PspAddrBufUnk, pvTmp, cbUnk);

    //PSPEmuWriteData("/home/alex/onchip_fuses.bin", pvTmp, cbUnk);

    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
#endif
}

static bool pspEmuSvcQuerySmmRegion(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPSVCINT pThis = (PPSPSVCINT)pvUser;

    uint32_t UsrPtrSmmRegionStart = 0;
    uint32_t UsrPtrSmmRegionSize  = 0;
    uint32_t uSts = PSPSTATUS_SUCCESS;

    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R0, &UsrPtrSmmRegionStart);
    if (!rc)
        rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_R1, &UsrPtrSmmRegionSize);
    if (!rc)
    {
        PSPADDR PspAddrScratch;
        uint64_t PhysX86AddrSmmRegionStart = 0;
        uint64_t SmmRegionSize = 0;

        rc = PSPProxyCtxScratchSpaceAlloc(pThis->hProxyCtx,
                                          sizeof(PhysX86AddrSmmRegionStart) + sizeof(SmmRegionSize),
                                          &PspAddrScratch);
        if (!rc)
        {
            rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, PspAddrScratch, PspAddrScratch + sizeof(PhysX86AddrSmmRegionStart), 0, 0, &uSts);
            if (!rc)
            {
                rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrScratch, &PhysX86AddrSmmRegionStart, sizeof(PhysX86AddrSmmRegionStart));
                if (!rc)
                    rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrScratch + sizeof(PhysX86AddrSmmRegionStart), &SmmRegionSize, sizeof(SmmRegionSize));
                if (!rc)
                {
                    rc = PSPEmuCoreMemWrite(pThis->hPspCore, UsrPtrSmmRegionStart, &PhysX86AddrSmmRegionStart, sizeof(PhysX86AddrSmmRegionStart));
                    if (!rc)
                        rc = PSPEmuCoreMemWrite(pThis->hPspCore, UsrPtrSmmRegionSize, &SmmRegionSize, sizeof(SmmRegionSize));
                    if (rc)
                        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                }
                else
                    uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
            }
            else
            {
                uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
                printf("Querying SMM region boundaries failed with %d\n", rc);
            }

            PSPProxyCtxScratchSpaceFree(pThis->hProxyCtx, PspAddrScratch, sizeof(PhysX86AddrSmmRegionStart) + sizeof(SmmRegionSize));
        }
        else
            uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;
    }
    else
        uSts = PSPSTATUS_GENERAL_MEMORY_ERROR;

    PSPEmuCoreSetReg(pThis->hPspCore, PSPCOREREG_R0, uSts);
    return true;
}

int PSPEmuSvcStateCreate(PPSPSVC phSvcState, PSPCORE hPspCore, PSPIOM hIoMgr, PSPPROXYCTX hPspProxyCtx)
{
    int rc = 0;
    PPSPSVCINT pThis = (PPSPSVCINT)calloc(1, sizeof(*pThis));

    if (pThis != NULL)
    {
        pThis->hPspCore  = hPspCore;
        pThis->hIoMgr    = hIoMgr;
        pThis->hProxyCtx = hPspProxyCtx;

        for (uint32_t i = 0; i < ELEMENTS(pThis->aX86MapSlots); i++)
        {
            pThis->aX86MapSlots[i].PhysX86AddrBase  = NIL_X86PADDR;
            pThis->aX86MapSlots[i].cRefs            = 0;
            pThis->aX86MapSlots[i].PspAddrProxyBase = 0;
            pThis->aX86MapSlots[i].uMemType         = 0;
            pThis->aX86MapSlots[i].cbMapping        = 0;
            pThis->aX86MapSlots[i].pThis            = pThis;
        }

        rc = PSPEmuCoreSvcInjectSet(hPspCore, &g_SvcReg, pThis);
        if (!rc)
            *phSvcState = pThis;
        else
            free(pThis);
    }
    else
        rc = -1;

    return rc;
}

void PSPEmuSvcStateDestroy(PSPSVC hSvcState)
{
    PPSPSVCINT pThis = hSvcState;

    PSPEmuCoreSvcInjectSet(pThis->hPspCore, NULL, NULL);
    free(pThis);
}

