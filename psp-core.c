/** @file
 * PSP Emulator - Core API (interfacing with unicorn engine).
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
#include <unicorn/unicorn.h>

#include <common/types.h>
#include <common/cdefs.h>

#include <psp-core.h>
#include <psp-svc.h>
#include <psp-disasm.h>

/**
 * A datum read/written.
 */
typedef union PSPDATUM
{
    uint8_t   u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    uint8_t  ab[8];
} PSPDATUM;
typedef PSPDATUM *PPSPDATUM;

/** Pointer to a PSP core instance. */
typedef struct PSPCOREINT *PPSPCOREINT;
/** Pointer to a const PSP core instance. */
typedef const struct PSPCOREINT *PCPSPCOREINT;

/**
 * Cached x86 memory mapping
 */
typedef struct PSPX86MEMCACHEDMAPPING
{
    /** Pointer to the owning PSP core instance. */
    PCPSPCOREINT        pPspCore;
    /** X86 Mapped base address, NIL_X86PADDR if mapping is not used. */
    X86PADDR            PhysX86AddrBase;
    /** 4K aligned base address of the mapping (for unicorn). */
    PSPADDR             PspAddrBase4K;
    /** PSP base address of the mapping. */
    PSPADDR             PspAddrBase;
    /** Highest cached address so far (exclusive, defines the memory span initialized). */
    PSPADDR             PspAddrCached;
    /** Highest address written so far (exclusive, defines range of memory we have to sync back on unmap). */
    PSPADDR             PspAddrHighestWritten;
    /** Size of mapped area. */
    size_t              cbMapped;
    /** 4K aligned mapping size (for unicorn). */
    size_t              cbMapped4K;
    /** Amount of memory allocated. */
    size_t              cbAlloc;
    /** Pointer to the memory caching the mapping. */
    void                *pvMapping;
} PSPX86MEMCACHEDMAPPING;
typedef PSPX86MEMCACHEDMAPPING *PPSPX86MEMCACHEDMAPPING;

/**
 * A single trace hook.
 */
typedef struct PSPCORETRACEHOOK
{
    /** Next trace hook in the list. */
    struct PSPCORETRACEHOOK *pNext;
    /** Start PSP address. */
    PSPADDR                 PspAddrStart;
    /** End PSP address. */
    PSPADDR                 PspAddrEnd;
    /** PSP core the hook belongs to. */
    PPSPCOREINT             pPspCore;
    /** The trace callback to execute. */
    PFNPSPCORETRACE         pfnTrace;
    /** Opaque user data to pass to the callback. */
    void                    *pvUser;
    /** The unicorn hook handle. */
    uc_hook                 hUcHook;
} PSPCORETRACEHOOK;
/** Pointer to a trace hook. */
typedef PSPCORETRACEHOOK *PPSPCORETRACEHOOK;
/** Pointer to a const trace hook. */
typedef const PSPCORETRACEHOOK *PCPSPCORETRACEHOOK;


/**
 * A single MMIO region registration.
 */
typedef struct PSPCOREMMIOREGION
{
    /** Next MMIO region in the list. */
    struct PSPCOREMMIOREGION *pNext;
    /** Start PSP address. */
    PSPADDR                  PspAddrStart;
    /** Size of the MMIO region. */
    size_t                   cbMmio;
    /** PSP core the region belongs to. */
    PPSPCOREINT              pPspCore;
    /** MMIO read handler. */
    PFNPSPCOREMMIOREAD       pfnRead;
    /** MMIO write handler. */
    PFNPSPCOREMMIOWRITE      pfnWrite;
    /** Opaque user data to pass to the read/write callbacks. */
    void                     *pvUser;
} PSPCOREMMIOREGION;
/** Pointer to a trace hook. */
typedef PSPCOREMMIOREGION *PPSPCOREMMIOREGION;
/** Pointer to a const trace hook. */
typedef const PSPCOREMMIOREGION *PCPSPCOREMMIOREGION;


/**
 * A single PSP core executing.
 */
typedef struct PSPCOREINT
{
    /** The emulation mode. */
    PSPCOREMODE             enmMode;
    /** The unicorn engine pointer. */
    uc_engine               *pUcEngine;
    /** The svc interrupt hook. */
    uc_hook                 pUcHookSvc;
    /** The SRAM region. */
    void                    *pvSram;
    /** Size of the SRAM region. */
    size_t                  cbSram;
    /** The CCD ID. */
    uint32_t                idCcd;
    /** The supervisor emulation instance if app emulation is used. */
    PSPSVC                  hSvcState;
    /** The next address to execute instructions from. */
    PSPADDR                 PspAddrExecNext;

    /** Head of registered trace hooks. */
    PPSPCORETRACEHOOK       pTraceHooksHead;
    /** Head of MMIO regions. */
    PPSPCOREMMIOREGION      pMmioRegionsHead;

    /** Flag whether an SVC call is pending. */
    bool                    fSvcPending;

    /** The x86 mapping for the privileged DRAM region where the SEV app state is saved. */
    PSPX86MEMCACHEDMAPPING  X86MappingPrivState;
    /** Size of the state region. */
    uint32_t                cbStateRegion;
    /** Cached temporary x86 mappings. */
    PSPX86MEMCACHEDMAPPING  aX86Mappings[8];
} PSPCOREINT;


/**
 * PSP Core register name to unicorn mapping.
 */
static const int g_aUcRegs[] =
{
    0,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_SP,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_CPSR,
    UC_ARM_REG_SPSR
};


/**
 * Human readable error strings for unicorn status codes.
 */
static const char *g_apszUcErr[] =
{
    "UC_ERR_OK",
    "UC_ERR_NOMEM",
    "UC_ERR_ARCH",
    "UC_ERR_HANDLE",
    "UC_ERR_MODE",
    "UC_ERR_VERSION",
    "UC_ERR_READ_UNMAPPED",
    "UC_ERR_WRITE_UNMAPPED",
    "UC_ERR_FETCH_UNMAPPED",
    "UC_ERR_HOOK",
    "UC_ERR_INSN_INVALID",
    "UC_ERR_MAP",
    "UC_ERR_WRITE_PROT",
    "UC_ERR_READ_PROT",
    "UC_ERR_FETCH_PROT",
    "UC_ERR_ARG",
    "UC_ERR_READ_UNALIGNED",
    "UC_ERR_WRITE_UNALIGNED",
    "UC_ERR_FETCH_UNALIGNED",
    "UC_ERR_HOOK_EXIST",
    "UC_ERR_RESOURCE",
    "UC_ERR_EXCEPTION",
    "UC_ERR_TIMEOUT"
};


/**
 * Converts the PSP core register enum to the unicorn equivalent.
 *
 * @returns Unicorn register number.
 * @param   enmReg                  The register.
 */
static int pspEmuCoreReg2Uc(PSPCOREREG enmReg)
{
    return g_aUcRegs[enmReg];
}


/**
 * Converts a unicorn error to a general status code.
 *
 * @returns Status code.
 * @param   rcUc                    The unicorn status code to convert.
 */
static int pspEmuCoreErrConvertFromUcErr(uc_err rcUc)
{
    if (rcUc == UC_ERR_OK)
        return 0;

    printf("rcUc=%u (%s)\n", rcUc, rcUc < ELEMENTS(g_apszUcErr) ? g_apszUcErr[rcUc] : "<UNKNOWN>");
    return -1; /** @todo */
}


/**
 * The trace hook wrapper called by unicorn.
 *
 * @returns nothing.
 * @param   pUcEngine               The unicorn engine pointer.
 * @param   uAddr                   The address of the instruction triggering the hook.
 * @param   cbInsn                  Size of the instruction.
 * @param   pvUser                  Opaque user data.
 */
static void pspEmuCoreUcHookWrapper(uc_engine *pUcEngine, uint64_t uAddr, uint32_t cbInsn, void *pvUser)
{
    PCPSPCORETRACEHOOK pHook = (PCPSPCORETRACEHOOK)pvUser;

    pHook->pfnTrace(pHook->pPspCore, (PSPADDR)uAddr, cbInsn, pHook->pvUser);
}


/**
 * The memory trace hook wrapper called by unicorn.
 *
 * @returns nothing.
 * @param   pUcEngine               The unicorn engine pointer.
 * @param   uMemType                Memory type.
 * @param   uAddr                   The address of the instruction triggering the hook.
 * @param   cb                      Size of the memory access.
 * @param   i64Val                  Value written during a write, ignored for a read.
 * @param   pvUser                  Opaque user data.
 */
static void pspEmuCoreUcHookMemWrapper(uc_engine *pUcEngine, uc_mem_type uMemType, uint64_t uAddr, int32_t cb, int64_t i64Val, void *pvUser)
{
    PCPSPCORETRACEHOOK pHook = (PCPSPCORETRACEHOOK)pvUser;

    pHook->pfnTrace(pHook->pPspCore, (PSPADDR)uAddr, cb, pHook->pvUser);
}


/**
 * Unicorn MMIO read wrapper.
 *
 * @returns Data read.
 * @param   pUcEngine               The unicorn engine pointer.
 * @param   pvUser                  Opaque user data.
 * @param   uAddr                   MMIO address read.
 * @param   cbInsn                  Size of the read (1, 2, 4 or 8 bytes).
 */
static uint64_t pspEmuCoreMmioRead(struct uc_struct* pUcEngine, void *pvUser, uint64_t uAddr, unsigned cb)
{
    PCPSPCOREMMIOREGION pRegion = (PCPSPCOREMMIOREGION)pvUser;
    PSPDATUM ValRead;
    uint64_t uValRet = 0;

    pRegion->pfnRead(pRegion->pPspCore, (PSPADDR)uAddr, cb, &ValRead, pRegion->pvUser);
    switch (cb)
    {
        case 1:
            uValRet = ValRead.u8;
            break;
        case 2:
            uValRet = ValRead.u16;
            break;
        case 4:
            uValRet = ValRead.u32;
            break;
        case 8:
            uValRet = ValRead.u64;
            break;
        default:
            /** @todo assert() */
            uc_emu_stop(pUcEngine);
    }

    return uValRet;
}


/**
 * Unicorn MMIO write wrapper.
 *
 * @returns nothing.
 * @param   pUcEngine               The unicorn engine pointer.
 * @param   pvUser                  Opaque user data.
 * @param   uAddr                   MMIO address written.
 * @param   uVal                    Value written.
 * @param   cbInsn                  Size of the write (1, 2, 4 or 8 bytes).
 */
static void pspEmuCoreMmioWrite(struct uc_struct* pUcEngine, void *pvUser, uint64_t uAddr, uint64_t uVal, unsigned cb)
{
    PCPSPCOREMMIOREGION pRegion = (PCPSPCOREMMIOREGION)pvUser;
    PSPDATUM ValWrite;

    switch (cb)
    {
        case 1:
            ValWrite.u8 = (uint8_t)uVal;
            break;
        case 2:
            ValWrite.u16 = (uint16_t)uVal;
            break;
        case 4:
            ValWrite.u32 = (uint32_t)uVal;
            break;
        case 8:
            ValWrite.u64 = uVal;
            break;
        default:
            /** @todo assert() */
            uc_emu_stop(pUcEngine);
    }
    pRegion->pfnWrite(pRegion->pPspCore, (PSPADDR)uAddr, cb, &ValWrite, pRegion->pvUser);
}


/**
 * The SVC instruction wrapper to transition back to supervisor mode.
 *
 * @returns nothing.
 * @param   pUcEngine           Pointer to the unicorn engine instance.
 * @param   uIntNo              Interrupt/Exception number, should be always 2.
 * @param   pvUser              Opaque user data passed when adding the hook.
 */
static void pspEmuCoreSvcWrapper(uc_engine *pUcEngine, uint32_t uIntNo, void *pvUser)
{
    PPSPCOREINT pThis = (PPSPCOREINT)pvUser;

    /*
     * Set SVC pending flag and stop emulation, we don't alter the vital CPU state
     * (PC, CPSR, etc.) here as unicorn seems to be rather fragile in this regard
     * when done from any hook callback.
     */
    pThis->fSvcPending = true;
    uc_emu_stop(pUcEngine);
}


int PSPEmuCoreCreate(PPSPCORE phCore, PSPCOREMODE enmMode)
{
    int rc = 0;
    PPSPCOREINT pThis = (PPSPCOREINT)calloc(1, sizeof(*pThis));

    if (pThis)
    {
        uc_err err;

        pThis->pTraceHooksHead  = NULL;
        pThis->pMmioRegionsHead = NULL;
        pThis->enmMode          = enmMode;
        pThis->cbSram           = _256K;
        pThis->pvSram           = calloc(1, pThis->cbSram);
        pThis->fSvcPending      = false;
        if (pThis->pvSram)
        {
            /* Initialize unicorn engine in ARM mode. */
            err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &pThis->pUcEngine);
            if (!err)
            {
                if (!rc)
                {
                    uc_mem_map_ptr(pThis->pUcEngine, 0x0, pThis->cbSram, UC_PROT_ALL, pThis->pvSram);

                     /** @todo The stack memory, do this more elegantly. The PSP sets up page tables
                      * but unicorn somehow ignores them so we have to make the stack available here for now
                      * with an explicit mapping.
                      */
                    uc_mem_map(pThis->pUcEngine, 0x50000, 2 * _4K, UC_PROT_READ | UC_PROT_WRITE);
                    uc_mem_map(pThis->pUcEngine, 0x60000, 2 * _4K, UC_PROT_READ | UC_PROT_WRITE);

                    err = uc_hook_add(pThis->pUcEngine, &pThis->pUcHookSvc, UC_HOOK_INTR, (void *)(uintptr_t)pspEmuCoreSvcWrapper, pThis, 1, 0);
                    if (!err)
                    {
                        *phCore = pThis;
                        return 0;
                    }
                }

                uc_close(pThis->pUcEngine);
            }
            else
            {
                printf("not ok - Failed on uc_open() with error: %s\n", uc_strerror(err));
                rc = -1;
            }

            free(pThis->pvSram);
        }
        else
            rc = -1;

        free(pThis);
    }
    else
        rc = -1;

    return rc;
}

void PSPEmuCoreDestroy(PSPCORE hCore)
{
    PPSPCOREINT pThis = hCore;

    uc_close(pThis->pUcEngine);
    free(pThis->pvSram);
    free(pThis);
}

int PSPEmuCoreCcdSet(PSPCORE hCore, uint32_t idCcd)
{
    PPSPCOREINT pThis = hCore;

    pThis->idCcd = idCcd;
    return 0;
}

int PSPEmuCoreQueryCcd(PSPCORE hCore, uint32_t *pidCcd)
{
    PPSPCOREINT pThis = hCore;

    *pidCcd = pThis->idCcd;
    return 0;
}

int PSPEmuCoreMemWrite(PSPCORE hCore, PSPADDR AddrPspWrite, const void *pvData, size_t cbData)
{
    PPSPCOREINT pThis = hCore;

    uc_err rcUc = uc_mem_write(pThis->pUcEngine, AddrPspWrite, pvData, cbData);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreMemRead(PSPCORE hCore, PSPADDR AddrPspRead, void *pvDst, size_t cbDst)
{
    PPSPCOREINT pThis = hCore;

    uc_err rcUc = uc_mem_read(pThis->pUcEngine, AddrPspRead, pvDst, cbDst);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreMemAddRegion(PSPCORE hCore, PSPADDR AddrStart, size_t cbRegion)
{
    return -1; /** @todo */
}

int PSPEmuCoreSetOnChipBl(PSPCORE hCore, void *pvOnChipBl, size_t cbOnChipBl)
{
    PPSPCOREINT pThis = hCore;

    uc_err rcUc = uc_mem_map_ptr(pThis->pUcEngine, 0xffff0000, cbOnChipBl, UC_PROT_READ | UC_PROT_EXEC, pvOnChipBl);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreSetReg(PSPCORE hCore, PSPCOREREG enmReg, uint32_t uVal)
{
    PPSPCOREINT pThis = hCore;

    uint64_t uTmp = uVal;
    uc_err rcUc = uc_reg_write(pThis->pUcEngine, pspEmuCoreReg2Uc(enmReg), &uTmp);
    if (   rcUc == UC_ERR_OK
        && enmReg == PSPCOREREG_PC)
    {
        /* Set the next address to execute to the written value. */
        pThis->PspAddrExecNext = (PSPADDR)uVal;
    }
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreQueryReg(PSPCORE hCore, PSPCOREREG enmReg, uint32_t *puVal)
{
    PPSPCOREINT pThis = hCore;

    uint64_t uTmp;
    uc_err rcUc = uc_reg_read(pThis->pUcEngine, pspEmuCoreReg2Uc(enmReg), &uTmp);
    *puVal = (uint32_t)uTmp;
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreExecSetStartAddr(PSPCORE hCore, PSPADDR AddrExecStart)
{
    PPSPCOREINT pThis = hCore;

    pThis->PspAddrExecNext = AddrExecStart;
    uint64_t uTmp = AddrExecStart;
    uc_err rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_PC, &uTmp);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreExecRun(PSPCORE hCore, uint32_t cInsnExec, uint32_t msExec)
{
    PPSPCOREINT pThis = hCore;

    int rc = 0;

    if (!cInsnExec)
        cInsnExec = UINT32_MAX;
    if (!msExec) /** @todo: Proper timekeeping for the loop. */
        msExec = UINT32_MAX;

    while (!rc && cInsnExec && msExec)
    {
        uc_err rcUc = uc_emu_start(pThis->pUcEngine, pThis->PspAddrExecNext, 0xffffffff, msExec, cInsnExec);
        if (rcUc == UC_ERR_OK)
        {
            cInsnExec--; /* Executed at least one instruction. */

            /* Query the PC. */
            uint32_t uPc = 0;
            uc_err rcUc2 = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_PC, &uPc);
            if (rcUc2 == UC_ERR_OK)
            {
                if (pThis->fSvcPending)
                {
                    /* Set new PC (assuming the exception table starting at 0x100 here), LR, CPSR and SPSR. */
                    uint32_t uCpsrOld;
                    uc_err rcUc2 = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_CPSR, &uCpsrOld);

                    uint16_t uInsnSvc;
                    uc_mem_read(pThis->pUcEngine, uPc - 2, &uInsnSvc, sizeof(uint16_t));
                    if (((uInsnSvc >> 8) & 0xff) == 0xdf)
                    {
                        uint32_t idxSyscall = uInsnSvc & 0xff;
                        printf("SYSCALL %#x pending\n", idxSyscall);
                    }

                    /* Set supervisor mode. */
                    uint32_t uCpsr = (uCpsrOld & ~0xf) | 0x3; /** @todo Proper defines! */
                    if (rcUc2 == UC_ERR_OK)
                        rcUc2 = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_CPSR, &uCpsr);
                    if (rcUc2 == UC_ERR_OK)
                        rcUc2 = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_SPSR, &uCpsrOld); /* Save CPSR into SPSR after switching modes. */
                    if (rcUc2 == UC_ERR_OK)
                        rcUc2 = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_LR, &uPc); /* PC is advanced already. */

                    /** @todo Determine base of exception table from VBAR register. */
                    uPc = 0x100 + 2 * sizeof(uint32_t); /* Switches to ARM mode. */
                    if (rcUc2 == UC_ERR_OK)
                        rcUc2 = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_PC, &uPc);
                    if (rcUc2 == UC_ERR_OK)
                        pThis->PspAddrExecNext = (PSPADDR)uPc;

                    pThis->fSvcPending = false;
                    if (rcUc2 != UC_ERR_OK)
                        rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
                }
                else
                {
                    /* Query the mode to execute and set the next address to execute. */
                    size_t ucCpuMode = 0;

                    /*
                     * Unicorn doesn't use the CPSR Thumb state bit but switches to the instruction set
                     * based on bit 0 of the address (like for a blx instruction for instance).
                     */
                    uc_err rcUc2 = uc_query(pThis->pUcEngine, UC_QUERY_MODE, &ucCpuMode);
                    if (rcUc2 == UC_ERR_OK)
                    {
                        uPc |= ucCpuMode == UC_MODE_THUMB ? 1 : 0;
                        pThis->PspAddrExecNext = (PSPADDR)uPc;
                    }
                    else
                        rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
                }
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
        }
        else
            rc = pspEmuCoreErrConvertFromUcErr(rcUc);
    }

    return rc;
}

int PSPEmuCoreExecStop(PSPCORE hCore)
{
    PPSPCOREINT pThis = hCore;

    int rcUc = uc_emu_stop(pThis->pUcEngine);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreTraceRegister(PSPCORE hCore, PSPADDR uPspAddrStart, PSPADDR uPspAddrEnd,
                            uint32_t fFlags, PFNPSPCORETRACE pfnTrace, void *pvUser)
{
    PPSPCOREINT pThis = hCore;
    int rc = 0;

    /* Exec and memory read/write hooks can't be mixed. */
    if (   (fFlags & PSPEMU_CORE_TRACE_F_EXEC)
        && (   (fFlags & PSPEMU_CORE_TRACE_F_READ)
            || (fFlags & PSPEMU_CORE_TRACE_F_WRITE)))
        return -1;

    /* Try to register a new hook. */
    PPSPCORETRACEHOOK pHook = (PPSPCORETRACEHOOK)calloc(1, sizeof(*pHook));
    if (pHook)
    {
        pHook->PspAddrStart = uPspAddrStart;
        pHook->PspAddrEnd   = uPspAddrEnd;
        pHook->pPspCore     = pThis;
        pHook->pfnTrace     = pfnTrace;
        pHook->pvUser       = pvUser;

        uc_hook_type fHook = fFlags & PSPEMU_CORE_TRACE_F_EXEC ? UC_HOOK_CODE : 0;
        void *pfnHook = (void *)(uintptr_t)pspEmuCoreUcHookWrapper;
        if (fFlags & PSPEMU_CORE_TRACE_F_READ)
        {
            pfnHook = (void *)(uintptr_t)pspEmuCoreUcHookMemWrapper;
            fHook |= UC_HOOK_MEM_READ;
        }
        if (fFlags & PSPEMU_CORE_TRACE_F_WRITE)
        {
            pfnHook = (void *)(uintptr_t)pspEmuCoreUcHookMemWrapper;
            fHook |= UC_HOOK_MEM_WRITE;
        }

        uc_err rcUc = uc_hook_add(pThis->pUcEngine, &pHook->hUcHook, fHook,
                                  pfnHook, pHook, uPspAddrStart, uPspAddrEnd);
        rc = pspEmuCoreErrConvertFromUcErr(rcUc);
        if (!rc)
        {
            pHook->pNext = pThis->pTraceHooksHead;
            pThis->pTraceHooksHead = pHook;
        }
        else
            free(pHook);
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuCoreTraceDeregister(PSPCORE hCore, PSPADDR uPspAddrStart, PSPADDR uPspAddrEnd)
{
    PPSPCOREINT pThis = hCore;
    int rc = 0;

    /* Search for the right hook and deregister. */
    PPSPCORETRACEHOOK pPrev = NULL;
    PPSPCORETRACEHOOK pCur = pThis->pTraceHooksHead;
    while (   pCur
           && (   pCur->PspAddrStart != uPspAddrStart
               || pCur->PspAddrEnd != uPspAddrEnd))
    {
        pPrev = pCur;
        pCur = pCur->pNext;
    }

    if (pCur)
    {
        if (pPrev)
            pPrev->pNext = pCur->pNext;
        else
            pThis->pTraceHooksHead = pCur->pNext;

        uc_err rcUc = uc_hook_del(pThis->pUcEngine, pCur->hUcHook);
        /** @todo assert(rcUc == UC_ERR_OK) */
        free(pCur);
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuCoreMmioRegister(PSPCORE hCore, PSPADDR uPspAddrMmioStart, size_t cbMmio,
                           PFNPSPCOREMMIOREAD pfnRead, PFNPSPCOREMMIOWRITE pfnWrite,
                           void *pvUser)
{
    PPSPCOREINT pThis = hCore;
    int rc = 0;

    /* Try to register a new hook. */
    PPSPCOREMMIOREGION pRegion = (PPSPCOREMMIOREGION)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->PspAddrStart = uPspAddrMmioStart;
        pRegion->cbMmio       = cbMmio;
        pRegion->pPspCore     = pThis;
        pRegion->pfnRead      = pfnRead;
        pRegion->pfnWrite     = pfnWrite;
        pRegion->pvUser       = pvUser;

        uc_err rcUc = uc_mmio_map(pThis->pUcEngine, uPspAddrMmioStart, cbMmio,
                                  pspEmuCoreMmioRead, pspEmuCoreMmioWrite, pRegion);
        rc = pspEmuCoreErrConvertFromUcErr(rcUc);
        if (!rc)
        {
            pRegion->pNext = pThis->pMmioRegionsHead;
            pThis->pMmioRegionsHead = pRegion;
        }
        else
            free(pRegion);
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuCoreMmioDeregister(PSPCORE hCore, PSPADDR uPspAddrMmioStart, size_t cbMmio)
{
    PPSPCOREINT pThis = hCore;
    int rc = 0;

    /* Search for the right hook and deregister. */
    PPSPCOREMMIOREGION pPrev = NULL;
    PPSPCOREMMIOREGION pCur = pThis->pMmioRegionsHead;
    while (   pCur
           && (   pCur->PspAddrStart != uPspAddrMmioStart
               || pCur->cbMmio != cbMmio))
    {
        pPrev = pCur;
        pCur = pCur->pNext;
    }

    if (pCur)
    {
        if (pPrev)
            pPrev->pNext = pCur->pNext;
        else
            pThis->pMmioRegionsHead = pCur->pNext;

        uc_err rcUc = uc_mem_unmap(pThis->pUcEngine, uPspAddrMmioStart, cbMmio);
        /** @todo assert(rcUc == UC_ERR_OK) */
        free(pCur);
    }
    else
        rc = -1;

    return rc;
}

void PSPEmuCoreStateDump(PSPCORE hCore)
{
    PPSPCOREINT pThis = hCore;

    PSPCOREREG enmReg = PSPCOREREG_R0;
    uint32_t au32Reg[PSPCOREREG_SPSR + 1];

    while (enmReg <= PSPCOREREG_SPSR)
    {
        PSPEmuCoreQueryReg(hCore, enmReg, &au32Reg[enmReg]);
        enmReg++;
    }

    printf( "R0  > 0x%08x | R1  > 0x%08x | R2 > 0x%08x | R3 > 0x%08x\n"
            "R4  > 0x%08x | R5  > 0x%08x | R6 > 0x%08x | R7 > 0x%08x\n"
            "R8  > 0x%08x | R9  > 0x%08x | R10> 0x%08x | R11> 0x%08x\n"
            "R12 > 0x%08x | SP  > 0x%08x | LR > 0x%08x | PC > 0x%08x\n"
            "CPSR> 0x%08x | SPSR> 0x%08x\n",
            au32Reg[PSPCOREREG_R0],   au32Reg[PSPCOREREG_R1], au32Reg[PSPCOREREG_R2],  au32Reg[PSPCOREREG_R3],
            au32Reg[PSPCOREREG_R4],   au32Reg[PSPCOREREG_R5], au32Reg[PSPCOREREG_R6],  au32Reg[PSPCOREREG_R7],
            au32Reg[PSPCOREREG_R8],   au32Reg[PSPCOREREG_R9], au32Reg[PSPCOREREG_R10], au32Reg[PSPCOREREG_R11],
            au32Reg[PSPCOREREG_R12],  au32Reg[PSPCOREREG_SP], au32Reg[PSPCOREREG_LR],  au32Reg[PSPCOREREG_PC],
            au32Reg[PSPCOREREG_CPSR], au32Reg[PSPCOREREG_SPSR]);

    /* Dump a few instructions. */
    uint8_t abInsn[5 * sizeof(uint32_t)];
    char achBuf[_1K];
    int rc = PSPEmuCoreMemRead(hCore, au32Reg[PSPCOREREG_PC], &abInsn[0], sizeof(abInsn));
    if (!rc)
    {
        size_t ucCpuMode = 0;

        uc_err rcUc = uc_query(pThis->pUcEngine, UC_QUERY_MODE, &ucCpuMode);
        if (rcUc == UC_ERR_OK)
        {
            rc = PSPEmuDisasm(&achBuf[0], sizeof(achBuf), &abInsn[0], sizeof(abInsn), au32Reg[PSPCOREREG_PC], ucCpuMode == UC_MODE_THUMB ? true : false);
            if (!rc)
                printf("Disasm:\n"
                       "%s", &achBuf[0]);
        }
        else
            fprintf(stderr, "Querying CPU mode failed with %d\n", pspEmuCoreErrConvertFromUcErr(rcUc));
    }
}
