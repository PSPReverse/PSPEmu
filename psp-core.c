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
    /** The unicorn engine pointer. */
    uc_engine               *pUcEngine;
    /** The initial CPU context state used for resetting. */
    uc_context              *pUcCtxReset;
    /** The svc interrupt hook. */
    uc_hook                 pUcHookSvc;
    /** The SRAM region. */
    void                    *pvSram;
    /** Size of the SRAM region. */
    size_t                  cbSram;
    /** The next address to execute instructions from. */
    PSPADDR                 PspAddrExecNext;
    /** Flag whether the exeuction should stop. */
    bool                    fExecStop;

    /** Head of registered trace hooks. */
    PPSPCORETRACEHOOK       pTraceHooksHead;
    /** Head of MMIO regions. */
    PPSPCOREMMIOREGION      pMmioRegionsHead;

    /** The WFI reached callback if set. */
    PFNPSPCOREWFI           pfnWfiReached;
    /** Opaque user data to pass to the WFI reached callback. */
    void                    *pvWfiUser;

    /** The SVC injection registartion record set, NULL if no overrides exist. */
    PCPSPCORESVCREG         pSvcReg;
    /** Opaque user data to pass to the SVC handlers. */
    void                    *pvSvcUser;
    /** The currently syscall number being executed. */
    uint32_t                idxSvc;
    /** Flag whether an SVC call is pending. */
    bool                    fSvcPending;
    /** The hook for the after SVC breakpoint. */
    uc_hook                 hUcHookSvcAfter;
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
 * The register set during a batch query for the state dump method.
 */
static const PSPCOREREG g_aenmRegQueryBatch[] =
{
    PSPCOREREG_R0,
    PSPCOREREG_R1,
    PSPCOREREG_R2,
    PSPCOREREG_R3,
    PSPCOREREG_R4,
    PSPCOREREG_R5,
    PSPCOREREG_R6,
    PSPCOREREG_R7,
    PSPCOREREG_R8,
    PSPCOREREG_R9,
    PSPCOREREG_R10,
    PSPCOREREG_R11,
    PSPCOREREG_R12,
    PSPCOREREG_SP,
    PSPCOREREG_LR,
    PSPCOREREG_PC,
    PSPCOREREG_CPSR,
    PSPCOREREG_SPSR
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


/**
 * Execute any injected SVC handlers before possibly passing control to the supervisor code.
 *
 * @returns Status code.
 * @param   pThis               The PSP emulation code instance.
 * @param   PspAddrSvc          Address of the instruction coming after the SVC instruction.
 * @param   fThumb              Flag whether the core is currently executing in thumb mode.
 * @param   pfSwitchToSvc       Where to store the flag whether to switch to supervisor mode after all
 *                              handlers where executed.
 */
static int pspEmuCoreSvcBefore(PPSPCOREINT pThis, PSPADDR PspAddrPc, bool fThumb, bool *pfSwitchToSvc)
{
    int rc = 0;
    bool fHandled = false; /* Default is to switch to supervisor mode in case there is nothing injected. */

    if (pThis->pSvcReg)
    {
        uint32_t idxSyscall = 0;

        if (fThumb)
        {
            uint16_t uInsnSvc;
            uc_err rcUc = uc_mem_read(pThis->pUcEngine, PspAddrPc - 2, &uInsnSvc, sizeof(uInsnSvc));
            if (rcUc == UC_ERR_OK)
            {
                if (((uInsnSvc >> 8) & 0xff) == 0xdf)
                    idxSyscall = uInsnSvc & 0xff;
                else
                    rc = -1; /* Should never happen. */
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc);
        }
        else
        {
            uint32_t uInsnSvc;
            uc_err rcUc = uc_mem_read(pThis->pUcEngine, PspAddrPc - 4, &uInsnSvc, sizeof(uInsnSvc));
            if (rcUc == UC_ERR_OK)
            {
                if (((uInsnSvc >> 24) & 0x0f) == 0xf)
                    idxSyscall = uInsnSvc & 0xffffff;
                else
                    rc = -1; /* Should never happen. */
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc);
        }

        if (!rc)
        {
            pThis->idxSvc = idxSyscall;

            /* Any global handlers?. */
            if (   pThis->pSvcReg->GlobalSvc.pfnSvcHnd
                && pThis->pSvcReg->GlobalSvc.fFlags & PSPEMU_CORE_SVC_F_BEFORE)
                fHandled = pThis->pSvcReg->GlobalSvc.pfnSvcHnd(pThis, idxSyscall, PSPEMU_CORE_SVC_F_BEFORE, pThis->pvSvcUser);

            /* Any per SVC handler set?. */
            if (idxSyscall < pThis->pSvcReg->cSvcDescs)
            {
                PCPSPCORESVCDESC pSvcDesc = &pThis->pSvcReg->paSvcDescs[idxSyscall];
                if (   pSvcDesc->pfnSvcHnd
                    && pSvcDesc->fFlags & PSPEMU_CORE_SVC_F_BEFORE)
                    fHandled = pSvcDesc->pfnSvcHnd(pThis, idxSyscall, PSPEMU_CORE_SVC_F_BEFORE, pThis->pvSvcUser);
            }
        }
    }

    *pfSwitchToSvc = fHandled ? false : true;

    return rc;
}


/**
 * Execute any injected SVC handlers after control was passed to the supervisor code and control is about to
 * return to the code invoking the SVC.
 *
 * @returns Status code.
 * @param   pThis               The PSP emulation code instance.
 */
static int pspEmuCoreSvcAfter(PPSPCOREINT pThis)
{
    int rc = 0;

    if (pThis->pSvcReg)
    {
        /* Any global handlers?. */
        if (   pThis->pSvcReg->GlobalSvc.pfnSvcHnd
            && pThis->pSvcReg->GlobalSvc.fFlags & PSPEMU_CORE_SVC_F_AFTER)
            pThis->pSvcReg->GlobalSvc.pfnSvcHnd(pThis, pThis->idxSvc, PSPEMU_CORE_SVC_F_AFTER, pThis->pvSvcUser);

        /* Any per SVC handler set?. */
        if (pThis->idxSvc < pThis->pSvcReg->cSvcDescs)
        {
            PCPSPCORESVCDESC pSvcDesc = &pThis->pSvcReg->paSvcDescs[pThis->idxSvc];
            if (   pSvcDesc->pfnSvcHnd
                && pSvcDesc->fFlags & PSPEMU_CORE_SVC_F_AFTER)
                pSvcDesc->pfnSvcHnd(pThis, pThis->idxSvc, PSPEMU_CORE_SVC_F_AFTER, pThis->pvSvcUser);
        }
    }

    return rc;
}


/**
 * The after SVC trace hook called by unicorn.
 *
 * @returns nothing.
 * @param   pUcEngine               The unicorn engine pointer.
 * @param   uAddr                   The address of the instruction triggering the hook.
 * @param   cbInsn                  Size of the instruction.
 * @param   pvUser                  Opaque user data.
 */
static void pspEmuCoreSvcAfterHook(uc_engine *pUcEngine, uint64_t uAddr, uint32_t cbInsn, void *pvUser)
{
    PPSPCOREINT pThis = (PPSPCOREINT)pvUser;

    pspEmuCoreSvcAfter(pThis); /* Handle all after hooks. */

    /* Delete the temporary unicorn hook. */
    uc_err rcUc = uc_hook_del(pThis->pUcEngine, pThis->hUcHookSvcAfter);
    /** @todo assert(rcUc == UC_ERR_OK) */
    pThis->hUcHookSvcAfter = 0;
}


/**
 * Checks whether the instruction before the given address is a WFI instruction.
 *
 * @returns Flag whether a WFI instruction was detected.
 * @param   pThis               The PSP emulation core instance.
 * @param   PspAddrPc           The PC following the potential WFI instruction.
 * @param   fThumb              Flag whether we are in thumb state.
 */
static bool pspEmuCoreInsnIsWfi(PPSPCOREINT pThis, PSPADDR PspAddrPc, bool fThumb)
{
    if (PspAddrPc <= pThis->cbSram)
    {
        if (fThumb)
        {
            uint16_t u16Insn = 0;
            uc_err rcUc = uc_mem_read(pThis->pUcEngine, PspAddrPc - 2, &u16Insn, sizeof(u16Insn));
            if (   rcUc = UC_ERR_OK
                && u16Insn == 0xbf30)
                return true;
        }
        else
        {
            uint32_t u32Insn = 0;
            uc_err rcUc = uc_mem_read(pThis->pUcEngine, PspAddrPc - 4, &u32Insn, sizeof(u32Insn));
            if (   rcUc = UC_ERR_OK
                && (u32Insn & 0x0fffffff) == 0x0320f003)
                return true;
        }
    }

    return false;
}


/**
 * Injects a new exception for execution.
 *
 * @returns Status code.
 * @param   pThis               The PSP emulation core instance.
 * @param   uMode               New processor mode to switch to.
 * @param   idxExcpVecTbl       Index in the exception vector table to jump to.
 * @param   PspAddrPcOld        The PC value when the exception was raised.
 */
static int pspEmuCoreExcpInject(PPSPCOREINT pThis, uint32_t uMode, uint32_t idxExcpVecTbl, PSPADDR PspAddrPcOld)
{
    uint32_t uCpsrOld = 0;

    uc_err rcUc = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_CPSR, &uCpsrOld);

    /* Set new mode. */
    uint32_t uCpsr = (uCpsrOld & ~0xf) | uMode;
    if (rcUc == UC_ERR_OK)
        rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_CPSR, &uCpsr);
    if (rcUc == UC_ERR_OK)
        rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_SPSR, &uCpsrOld); /* Save CPSR into SPSR after switching modes. */
    if (rcUc == UC_ERR_OK)
        rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_LR, &PspAddrPcOld); /* PC is advanced already. */

    uint32_t u32VBar = 0;
    rcUc = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_VBAR, &u32VBar);
    PSPADDR PspAddrPc = u32VBar + idxExcpVecTbl * sizeof(uint32_t); /* Switches to ARM mode. */

    if (rcUc == UC_ERR_OK)
        rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_PC, &PspAddrPc);
    if (rcUc == UC_ERR_OK)
        pThis->PspAddrExecNext = PspAddrPc;

    return pspEmuCoreErrConvertFromUcErr(rcUc);
}


/**
 * Single steps through the instructions until the pending interrupt source is enabled.
 *
 * @returns Status code.
 * @param   pThis               The PSP emulation core instance.
 * @param   fFirq               Flag whether an FIRQ is pending.
 * @param   fIrq                Flag whether an IRQ is pending.
 *
 * @note This is a very limited version of our runloop which expects that there is nothing fancy going
 *       on between exiting the WFI instruction and enabling the interrupts on the core.
 */
static int pspEmuCoreExecSingleStepUntilIrqEnabled(PPSPCOREINT pThis, bool fFirq, bool fIrq)
{
    int rc = 0;

    while (   !rc
           && !pThis->fExecStop)
    {
        uc_err rcUc = uc_emu_start(pThis->pUcEngine, pThis->PspAddrExecNext, 0xffffffff, 0, 1);
        if (rcUc == UC_ERR_OK)
        {
            /* Query CPSR and check whether interrupts are enabled for a pending source. */
            PSPADDR PspAddrPc = 0;
            uint32_t uCpsrOld = 0;
            size_t   ucCpuMode = 0;

            uc_err rcUc = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_CPSR, &uCpsrOld);
            if (rcUc == UC_ERR_OK)
                rcUc = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_PC, &PspAddrPc);
            if (rcUc == UC_ERR_OK)
                rcUc = uc_query(pThis->pUcEngine, UC_QUERY_MODE, &ucCpuMode);
            if (rcUc == UC_ERR_OK)
            {
                if (   (   fFirq
                        && !(uCpsrOld & (1 << 6)))
                    || (   fIrq
                        && !(uCpsrOld & (1 << 7))))
                    break;
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc);

            /*
             * Unicorn doesn't use the CPSR Thumb state bit but switches to the instruction set
             * based on bit 0 of the address (like for a blx instruction for instance).
             */
            bool fThumb = ucCpuMode == UC_MODE_THUMB ? true : false;
            PspAddrPc |= fThumb ? 1 : 0;
            pThis->PspAddrExecNext = PspAddrPc;
        }
        else
            rc = pspEmuCoreErrConvertFromUcErr(rcUc);
    }

    return rc;
}


int PSPEmuCoreCreate(PPSPCORE phCore, size_t cbSram)
{
    int rc = 0;
    PPSPCOREINT pThis = (PPSPCOREINT)calloc(1, sizeof(*pThis));

    if (pThis)
    {
        uc_err err;

        pThis->pTraceHooksHead  = NULL;
        pThis->pMmioRegionsHead = NULL;
        pThis->cbSram           = cbSram;
        pThis->pvSram           = calloc(1, pThis->cbSram);
        pThis->pSvcReg          = NULL;
        pThis->pvSvcUser        = NULL;
        pThis->fSvcPending      = false;
        pThis->fExecStop        = false;
        pThis->hUcHookSvcAfter  = 0;
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
                      *
                      * For Zen2 the physical addresses are different so this gross hack gets even worse...
                      */
                    if (pThis->cbSram == 320 * _1K)
                    {
                        /* Phyiscal address for the SVC stack is 0x4d000 so let it point into the correct memory region. */
                        uc_mem_map_ptr(pThis->pUcEngine, 0x60000, 2 * _4K, UC_PROT_READ | UC_PROT_WRITE, (uint8_t *)pThis->pvSram + 0x4d000);
                        /* The USR mode stack for Zen2 starts at 0x70000 and covers the last two user mode region pages. */
                        uc_mem_map_ptr(pThis->pUcEngine, 0x70000, 2 * _4K, UC_PROT_READ | UC_PROT_WRITE, (uint8_t *)pThis->pvSram + 0x4b000);
                    }
                    else
                    {
                        /* The SVC mode stack for Zen1 and Zen+ starts at 0x50000. */
                        uc_mem_map_ptr(pThis->pUcEngine, 0x50000, 2 * _4K, UC_PROT_READ | UC_PROT_WRITE, (uint8_t *)pThis->pvSram + 0x3d000);
                        /* The USR mode stack for Zen1 and Zen+ starts at 0x60000 and covers the last two user mode region pages. */
                        uc_mem_map_ptr(pThis->pUcEngine, 0x60000, 2 * _4K, UC_PROT_READ | UC_PROT_WRITE, (uint8_t *)pThis->pvSram + 0x3b000);
                    }

                    err = uc_hook_add(pThis->pUcEngine, &pThis->pUcHookSvc, UC_HOOK_INTR, (void *)(uintptr_t)pspEmuCoreSvcWrapper, pThis, 1, 0);
                    if (!err)
                    {
                        /* Create the initial CPU context used for resetting later on. */
                        err = uc_context_alloc(pThis->pUcEngine, &pThis->pUcCtxReset);
                        if (!err)
                        {
                            err = uc_context_save(pThis->pUcEngine, pThis->pUcCtxReset);
                            if (!err)
                            {
                                *phCore = pThis;
                                return 0;
                            }

                            uc_free(pThis->pUcCtxReset);
                            pThis->pUcCtxReset = NULL;
                        }
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

    /* Unmap all MMIO hooks. */
    PPSPCOREMMIOREGION pMmioCur = pThis->pMmioRegionsHead;
    while (pMmioCur)
    {
        PPSPCOREMMIOREGION pFree = pMmioCur;

        pMmioCur = pMmioCur->pNext;
        uc_err rcUc = uc_mem_unmap(pThis->pUcEngine, pFree->PspAddrStart, pFree->cbMmio);
        /** @todo assert(rcUrc == UC_ERR_OK) */
        free(pFree);
    }

    /* Deregister all hooks. */
    PPSPCORETRACEHOOK pTraceCur = pThis->pTraceHooksHead;
    while (pTraceCur)
    {
        PPSPCORETRACEHOOK pFree = pTraceCur;

        pTraceCur = pTraceCur->pNext;
        uc_err rcUc = uc_hook_del(pThis->pUcEngine, pFree->hUcHook);
        /** @todo assert(rcUc == UC_ERR_OK) */
        free(pFree);
    }

    pThis->pMmioRegionsHead = NULL;
    uc_free(pThis->pUcCtxReset);
    uc_close(pThis->pUcEngine);
    free(pThis->pvSram);
    free(pThis);
}

int PSPEmuCoreMemWrite(PSPCORE hCore, PSPADDR AddrPspWrite, const void *pvData, size_t cbData)
{
    PPSPCOREINT pThis = hCore;

    /*
     * Limit the size to the end of the SRAM so we don't get any unmapped write errors right away
     * but only when we hit an unmapped region.
     *
     * @todo Get rid of uc_mem_write/uc_mem_read and do everything ourselves.
     */
    if (   AddrPspWrite < pThis->cbSram
        && AddrPspWrite + cbData > pThis->cbSram)
    {
        size_t cbThisWrite = pThis->cbSram - AddrPspWrite;
        uc_err rcUc = uc_mem_write(pThis->pUcEngine, AddrPspWrite, pvData, cbThisWrite);
        if (rcUc != UC_ERR_OK)
            return pspEmuCoreErrConvertFromUcErr(rcUc);

        AddrPspWrite += cbThisWrite;
        cbData       -= cbThisWrite;
        pvData       = (uint8_t *)pvData + cbThisWrite;
        /* Continue Below to get the error. */
    }
    uc_err rcUc = uc_mem_write(pThis->pUcEngine, AddrPspWrite, pvData, cbData);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreMemRead(PSPCORE hCore, PSPADDR AddrPspRead, void *pvDst, size_t cbDst)
{
    PPSPCOREINT pThis = hCore;

    uc_err rcUc = uc_mem_read(pThis->pUcEngine, AddrPspRead, pvDst, cbDst);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreMemRegionAdd(PSPCORE hCore, PSPADDR AddrStart, size_t cbRegion, uint32_t fProt,
                           void *pvBacking)
{
    PPSPCOREINT pThis = hCore;
    int fUcProt = 0;
    uc_err rcUc = UC_ERR_OK;

    if (fProt & PSPEMU_CORE_MEM_REGION_PROT_F_EXEC)
        fUcProt |= UC_PROT_EXEC;
    if (fProt & PSPEMU_CORE_MEM_REGION_PROT_F_READ)
        fUcProt |= UC_PROT_READ;
    if (fProt & PSPEMU_CORE_MEM_REGION_PROT_F_WRITE)
        fUcProt |= UC_PROT_WRITE;

    if (pvBacking)
        rcUc = uc_mem_map_ptr(pThis->pUcEngine, AddrStart, cbRegion, fUcProt, pvBacking);
    else
        rcUc = uc_mem_map(pThis->pUcEngine, AddrStart, cbRegion, fUcProt);

    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreMemRegionRemove(PSPCORE hCore, PSPADDR AddrStart, size_t cbRegion)
{
    PPSPCOREINT pThis = hCore;

    uc_err rcUc = uc_mem_unmap(pThis->pUcEngine, AddrStart, cbRegion);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreSvcInjectSet(PSPCORE hCore, PCPSPCORESVCREG pSvcReg, void *pvUser)
{
    PPSPCOREINT pThis = hCore;

    pThis->pSvcReg   = pSvcReg;
    pThis->pvSvcUser = pvUser;
    return 0;
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

int PSPEmuCoreQueryRegBatch(PSPCORE hCore, const PSPCOREREG *paenmReg, uint32_t cRegs, uint32_t *pauVal)
{
    PPSPCOREINT pThis = hCore;
    int aUcRegs[PSPCOREREG_LAST + 1];
    uint64_t au64Vals[PSPCOREREG_LAST + 1];
    void *apvVals[PSPCOREREG_LAST + 1];

    /* Don't support querying the same register multiple times. */
    if (cRegs > ELEMENTS(aUcRegs))
        return -1;

    for (uint32_t i = 0; i < cRegs; i++)
    {
        au64Vals[i] = 0;
        aUcRegs[i] = pspEmuCoreReg2Uc(paenmReg[i]);
        apvVals[i] = &au64Vals[i];
    }

    uc_err rcUc = uc_reg_read_batch(pThis->pUcEngine, &aUcRegs[0], &apvVals[0], cRegs);
    if (rcUc == UC_ERR_OK)
    {
        for (uint32_t i = 0; i < cRegs; i++)
            pauVal[i] = (uint32_t)au64Vals[i];
    }

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
    if (!msExec)
        msExec = 1;

    pThis->fExecStop = false;

    while (!rc && cInsnExec && msExec && !pThis->fExecStop)
    {
        uint64_t usUcExec = msExec == PSPEMU_CORE_EXEC_INDEFINITE ? 0 : (uint64_t)msExec * 1000;
        uc_err rcUc = uc_emu_start(pThis->pUcEngine, pThis->PspAddrExecNext, 0xffffffff, usUcExec, cInsnExec);
        if (rcUc == UC_ERR_OK)
        {
            cInsnExec--; /* Executed at least one instruction. */

            /* Query the PC and execution mode. */
            uint32_t uPc = 0;
            bool     fThumb = false;
            size_t   ucCpuMode = 0;
            uc_err rcUc2 = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_PC, &uPc);
            if (rcUc2 == UC_ERR_OK)
                rcUc2 = uc_query(pThis->pUcEngine, UC_QUERY_MODE, &ucCpuMode);

            fThumb = ucCpuMode == UC_MODE_THUMB ? true : false;

            if (rcUc2 == UC_ERR_OK)
            {
                if (pThis->fSvcPending)
                {
                    /* Set new PC, LR, CPSR and SPSR. */

                    /* Handle any SVC injections before passing control to any supervisor code. */
                    bool fSwitchToSvc = true;
                    if (rcUc2 == UC_ERR_OK)
                        rcUc2 = pspEmuCoreSvcBefore(pThis, uPc, fThumb, &fSwitchToSvc);
                    if (rcUc2 == UC_ERR_OK)
                    {
                        if (fSwitchToSvc) /** @todo Set temporary breakpoint to call SVC injection handlers afterwards. */
                            rc = pspEmuCoreExcpInject(pThis, 0x3, 0x2, uPc);
                        else
                        {
                            pspEmuCoreSvcAfter(pThis);

                            /* Return to the caller. */
                            uPc |= fThumb ? 1 : 0;
                            pThis->PspAddrExecNext = (PSPADDR)uPc;
                        }
                    }

                    pThis->fSvcPending = false;
                    if (rcUc2 != UC_ERR_OK)
                        rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
                }
                else if (pspEmuCoreInsnIsWfi(pThis, uPc, fThumb))
                {
                    if (pThis->pfnWfiReached)
                    {
                        bool fIrq = false;
                        bool fFirq = false;
                        rc = pThis->pfnWfiReached(pThis, uPc, &fIrq, &fFirq, pThis->pvWfiUser);
                        if (!rc)
                        {
                            uint32_t uCpsrOld = 0;
                            rcUc2 = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_CPSR, &uCpsrOld);
                            if (rcUc2 == UC_ERR_OK)
                            {
                                /*
                                 * If we have an interrupt and the corresponding source is masked
                                 * we have to single step through the code to find out when it gets enabled.
                                 */
                                if (   (   fFirq
                                        && (uCpsrOld & (1 << 6)))
                                    || (   fIrq
                                        && (uCpsrOld & (1 << 7))))
                                {
                                    uPc |= fThumb ? 1 : 0;
                                    pThis->PspAddrExecNext = (PSPADDR)uPc;

                                    rc = pspEmuCoreExecSingleStepUntilIrqEnabled(pThis, fFirq, fIrq);
                                    if (!rc)
                                    {
                                        /* Query new PC and new mode value. */
                                        uc_err rcUc2 = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_PC, &uPc);
                                        if (rcUc2 == UC_ERR_OK)
                                            rcUc2 = uc_query(pThis->pUcEngine, UC_QUERY_MODE, &ucCpuMode);

                                        fThumb = ucCpuMode == UC_MODE_THUMB ? true : false;
                                        if (rcUc2 != UC_ERR_OK)
                                            rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
                                    }
                                }

                                if (!rc)
                                {
                                    /* Continue with the appropriate exception handler. */
                                    if (fFirq)
                                        rc = pspEmuCoreExcpInject(pThis, 0x1, 0x7, uPc);
                                    else if (fIrq)
                                        rc = pspEmuCoreExcpInject(pThis, 0x2, 0x6, uPc);
                                    else
                                    {
                                        uPc |= fThumb ? 1 : 0;
                                        pThis->PspAddrExecNext = (PSPADDR)uPc;
                                    }
                                }
                            }
                            else
                                rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
                        }
                        else /* Break out of execution loop. */
                            break;
                    }
                    else
                    {
                        rc = PSPEMU_INF_CORE_INSN_WFI_REACHED;
                        break;
                    }
                }
                else
                {
                    /*
                     * Unicorn doesn't use the CPSR Thumb state bit but switches to the instruction set
                     * based on bit 0 of the address (like for a blx instruction for instance).
                     */
                    uPc |= fThumb ? 1 : 0;
                    pThis->PspAddrExecNext = (PSPADDR)uPc;
                }
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
        }
        else if (rcUc == UC_ERR_TIMEOUT)
            break;
        else
            rc = pspEmuCoreErrConvertFromUcErr(rcUc);
    }

    return rc;
}

int PSPEmuCoreExecStop(PSPCORE hCore)
{
    PPSPCOREINT pThis = hCore;

    pThis->fExecStop = true;
    int rcUc = uc_emu_stop(pThis->pUcEngine);
    return pspEmuCoreErrConvertFromUcErr(rcUc);
}

int PSPEmuCoreExecReset(PSPCORE hCore)
{
    PPSPCOREINT pThis = hCore;

    int rcUc = uc_context_restore(pThis->pUcEngine, pThis->pUcCtxReset);
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

        uc_hook_type fHook = 0;
        if (fFlags & PSPEMU_CORE_TRACE_F_EXEC)
        {
            if (fFlags & PSPEMU_CORE_TRACE_F_EXEC_BASIC_BLOCK)
                fHook = UC_HOOK_BLOCK;
            else
                fHook = UC_HOOK_CODE;
        }

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

int PSPEmuCoreWfiSet(PSPCORE hCore, PFNPSPCOREWFI pfnWfiReached, void *pvUser)
{
    PPSPCOREINT pThis = hCore;
    int rc = 0;

    /* Only allow one callback for now. */
    if (!pThis->pfnWfiReached)
    {
        pThis->pfnWfiReached = pfnWfiReached;
        pThis->pvWfiUser     = pvUser;
    }
    else
        rc = -1;

    return rc;
}

void PSPEmuCoreStateDump(PSPCORE hCore)
{
    PPSPCOREINT pThis = hCore;

    uint32_t au32Reg[ELEMENTS(g_aenmRegQueryBatch) + 1];
    int rc = PSPEmuCoreQueryRegBatch(hCore, &g_aenmRegQueryBatch[0], ELEMENTS(g_aenmRegQueryBatch), &au32Reg[1]);
    if (!rc)
    {
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

        /* Dump last 0x20 bytes of stack memory */
        uint32_t au32Stack[8];
        rc = PSPEmuCoreMemRead(hCore, au32Reg[PSPCOREREG_SP], &au32Stack[0], sizeof(au32Stack));
        if (!rc)
        {
            printf("Stack:\n"
                   "\t0x%08x: 0x%08x <= SP\n"
                   "\t0x%08x: 0x%08x\n"
                   "\t0x%08x: 0x%08x\n"
                   "\t0x%08x: 0x%08x\n"
                   "\t0x%08x: 0x%08x\n"
                   "\t0x%08x: 0x%08x\n"
                   "\t0x%08x: 0x%08x\n"
                   "\t0x%08x: 0x%08x\n",
                   au32Reg[PSPCOREREG_SP],      au32Stack[0], au32Reg[PSPCOREREG_SP] +  4, au32Stack[1],
                   au32Reg[PSPCOREREG_SP] + 8,  au32Stack[2], au32Reg[PSPCOREREG_SP] + 12, au32Stack[3],
                   au32Reg[PSPCOREREG_SP] + 16, au32Stack[4], au32Reg[PSPCOREREG_SP] + 20, au32Stack[5],
                   au32Reg[PSPCOREREG_SP] + 24, au32Stack[6], au32Reg[PSPCOREREG_SP] + 28, au32Stack[7]);
        }
    }
    else
        printf("Querying the register set failed with %d\n", rc);
}
