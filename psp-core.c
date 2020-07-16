/** @file
 * PSP Emulator - Core API (interfacing with unicorn engine).
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
#include <string.h>

#include <unicorn/unicorn.h>

#include <common/types.h>
#include <common/cdefs.h>
#include <common/status.h>

#include <psp-core.h>
#include <psp-disasm.h>
#include <psp-trace.h>

/** Page size used in the PSP firmware. */
#define PSP_PAGE_SIZE         _4K
#define PSP_PAGE_L1_IDX_SHIFT 20

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


/**
 * Currently pending exception.
 */
typedef enum PSPCOREEXCP
{
    /** Invalid pending exception. */
    PSPCOREEXCP_INVALID = 0,
    /** No exception pending currently. */
    PSPCOREEXCP_NONE,
    /** SWI exception pending. */
    PSPCOREEXCP_SWI,
    /** SMC exception pending. */
    PSPCOREEXCP_SMC,
    /** IRQ exception pending. */
    PSPCOREEXCP_IRQ,
    /** FIQ exception pending. */
    PSPCOREEXCP_FIQ,
    /** 32bit hack. */
    PSPCOREEXCP_32BIT_HACK = 0x7fffffff
} PSPCOREEXCP;


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
    /** The ASID to trigger on. */
    ARMASID                 idAsid;
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
 * A single memory (RAM/MMIO) region registration.
 */
typedef struct PSPCOREMEMREGION
{
    /** Next region in the list. */
    struct PSPCOREMEMREGION  *pNext;
    /** Start PSP address. */
    PSPADDR                  PspAddrStart;
    /** Size of the region. */
    size_t                   cbRegion;
    /** PSP core the region belongs to. */
    PPSPCOREINT              pPspCore;
    /** Flag whether this is a RAM of MMIO region. */
    bool                     fMmio;
    /** Flag whether the region is mapped directly in unicorn (for MMU disabled case). */
    bool                     fMapped;
    /** Region type dependent data. */
    union
    {
        /** MMIO region. */
        struct
        {
            /** MMIO read handler. */
            PFNPSPCOREMMIOREAD       pfnRead;
            /** MMIO write handler. */
            PFNPSPCOREMMIOWRITE      pfnWrite;
            /** Opaque user data to pass to the read/write callbacks. */
            void                     *pvUser;
        } Mmio;
        /** RAM region. */
        struct
        {
            /** The backing memory. */
            void                     *pvBacking;
            /** Protection flags assigned to this region. */
            uint32_t                 fProt;
        } Ram;
    } u;
} PSPCOREMEMREGION;
/** Pointer to a trace hook. */
typedef PSPCOREMEMREGION *PPSPCOREMEMREGION;
/** Pointer to a const trace hook. */
typedef const PSPCOREMEMREGION *PCPSPCOREMEMREGION;


/**
 * A MMU mapping.
 */
typedef struct PSPCOREMMUMAP
{
    /** Pointer to the next MMU mapping structure in the list. */
    struct PSPCOREMMUMAP            *pNext;
    /** PSP core the mapping belongs to. */
    PPSPCOREINT                     pPspCore;
    /** Virtual start address (aligned to a page). */
    PSPVADDR                        PspAddrVStart;
    /** The physical address it maps to. */
    PSPPADDR                        PspAddrPStart;
    /** Size of the region. */
    size_t                          cbRegion;
    /** Offset into the physical region the mapping starts at. */
    PSPPADDR                        offPhysMap;
    /** The physical memory region this mapping maps to. */
    PCPSPCOREMEMREGION              pMemRegion;
} PSPCOREMMUMAP;
/** Pointer to a MMU mapping structure. */
typedef PSPCOREMMUMAP *PPSPCOREMMUMAP;
/** Pointer to a const MMU mapping structure. */
typedef const PSPCOREMMUMAP *PCPSPCOREMMUMAP;


/**
 * A set of banked Co-Processor registers.
 */
typedef struct PSPCORECPBANK
{
    /** VBAR register. */
    uint32_t                u32RegVBar;
    /** MVBAR register. */
    uint32_t                u32RegMVBar;
    /** PAR register (VA to PA address translation). */
    uint32_t                u32RegPa;
    /** TTBR0 register. */
    uint32_t                u32RegTtbr0;
    /** TTBCR register. */
    uint32_t                u32RegTtbcr;
    /** SCTRL register. */
    uint32_t                u32RegSctrl;
    /** DFSR register. */
    uint32_t                u32RegDfsr;
    /** IFSR register. */
    uint32_t                u32RegIfsr;
    /** DFAR register. */
    uint32_t                u32RegDfar;
    /** IFAR register. */
    uint32_t                u32RegIfar;
    /** CONTEXTIDR register. */
    uint32_t                u32RegContextId;
    /** TPIDRURW register. */
    uint32_t                u32RegTpIdURw;
    /** TPIDRURO register. */
    uint32_t                u32RegTpIdURo;
    /** TPIDRPRW register. */
    uint32_t                u32RegTpIdPRw;
} PSPCORECPBANK;
/** Pointer to a set of banked Co-Processor registers. */
typedef PSPCORECPBANK *PPSPCORECPBANK;
/** Pointer to a const of banked Co-Processor registers. */
typedef const PSPCORECPBANK *PCPSPCORECPBANK;


/** The index denoting the register bank when in secure world. */
#define PSP_CORE_CP_BANK_IDX_SECURE     0
/** The index denoting the register bank when in non-secure world. */
#define PSP_CORE_CP_BANK_IDX_NON_SECURE 1
/** Number of register banks available. */
#define PSP_CORE_CP_BANK_COUNT          2


/**
 * Page table tracking structure.
 */
typedef struct PSPCOREPGTBLTRACK
{
    /** Pointer to the next tracking structure. */
    struct PSPCOREPGTBLTRACK    *pNext;
    /** Pointer to the owning core instance. */
    PPSPCOREINT                 pThis;
    /** Flag whether this tracks an L1 or L2 table. */
    bool                        fL2PgTbl;
    /** Unicorn hook handle to monitor writes. */
    uc_hook                     hUcHookWrites;
    /** The physical page table start address we are tracking. */
    PSPPADDR                    PhysAddrPgTblStart;
    /** Virtual address of the page tables (this is what the unicorn hook is registered with). */
    PSPVADDR                    PspAddrVPgTbl;
    /** Size of the page table we are tracking. */
    size_t                      cbPgTbl;
} PSPCOREPGTBLTRACK;
/** Pointer to a page table tracking structure. */
typedef PSPCOREPGTBLTRACK *PPSPCOREPGTBLTRACK;
/** Pointer to a const page table tracking structure. */
typedef const PSPCOREPGTBLTRACK *PCPSPCOREPGTBLTRACK;


/**
 * A single PSP core executing.
 */
typedef struct PSPCOREINT
{
    /** The unicorn engine pointer. */
    uc_engine               *pUcEngine;
    /** The initial CPU context state used for resetting. */
    uc_context              *pUcCtxReset;
    /** The interrupt hook. */
    uc_hook                 pUcHookIntr;
    /** The next address to execute instructions from. */
    PSPADDR                 PspAddrExecNext;
    /** Flag whether the exeuction should stop. */
    bool                    fExecStop;
    /** The current CPU mode. */
    PSPCOREMODE             enmCoreMode;
    /** Currently pending exception. */
    PSPCOREEXCP             enmExcpPending;
    /** The CPSR change hook. */
    uc_hook                 hUcHookCpsrChange;
    /** The current CPSR value. */
    uint32_t                u32RegCpsr;

    /** Head of registered trace hooks. */
    PPSPCORETRACEHOOK       pTraceHooksHead;
    /** Head of memory regions. */
    PPSPCOREMEMREGION       pMemRegionsHead;
    /** Lowest memory address assigned to a region (for faster lookup). */
    PSPADDR                 PspAddrMemLowest;
    /** Highest memory address assigned to a region (inclusive). */
    PSPADDR                 PspAddrMemHighest;

    /** The WFI reached callback if set. */
    PFNPSPCOREWFI           pfnWfiReached;
    /** Opaque user data to pass to the WFI reached callback. */
    void                    *pvWfiUser;

    /** The SVC injection registartion record set, NULL if no overrides exist. */
    PCPSPCORESVMCREG        pSvcReg;
    /** Opaque user data to pass to the SVC handlers. */
    void                    *pvSvcUser;
    /** The currently syscall number being executed. */
    uint32_t                idxSvc;
    /** The hook for the after SVC breakpoint. */
    uc_hook                 hUcHookSvcAfter;

    /** The SMC injection registartion record set, NULL if no overrides exist. */
    PCPSPCORESVMCREG        pSmcReg;
    /** Opaque user data to pass to the SMC handlers. */
    void                    *pvSmcUser;
    /** The current smc number being serviced. */
    uint32_t                idxSmc;

    /** CP write hook. */
    uc_hook                 hUcHookCpWrite;
    /** CP read hook. */
    uc_hook                 hUcHookCpRead;
    /** Hook for invalid memory accesses. */
    uc_hook                 hUcInvMemAcc;
    /** Flag whether the MMU is currently set up for secure world. */
    bool                    fMmuSecure;
    /** Flag whether the MMU status has changed. */
    bool                    fMmuChanged;
    /** Flag whether the MMU is currently enabled. */
    bool                    fMmuEnabled;
    /** Flag whether the IRQ line is asserted. */
    bool                    fIrq;
    /** Flag whether the FIQ line is asserted. */
    bool                    fFiq;
    /** Head of MMU mappings sorted by virtual start address. */
    PPSPCOREMMUMAP          pMmuMappingsHead;
    /** Head of page trable tracking structures to monitor writes to L1 and L2. */
    PPSPCOREPGTBLTRACK      pMmuPgTblTrackingHead;

    /** @name Co-Processor 15 related registers.
     * @{ */
    struct
    {
        /** Secure Debug Configuration register. */
        uint32_t            u32RegScr;
        /** Banked registers. */
        PSPCORECPBANK       aBankedRegs[PSP_CORE_CP_BANK_COUNT];
    } Cp15;
    /** @} */
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


static int pspEmuCoreMmuPAddrQueryFromVAddr(PPSPCOREINT pThis, PSPVADDR PspVAddr, PSPPADDR *pPspPAddr, size_t *pcbRegion,
                                            PPSPCOREPGTBLWALKSTS penmPgTblWalk);
static int pspEmuCoreMmuMappingsClear(PPSPCOREINT pThis);


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
 * Returns the name of the given core mode.
 *
 * @returns Pointer to string for human readable core mode.
 * @param   enmCoreMode             The core mode.
 */
static const char *pspEmuCoreModeToStr(PSPCOREMODE enmCoreMode)
{
    switch (enmCoreMode)
    {
        case PSPCOREMODE_USR:
            return "USR";
        case PSPCOREMODE_FIQ:
            return "FIQ";
        case PSPCOREMODE_IRQ:
            return "IRQ";
        case PSPCOREMODE_SVC:
            return "SVC";
        case PSPCOREMODE_MON:
            return "MON";
        case PSPCOREMODE_ABRT:
            return "ABRT";
        case PSPCOREMODE_UNDEF:
            return "UNDEF";
        case PSPCOREMODE_SYS:
            return "SYS";
        default:
            printf("pspEmuCoreModeToStr(): Invalid mode selected!\n");
    }

    return "<INVALID>";
}


/**
 * Returns the internal mode value from the given CPSR.
 *
 * @returns Internal mode value.
 * @param   u32Cpsr                 The CPSR to convert from.
 */
static inline PSPCOREMODE pspEmuCoreModeFromCpsr(uint32_t u32Cpsr)
{
    PSPCOREMODE enmCoreMode = PSPCOREMODE_INVALID;

    switch (u32Cpsr & 0x1f)
    {
        case 0x10:
            enmCoreMode = PSPCOREMODE_USR;
            break;
        case 0x11:
            enmCoreMode = PSPCOREMODE_FIQ;
            break;
        case 0x12:
            enmCoreMode = PSPCOREMODE_IRQ;
            break;
        case 0x13:
            enmCoreMode = PSPCOREMODE_SVC;
            break;
        case 0x16:
            enmCoreMode = PSPCOREMODE_MON;
            break;
        case 0x17:
            enmCoreMode = PSPCOREMODE_ABRT;
            break;
        case 0x1b:
            enmCoreMode = PSPCOREMODE_UNDEF;
            break;
        case 0x1f:
            enmCoreMode = PSPCOREMODE_SYS;
            break;
        default:
            printf("pspEmuCoreModeFromCpsr(): Invalid mode selected!\n");
    }

    return enmCoreMode;
}


/**
 * Returns the CPSR mode bits from the given internal core mode.
 *
 * @returns CPSR mode bits.
 * @param   enmCoreMode             THe internal core mode to convert.
 */
static inline uint32_t pspEmuCoreModeToCpsr(PSPCOREMODE enmCoreMode)
{
    uint32_t uCpsr = 0;

    switch (enmCoreMode)
    {
        case PSPCOREMODE_USR:
            uCpsr = 0x10;
            break;
        case PSPCOREMODE_FIQ:
            uCpsr = 0x11;
            break;
        case PSPCOREMODE_IRQ:
            uCpsr = 0x12;
            break;
        case PSPCOREMODE_SVC:
            uCpsr = 0x13;
            break;
        case PSPCOREMODE_MON:
            uCpsr = 0x16;
            break;
        case PSPCOREMODE_ABRT:
            uCpsr = 0x17;
            break;
        case PSPCOREMODE_UNDEF:
            uCpsr = 0x1b;
            break;
        case PSPCOREMODE_SYS:
            uCpsr = 0x1f;
            break;
        default:
            printf("pspEmuCoreModeToCpsr(): Invalid mode selected!\n");
    }

    return uCpsr;
}


/**
 * Returns flag whether the core is currently operating in the secure world.
 *
 * @returns Flag indicating whether the core is in secure world mode.
 * @param   pThis               The PSP emulation core instance.
 */
static inline bool pspEmuCoreIsSecure(PPSPCOREINT pThis)
{
    if (   pThis->Cp15.u32RegScr & 0x1
        && pThis->enmCoreMode != PSPCOREMODE_MON)
        return false;

    return true;
}


/**
 * Returns the co-processor register bank based on the current processor state.
 *
 * @returns Pointer to the co-processor register bank.
 * @param   pThis               The PSP emulation core instance.
 */
static PPSPCORECPBANK pspEmuCoreCpGetBank(PPSPCOREINT pThis)
{
    /* Monitor mode is always executed in securre world regardless of the NS bit in SCR. */
    if (!pspEmuCoreIsSecure(pThis))
        return &pThis->Cp15.aBankedRegs[PSP_CORE_CP_BANK_IDX_NON_SECURE];

    return &pThis->Cp15.aBankedRegs[PSP_CORE_CP_BANK_IDX_SECURE];
}


/**
 * Returns whether the MMU is enabled in the current world SCTRL register.
 *
 * @returns Flag whether the MMU is enabled.
 * @param   pThis               The PSP emulation core instance.
 */
static inline bool pspEmuCoreCpIsSctrlMmuEnabled(PPSPCOREINT pThis)
{
    PCPSPCORECPBANK pCpBank = pspEmuCoreCpGetBank(pThis);
    if (pCpBank->u32RegSctrl & BIT(0))
        return true;

    return false;
}


/**
 * Checks whether an interrupt is pending and injects it.
 *
 * @returns nothing.
 * @param   pThis               The PSP emulation core instance.
 * @param   PspAddrPc           The PC causing the check.
 * @param   fWait               Flag whether to wait for an interrupt (for wfi).
 */
static void pspEmuCoreIrqCheckAndInject(PPSPCOREINT pThis, PSPVADDR PspAddrPc, bool fWait)
{
    bool fIrq = pThis->fIrq;
    bool fFirq = pThis->fFiq;

    if (pThis->pfnWfiReached)
        pThis->pfnWfiReached(pThis, PspAddrPc, fWait ? 0 : PSPEMU_CORE_WFI_CHECK, &fIrq, &fFirq, pThis->pvWfiUser);

    if (pThis->fIrq || pThis->fFiq)
    {
        if (pThis->enmExcpPending != PSPCOREEXCP_NONE)
            printf("OVERWRITING another exception which should not happen!\n");
        if (fFirq && !(pThis->u32RegCpsr & BIT(6)))
            pThis->enmExcpPending = PSPCOREEXCP_FIQ;
        else if (fIrq && !(pThis->u32RegCpsr & BIT(7)))
            pThis->enmExcpPending = PSPCOREEXCP_IRQ;

        if (pThis->enmExcpPending == PSPCOREEXCP_FIQ || pThis->enmExcpPending == PSPCOREEXCP_IRQ)
        {
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE, "Injecting IRQ!\n");
            if (!fWait)
                uc_emu_stop(pThis->pUcEngine);
        }
    }
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
    PPSPCOREINT pThis = pHook->pPspCore;
    PPSPCORECPBANK pCpBank = pspEmuCoreCpGetBank(pThis);

    if (   pHook->idAsid == ARMASID_ANY
        || pHook->idAsid == pCpBank->u32RegContextId)
        pHook->pfnTrace(pThis, (PSPADDR)uAddr, cbInsn, pHook->pvUser);
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
    PPSPCOREINT pThis = pHook->pPspCore;
    PPSPCORECPBANK pCpBank = pspEmuCoreCpGetBank(pThis);

    if (   pHook->idAsid == ARMASID_ANY
        || pHook->idAsid == pCpBank->u32RegContextId)
        pHook->pfnTrace(pThis, (PSPADDR)uAddr, cb, pHook->pvUser);
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
    PCPSPCOREMEMREGION pRegion = (PCPSPCOREMEMREGION)pvUser;
    PSPDATUM ValRead;
    uint64_t uValRet = 0;

    pRegion->u.Mmio.pfnRead(pRegion->pPspCore, (PSPADDR)uAddr, cb, &ValRead, pRegion->u.Mmio.pvUser);
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

    pspEmuCoreIrqCheckAndInject(pRegion->pPspCore, (PSPVADDR)uAddr, false /*fWait*/);
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
    PCPSPCOREMEMREGION pRegion = (PCPSPCOREMEMREGION)pvUser;
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

    pRegion->u.Mmio.pfnWrite(pRegion->pPspCore, (PSPADDR)uAddr, cb, &ValWrite, pRegion->u.Mmio.pvUser);
    pspEmuCoreIrqCheckAndInject(pRegion->pPspCore, (PSPVADDR)uAddr, false /*fWait*/);
}


/**
 * The exception wrapper to transition between CPU modes.
 *
 * @returns nothing.
 * @param   pUcEngine           Pointer to the unicorn engine instance.
 * @param   uIntNo              Interrupt/Exception number.
 * @param   pvUser              Opaque user data passed when adding the hook.
 */
static void pspEmuCoreExcpWrapper(uc_engine *pUcEngine, uint32_t uIntNo, void *pvUser)
{
    PPSPCOREINT pThis = (PPSPCOREINT)pvUser;

    /*
     * Set appropriate exception and stop emulation, we don't alter the vital CPU state
     * (PC, CPSR, etc.) here as unicorn seems to be rather fragile in this regard
     * when done from any hook callback.
     */
    if (uIntNo == 2)
        pThis->enmExcpPending = PSPCOREEXCP_SWI;
    else if (uIntNo == 13)
        pThis->enmExcpPending = PSPCOREEXCP_SMC;

    uc_emu_stop(pUcEngine);
}


/**
 * The CP write wrapper to keep track of the MMU status.
 *
 * @returns nothing.
 * @param   pUcEngine           Pointer to the unicorn engine instance.
 * @param   uAddrPc             The PC causing the write.
 * @param   uCp                 Co-Processor being accessed.
 * @param   uCrn                cr<n> value.
 * @param   uCrm                cr<m> value.
 * @param   uOpc0               Opcode 0.
 * @param   uOpc1               Opcode 1.
 * @param   uOpc2               Opcode 2.
 * @param   u64Val              The value being written.
 * @param   pvUser              Opaque user data passed when adding the hook.
 */
static bool pspEmuCoreCpWriteWrapper(struct uc_struct *pUcEngine, uint64_t uAddrPc, uint32_t uCp, uint32_t uCrn, uint32_t uCrm,
                                     uint32_t uOpc0, uint32_t uOpc1, uint32_t uOpc2, uint64_t u64Val, void *pvUser)
{
    PPSPCOREINT pThis = (PPSPCOREINT)pvUser;
    PPSPCORECPBANK pCpBank = pspEmuCoreCpGetBank(pThis);

    /*
     * Check whether the MMU status changed and cause the emulation to stop so we
     * can adjust the memory layout.
     */
    bool fHandled = true;
    if (   uCp == 15
        && uCrn == 1
        && uCrm == 0
        && uOpc1 == 0
        && uOpc2 == 0)
    {
        if ((pCpBank->u32RegSctrl & BIT(0)) != (u64Val & BIT(0)))
        {
            pThis->fMmuChanged = true;
            uc_emu_stop(pUcEngine);
        }

        /* Store a copy of the SCTRL register. */
        pCpBank->u32RegSctrl = (uint32_t)u64Val;
        fHandled = false; /* To sync unicorns own copy. */
    }
    else if (   uCp == 15
             && uCrn == 2
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        pCpBank->u32RegTtbr0 = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 2
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 2)
        pCpBank->u32RegTtbcr = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 12
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        pCpBank->u32RegVBar = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 12
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 1)
        pCpBank->u32RegMVBar = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 7
             && uCrm == 4
             && uOpc1 == 0
             && uOpc2 == 0)
        pCpBank->u32RegPa = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 7
             && uCrm == 8
             && uOpc1 == 0
             && uOpc2 == 0)
    {
        /* V2PCWPR, Privileged Read VA to PA translation */
        PSPPADDR PspPAddrPg = 0;
        size_t cbRegion = 0;
        int rc = pspEmuCoreMmuPAddrQueryFromVAddr(pThis, (PSPVADDR)u64Val, &PspPAddrPg, &cbRegion, NULL /*penmPgTblWalk*/);
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE,
                                "pspEmuCoreMmuPAddrQueryFromVAddr(): VAddr=%#lx rc=%d PAddr=%#lx\n",
                                (PSPVADDR)u64Val, rc, PspPAddrPg);
        if (!rc)
            pCpBank->u32RegPa = PspPAddrPg;
        else
            pCpBank->u32RegPa = 0x1;
    }
    else if (   uCp == 15
             && uCrn == 7
             && uCrm == 8
             && uOpc1 == 0
             && uOpc2 == 2)
    {
        /* V2PCWUR, User Read VA to PA translation */
        PSPPADDR PspPAddrPg = 0;
        size_t cbRegion = 0;
        int rc = pspEmuCoreMmuPAddrQueryFromVAddr(pThis, (PSPVADDR)u64Val, &PspPAddrPg, &cbRegion, NULL /*penmPgTblWalk*/);
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE,
                                "pspEmuCoreMmuPAddrQueryFromVAddr(): VAddr=%#lx rc=%d PAddr=%#lx\n",
                                (PSPVADDR)u64Val, rc, PspPAddrPg);
        if (!rc)
            pCpBank->u32RegPa = PspPAddrPg;
        else
            pCpBank->u32RegPa = 0x1;
    }
    else if (   uCp == 15
             && uCrn == 1
             && uCrm == 1
             && uOpc1 == 0
             && uOpc2 == 0)
    {
        /* Check for a world switch and reset the MMU. */
        if (   (pThis->Cp15.u32RegScr & BIT(0)) != (u64Val & BIT(0))
            && pThis->enmCoreMode != PSPCOREMODE_MON)
        {
            pThis->fMmuChanged = true;
            uc_emu_stop(pUcEngine);
        }

        pThis->Cp15.u32RegScr = (uint32_t)u64Val;
    }
    else if (   uCp == 15
             && uCrn == 5
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        pCpBank->u32RegDfsr = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 5
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 1)
        pCpBank->u32RegIfsr = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 6
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        pCpBank->u32RegDfar = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 6
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        pCpBank->u32RegIfar = (uint32_t)u64Val;
    else if (   uCp == 15
             && uCrn == 13
             && uCrm == 0
             && uOpc1 == 0)
    {
        switch (uOpc2)
        {
            case 1:
                if (pCpBank->u32RegContextId != (uint32_t)u64Val)
                {
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE,
                                            "CO-PROC WRITE: ASID changed to %#lx\n", u64Val);
                    pspEmuCoreMmuMappingsClear(pThis);
                    fHandled = false; /* Let qemu update its internal states as well. */
                }
                pCpBank->u32RegContextId = (uint32_t)u64Val;
                break;
            case 2:
                pCpBank->u32RegTpIdURw = (uint32_t)u64Val;
                break;
            case 3:
                pCpBank->u32RegTpIdURo = (uint32_t)u64Val;
                break;
            case 4:
                pCpBank->u32RegTpIdPRw = (uint32_t)u64Val;
                break;
            default:
                fHandled = false;
                break;
        }
    }
    else
        fHandled = false;
    /** @todo TTBR0, TTBR1 and TTBCR writes should cause a stop as well. */

    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE,
                            "CO-PROC WRITE: uCp=%u uCrn=%u uCrm=%u uOpc1=%u uOpc2=%u u64Val=%#llx fHandled=%u\n",
                            uCp, uCrn, uCrm, uOpc1, uOpc2, u64Val, fHandled);
    return fHandled;
}


/**
 * The CP read wrapper to keep track of the MMU status.
 *
 * @returns nothing.
 * @param   pUcEngine           Pointer to the unicorn engine instance.
 * @param   uAddrPc             The PC causing the write.
 * @param   uCp                 Co-Processor being accessed.
 * @param   uCrn                cr<n> value.
 * @param   uCrm                cr<m> value.
 * @param   uOpc0               Opcode 0.
 * @param   uOpc1               Opcode 1.
 * @param   uOpc2               Opcode 2.
 * @param   pu64Val             Where to store the read value on success.
 * @param   pvUser              Opaque user data passed when adding the hook.
 */
static bool pspEmuCoreCpReadWrapper(struct uc_struct *pUcEngine, uint64_t uAddrPc, uint32_t uCp, uint32_t uCrn, uint32_t uCrm,
                                    uint32_t uOpc0, uint32_t uOpc1, uint32_t uOpc2, uint64_t *pu64Val, void *pvUser)
{
    PPSPCOREINT pThis = (PPSPCOREINT)pvUser;
    PPSPCORECPBANK pCpBank = pspEmuCoreCpGetBank(pThis);

    *pu64Val = 0;
    bool fHandled = true;
    if (   uCp == 15
        && uCrn == 1
        && uCrm == 0
        && uOpc1 == 0
        && uOpc2 == 0)
        *pu64Val = pCpBank->u32RegSctrl;
    else if (   uCp == 15
        && uCrn == 7
        && uCrm == 4
        && uOpc1 == 0
        && uOpc2 == 0)
        *pu64Val = pCpBank->u32RegPa;
    else if (   uCp == 15
             && uCrn == 2
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        *pu64Val = pCpBank->u32RegTtbr0;
    else if (   uCp == 15
             && uCrn == 2
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 2)
        *pu64Val = pCpBank->u32RegTtbcr;
    else if (   uCp == 15
             && uCrn == 12
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        *pu64Val = pCpBank->u32RegVBar;
    else if (   uCp == 15
             && uCrn == 12
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 1)
        *pu64Val = pCpBank->u32RegVBar;
    else if (   uCp == 15
             && uCrn == 1
             && uCrm == 1
             && uOpc1 == 0
             && uOpc2 == 0)
        *pu64Val = pThis->Cp15.u32RegScr;
    else if (   uCp == 15
             && uCrn == 5
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        *pu64Val = pCpBank->u32RegDfsr;
    else if (   uCp == 15
             && uCrn == 5
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 1)
        *pu64Val = pCpBank->u32RegIfsr;
    else if (   uCp == 15
             && uCrn == 6
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        *pu64Val = pCpBank->u32RegDfar;
    else if (   uCp == 15
             && uCrn == 6
             && uCrm == 0
             && uOpc1 == 0
             && uOpc2 == 0)
        *pu64Val = pCpBank->u32RegIfar;
    else if (   uCp == 15
             && uCrn == 13
             && uCrm == 0
             && uOpc1 == 0)
    {
        switch (uOpc2)
        {
            case 1:
                *pu64Val = pCpBank->u32RegContextId;
                break;
            case 2:
                *pu64Val = pCpBank->u32RegTpIdURw;
                break;
            case 3:
                *pu64Val = pCpBank->u32RegTpIdURo;
                break;
            case 4:
                *pu64Val = pCpBank->u32RegTpIdPRw;
                break;
            default:
                fHandled = false;
                break;
        }
    }
    else
        fHandled = false;

    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE,
                            "CO-PROC READ: uCp=%u uCrn=%u uCrm=%u uOpc1=%u uOpc2=%u u64Val=%#llx fHandled=%u\n",
                            uCp, uCrn, uCrm, uOpc1, uOpc2, *pu64Val, fHandled);
    return fHandled;
}


/**
 * The CPSR write callback.
 *
 * @returns nothing.
 * @param   pUcEngine           Pointer to the unicorn engine instance.
 * @param   uAddrPc             The PC causing the write.
 * @param   u32Val              The new CPSR value.
 * @param   pvUser              Opaque user data passed when adding the hook.
 */
static void pspEmuCoreCpsrChangeWrapper(struct uc_struct *pUcEngine, uint64_t uAddrPc, uint32_t u32Val, void *pvUser)
{
    PPSPCOREINT pThis = (PPSPCOREINT)pvUser;

    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE, "pspEmuCoreCpsrChangeWrapper: u32Val=%#x\n", u32Val);

    PSPCOREMODE enmCoreMode = pspEmuCoreModeFromCpsr(u32Val);
    if (pThis->enmCoreMode != enmCoreMode)
    {
        /* We need to stop emulation and rearrange the MMU when we switch in and out of monitor mode. */
        //printf("%#llx Switching from mode %s to %s\n", uAddrPc, pspEmuCoreModeToStr(pThis->enmCoreMode),
        //       pspEmuCoreModeToStr(enmCoreMode));
        if (   (   pThis->enmCoreMode == PSPCOREMODE_MON
                || enmCoreMode == PSPCOREMODE_MON)
            && (pThis->Cp15.u32RegScr & BIT(0)))
        {
            pThis->fMmuChanged = true;
            uc_emu_stop(pUcEngine);
        }
        pThis->enmCoreMode = enmCoreMode;
    }

    pThis->u32RegCpsr = u32Val;
    if ((u32Val & (BIT(7) | BIT(6))) != 0xc0)
        pspEmuCoreIrqCheckAndInject(pThis, (PSPVADDR)uAddrPc, false /*fWait*/);
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
            if (   pThis->pSvcReg->GlobalSvmc.pfnSvmcHnd
                && pThis->pSvcReg->GlobalSvmc.fFlags & PSPEMU_CORE_SVMC_F_BEFORE)
                fHandled = pThis->pSvcReg->GlobalSvmc.pfnSvmcHnd(pThis, idxSyscall, PSPEMU_CORE_SVMC_F_BEFORE, pThis->pvSvcUser);

            /* Any per SVC handler set?. */
            if (idxSyscall < pThis->pSvcReg->cSvmcDescs)
            {
                PCPSPCORESVMCDESC pSvcDesc = &pThis->pSvcReg->paSvmcDescs[idxSyscall];
                if (   pSvcDesc->pfnSvmcHnd
                    && pSvcDesc->fFlags & PSPEMU_CORE_SVMC_F_BEFORE)
                    fHandled = pSvcDesc->pfnSvmcHnd(pThis, idxSyscall, PSPEMU_CORE_SVMC_F_BEFORE, pThis->pvSvcUser);
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
        if (   pThis->pSvcReg->GlobalSvmc.pfnSvmcHnd
            && pThis->pSvcReg->GlobalSvmc.fFlags & PSPEMU_CORE_SVMC_F_AFTER)
            pThis->pSvcReg->GlobalSvmc.pfnSvmcHnd(pThis, pThis->idxSvc, PSPEMU_CORE_SVMC_F_AFTER, pThis->pvSvcUser);

        /* Any per SVC handler set?. */
        if (pThis->idxSvc < pThis->pSvcReg->cSvmcDescs)
        {
            PCPSPCORESVMCDESC pSvcDesc = &pThis->pSvcReg->paSvmcDescs[pThis->idxSvc];
            if (   pSvcDesc->pfnSvmcHnd
                && pSvcDesc->fFlags & PSPEMU_CORE_SVMC_F_AFTER)
                pSvcDesc->pfnSvmcHnd(pThis, pThis->idxSvc, PSPEMU_CORE_SVMC_F_AFTER, pThis->pvSvcUser);
        }
    }

    return rc;
}


/**
 * Execute any injected SMC handlers before possibly passing control to the monitor code.
 *
 * @returns Status code.
 * @param   pThis               The PSP emulation code instance.
 * @param   PspAddrPc           Address of the instruction coming after the SMC instruction.
 * @param   fThumb              Flag whether the core is currently executing in thumb mode.
 * @param   pfSwitchToMon       Where to store the flag whether to switch to monitor mode after all
 *                              handlers where executed.
 */
static int pspEmuCoreSmcBefore(PPSPCOREINT pThis, PSPADDR PspAddrPc, bool fThumb, bool *pfSwitchToMon)
{
    int rc = 0;
    bool fHandled = false; /* Default is to switch to supervisor mode in case there is nothing injected. */

    if (pThis->pSmcReg)
    {
        uint32_t idxCall = 0;

        if (fThumb)
        {
            uint32_t uInsnSmc;
            uc_err rcUc = uc_mem_read(pThis->pUcEngine, PspAddrPc - 4, &uInsnSmc, sizeof(uInsnSmc));
            if (rcUc == UC_ERR_OK)
            {
                if ((uInsnSmc & 0xfff0ffff) == 0x8000f7f0)
                    idxCall = (uInsnSmc >> 16) & 0xf;
                else
                    rc = -1; /* Should never happen. */
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc);
        }
        else
        {
            uint32_t uInsnSmc;
            uc_err rcUc = uc_mem_read(pThis->pUcEngine, PspAddrPc - 4, &uInsnSmc, sizeof(uInsnSmc));
            if (rcUc == UC_ERR_OK)
            {
                if ((uInsnSmc & 0x0ffffff0) == 0x01600070)
                    idxCall = uInsnSmc & 0xf;
                else
                    rc = -1; /* Should never happen. */
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc);
        }

        if (!rc)
        {
            pThis->idxSmc = idxCall;

            /* Any global handlers?. */
            if (   pThis->pSmcReg->GlobalSvmc.pfnSvmcHnd
                && pThis->pSmcReg->GlobalSvmc.fFlags & PSPEMU_CORE_SVMC_F_BEFORE)
                fHandled = pThis->pSmcReg->GlobalSvmc.pfnSvmcHnd(pThis, idxCall, PSPEMU_CORE_SVMC_F_BEFORE, pThis->pvSmcUser);

            /* Any per SVC handler set?. */
            if (idxCall < pThis->pSmcReg->cSvmcDescs)
            {
                PCPSPCORESVMCDESC pSmcDesc = &pThis->pSmcReg->paSvmcDescs[idxCall];
                if (   pSmcDesc->pfnSvmcHnd
                    && pSmcDesc->fFlags & PSPEMU_CORE_SVMC_F_BEFORE)
                    fHandled = pSmcDesc->pfnSvmcHnd(pThis, idxCall, PSPEMU_CORE_SVMC_F_BEFORE, pThis->pvSmcUser);
            }
        }
    }

    *pfSwitchToMon = fHandled ? false : true;

    return rc;
}


/**
 * Execute any injected SMC handlers after control was passed to the supervisor code and control is about to
 * return to the code invoking the SVC.
 *
 * @returns Status code.
 * @param   pThis               The PSP emulation code instance.
 */
static int pspEmuCoreSmcAfter(PPSPCOREINT pThis)
{
    int rc = 0;

    if (pThis->pSmcReg)
    {
        /* Any global handlers?. */
        if (   pThis->pSmcReg->GlobalSvmc.pfnSvmcHnd
            && pThis->pSmcReg->GlobalSvmc.fFlags & PSPEMU_CORE_SVMC_F_AFTER)
            pThis->pSmcReg->GlobalSvmc.pfnSvmcHnd(pThis, pThis->idxSmc, PSPEMU_CORE_SVMC_F_AFTER, pThis->pvSmcUser);

        /* Any per SMC handler set?. */
        if (pThis->idxSmc < pThis->pSmcReg->cSvmcDescs)
        {
            PCPSPCORESVMCDESC pSmcDesc = &pThis->pSvcReg->paSvmcDescs[pThis->idxSvc];
            if (   pSmcDesc->pfnSvmcHnd
                && pSmcDesc->fFlags & PSPEMU_CORE_SVMC_F_AFTER)
                pSmcDesc->pfnSvmcHnd(pThis, pThis->idxSmc, PSPEMU_CORE_SVMC_F_AFTER, pThis->pvSmcUser);
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
static bool pspEmuCoreInsnIsWfi(PPSPCOREINT pThis, PSPVADDR PspAddrPc, bool fThumb)
{
    if (fThumb)
    {
        uint16_t u16Insn = 0;
        int rc = PSPEmuCoreMemReadVirt(pThis, PspAddrPc - 2, &u16Insn, sizeof(u16Insn));
        if (   STS_SUCCESS(rc)
            && u16Insn == 0xbf30)
            return true;
    }
    else
    {
        uint32_t u32Insn = 0;
        int rc = PSPEmuCoreMemReadVirt(pThis, PspAddrPc - 4, &u32Insn, sizeof(u32Insn));
        if (   STS_SUCCESS(rc)
            && (   (u32Insn & 0x0fffffff) == 0x0320f003)
                || (u32Insn & 0x0fffffff) == 0x0320f002) /* WFE, treated the same here for now */
            return true;
    }

    return false;
}


/**
 * Finds the region assigned to the given address or NULL if there is nothing assigned.
 *
 * @returns Pointer to the region or NULL if not found.
 * @param   pThis                   The PSP core instance.
 * @param   PspAddr                 The physical PSP address to look for.
 * @param   ppPrevRegion            Where to store the pointer to the previous region, optional.
 */
static PPSPCOREMEMREGION pspEmuCoreMemRegionFindByAddr(PPSPCOREINT pThis, PSPADDR PspAddr,
                                                       PPSPCOREMEMREGION *ppPrevRegion)
{
    if (   PspAddr < pThis->PspAddrMemLowest
        || PspAddr > pThis->PspAddrMemHighest)
        return NULL;

    /* Slow path. */
    PPSPCOREMEMREGION pPrev = NULL;
    PPSPCOREMEMREGION pCur = pThis->pMemRegionsHead;
    while (pCur)
    {
        if (   PspAddr >= pCur->PspAddrStart
            && PspAddr < pCur->PspAddrStart + pCur->cbRegion)
        {
            if (ppPrevRegion)
                *ppPrevRegion = pPrev;
            return pCur;
        }

        pPrev = pCur;
        pCur = pCur->pNext;
    }

    return NULL;
}


/**
 * Inserts the given memory region at the appropriate palce in the linked list.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   pMemRegion              The memory region to add.
 */
static int pspEmuCoreMemRegionInsert(PPSPCOREINT pThis, PPSPCOREMEMREGION pMemRegion)
{
    int rc = 0;
    PPSPCOREMEMREGION pPrev = NULL;
    PPSPCOREMEMREGION pCur = pThis->pMemRegionsHead;

    /* Search where to insert the new device, sorted by starting MMIO address. */
    while (pCur)
    {
        if (pCur->PspAddrStart > pMemRegion->PspAddrStart)
            break;
        pPrev = pCur;
        pCur = pCur->pNext;
    }

    /* Do some sanity checks, the new range must not overlap with the previous and current range. */
    if (   (   !pPrev
            || pPrev->PspAddrStart + pPrev->cbRegion <= pMemRegion->PspAddrStart)
        && (   !pCur
            || pMemRegion->PspAddrStart + pMemRegion->cbRegion <= pCur->PspAddrStart))
    {
        pMemRegion->pNext = pCur;
        if (pPrev)
            pPrev->pNext = pMemRegion;
        else
            pThis->pMemRegionsHead = pMemRegion;

        /* Adjust the lowest and highest device range. */
        if (pMemRegion->PspAddrStart < pThis->PspAddrMemLowest)
            pThis->PspAddrMemLowest = pMemRegion->PspAddrStart;
        if (pMemRegion->PspAddrStart + pMemRegion->cbRegion - 1 > pThis->PspAddrMemHighest)
            pThis->PspAddrMemHighest = pMemRegion->PspAddrStart + pMemRegion->cbRegion - 1;
    }
    else
        rc = -1;

    return rc;
}


/**
 * Finds the region assigned to the given region bounadries, unlinks and returns or returns
 * NULL if there is nothing assigned.
 *
 * @returns Pointer to the unlinked region or NULL if not found.
 * @param   pThis                   The PSP core instance.
 * @param   PspAddr                 The physical PSP address to look for.
 * @param   cbRegion                Size of the region.
 */
static PPSPCOREMEMREGION pspEmuCoreMemRegionFindAndUnlinkByAddr(PPSPCOREINT pThis, PSPADDR PspAddr, size_t cbRegion)
{
    PPSPCOREMEMREGION pPrev = NULL;
    PPSPCOREMEMREGION pRegion = pspEmuCoreMemRegionFindByAddr(pThis, PspAddr, &pPrev);
    if (   pRegion
        && pRegion->PspAddrStart == PspAddr
        && pRegion->cbRegion == cbRegion)
    {
        if (pPrev)
            pPrev->pNext = pRegion->pNext;
        else
            pThis->pMemRegionsHead = pRegion->pNext;
        return pRegion;
    }

    return NULL;
}


/**
 * Unregisters all memory regions from unicorn.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 */
static int pspEmuCoreMemRegionsUnregisterAll(PPSPCOREINT pThis)
{
    PPSPCOREMEMREGION pMemCur = pThis->pMemRegionsHead;
    while (pMemCur)
    {
        if (pMemCur->fMapped)
        {
            uc_err rcUc = uc_mem_unmap(pThis->pUcEngine, pMemCur->PspAddrStart, pMemCur->cbRegion);
            /** @todo assert(rcUrc == UC_ERR_OK) */
            pMemCur->fMapped = false;
        }
        pMemCur = pMemCur->pNext;
    }

    return 0;
}


/**
 * Converts our own protection flags to unicorn flags.
 *
 * @returns Unicorn protection flag mask.
 * @param   fProt                   The protection flags to convert.
 */
static int32_t pspEmuCoreMemRegionProt2UcProt(uint32_t fProt)
{
    int32_t fUcProt = 0;

    if (fProt & PSPEMU_CORE_MEM_REGION_PROT_F_EXEC)
        fUcProt |= UC_PROT_EXEC;
    if (fProt & PSPEMU_CORE_MEM_REGION_PROT_F_READ)
        fUcProt |= UC_PROT_READ;
    if (fProt & PSPEMU_CORE_MEM_REGION_PROT_F_WRITE)
        fUcProt |= UC_PROT_WRITE;

    return fUcProt;
}


/**
 * Maps a given memory region directly into unicorn.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   pMemRegion              The memory region to map.
 */
static int pspEmuCoreMemRegionMap(PPSPCOREINT pThis, PPSPCOREMEMREGION pMemRegion)
{
    int rc = 0;
    uc_err rcUc;

    if (pMemRegion->fMmio)
        rcUc = uc_mmio_map(pThis->pUcEngine, pMemRegion->PspAddrStart, pMemRegion->cbRegion,
                           pspEmuCoreMmioRead, pspEmuCoreMmioWrite, pMemRegion);
    else
    {
        int32_t fUcProt = pspEmuCoreMemRegionProt2UcProt(pMemRegion->u.Ram.fProt);
        rcUc = uc_mem_map_ptr(pThis->pUcEngine, pMemRegion->PspAddrStart, pMemRegion->cbRegion,
                              fUcProt, pMemRegion->u.Ram.pvBacking);
    }

    if (rcUc == UC_ERR_OK)
        pMemRegion->fMapped = true;
    else
        rc = pspEmuCoreErrConvertFromUcErr(rcUc);

    return rc;
}


/**
 * Unregisters all physical memory regions with unicorn.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 */
static int pspEmuCoreMemRegionsRegisterAll(PPSPCOREINT pThis)
{
    int rc = 0;
    PPSPCOREMEMREGION pMemCur = pThis->pMemRegionsHead;
    while (   pMemCur
           && !rc)
    {
        rc = pspEmuCoreMemRegionMap(pThis, pMemCur);
        pMemCur = pMemCur->pNext;
    }

    return rc;
}


/**
 * Inserts the given MMU mapping at the appropriate place in the linked list.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   pMmuMap                 The MMU mapping to add.
 */
static int pspEmuCoreMmuMappingInsert(PPSPCOREINT pThis, PPSPCOREMMUMAP pMmuMap)
{
    int rc = 0;
    PPSPCOREMMUMAP pPrev = NULL;
    PPSPCOREMMUMAP pCur  = pThis->pMmuMappingsHead;

    /* Search where to insert the new device, sorted by starting MMIO address. */
    while (pCur)
    {
        if (pCur->PspAddrVStart > pMmuMap->PspAddrVStart)
            break;
        pPrev = pCur;
        pCur = pCur->pNext;
    }

    /* Do some sanity checks, the new range must not overlap with the previous and current range. */
    if (   (   !pPrev
            || pPrev->PspAddrVStart + pPrev->cbRegion <= pMmuMap->PspAddrVStart)
        && (   !pCur
            || pMmuMap->PspAddrVStart + pMmuMap->cbRegion <= pCur->PspAddrVStart))
    {
        pMmuMap->pNext = pCur;
        if (pPrev)
            pPrev->pNext = pMmuMap;
        else
            pThis->pMmuMappingsHead = pMmuMap;
    }
    else
        rc = -1;

    return rc;
}


/**
 * Queries the root of the page tables, i.e. the physical address where the L1 table is located.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   pPspAddrPbTblL1         WHere to store the physical address of the L1 page table start on success.
 */
static int pspEmuCoreMmuPgTblQueryRoot(PPSPCOREINT pThis, PSPPADDR *pPspPAddrPgTblL1)
{
    int rc = STS_INF_SUCCESS;

    /* Get TTBR0 . */
    PPSPCORECPBANK pCpBank = pspEmuCoreCpGetBank(pThis);
    uint32_t uN = pCpBank->u32RegTtbcr & 0x7;
    PSPPADDR PhysAddrPgTbl = pCpBank->u32RegTtbr0;

    /* Extract the physical L1 address using the read boundary size. */
    *pPspPAddrPgTblL1 = PhysAddrPgTbl & ~(uint32_t)(0x3fff >> uN);

    return rc;
}


/**
 * Returns the memory range where page tables are located (this can also cover memory which
 * doesn't contain page tables).
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   pPspPAddrPgTblStart     Where to store the physical address of the start of the page tables on success.
 * @param   pcbPgTbl                Size of the memory region containing the page tables on success.
 */
static int pspEmuCoreMmuPgTblQueryRange(PPSPCOREINT pThis, PSPPADDR *pPspPAddrPgTblStart, size_t *pcbPgTbl)
{
    PSPPADDR PhysAddrPgTbl = 0;
    int rc = pspEmuCoreMmuPgTblQueryRoot(pThis, &PhysAddrPgTbl);
    if (!rc)
    {
        uint32_t au32Tbl[32/*4096*/];

        rc = PSPEmuCoreMemRead(pThis, PhysAddrPgTbl, &au32Tbl[0], sizeof(au32Tbl));
        if (!rc)
        {
            PSPPADDR PhysAddrStart = PhysAddrPgTbl;
            PSPPADDR PhysAddrEnd   = PhysAddrStart + sizeof(au32Tbl);

            for (uint32_t i = 0; i < ELEMENTS(au32Tbl) && !rc; i++)
            {
                if ((au32Tbl[i] & 0x3) == 0x1) /* Only page table entries contain a L2 table. */
                {
                    PSPPADDR PhysAddrL2 = au32Tbl[i] & 0xfffffc00;

                    if (PhysAddrL2 < PhysAddrStart)
                        PhysAddrStart = PhysAddrL2;
                    else if (PhysAddrL2 > PhysAddrEnd)
                        PhysAddrEnd = PhysAddrL2 + _1K;
                }
            }

            *pPspPAddrPgTblStart = PhysAddrStart;
            *pcbPgTbl = PhysAddrEnd - PhysAddrStart;
        }
    }

    return rc;
}


/**
 * Returns the physical address the given L2 descriptor points to.
 *
 * @returns Page aligned physical address.
 * @param   u32L2Desc               The L2 descriptor.
 * @param   idxL2                   Index in the L2 table where the descriptor is stored.
 */
static inline PSPPADDR pspEmuCoreMmuPgTblL2GetPhysAddrFromDesc(uint32_t u32L2Desc, uint32_t idxL2)
{
    if ((u32L2Desc & 0x2) == 0x2)
        return u32L2Desc & 0xfffff000;
    else if ((u32L2Desc & 0x3) == 0x1)
        return (u32L2Desc & 0xffff0000) + (idxL2 % 16) * _4K;

    /* Not present entry. */
    return 0xffffffff;
}


/**
 * Tries to resolve a given virtual PSP address to a physical one - page aligned version.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   PspVAddrPg              Page aligned virtual PSP address.
 * @param   pPspPAddrPg             Where to store the physical address on success.
 * @param   pcbRegion               Where to store the size of the resolved physical memory region on success.
 * @param   penmPgTblWalk           Where to store information on the page table walk, optional.
 *
 * @todo Extract access permissions.
 */
static int pspEmuCoreMmuPAddrQueryFromVAddrPageAligned(PPSPCOREINT pThis, PSPVADDR PspVAddrPg, PSPPADDR *pPspPAddrPg, size_t *pcbRegion,
                                                       PPSPCOREPGTBLWALKSTS penmPgTblWalk)
{
    PSPPADDR PhysAddrPgTbl = 0;
    int rc = pspEmuCoreMmuPgTblQueryRoot(pThis, &PhysAddrPgTbl);
    if (!rc)
    {
        uint32_t au32Tbl[4096];

        rc = PSPEmuCoreMemRead(pThis, PhysAddrPgTbl, &au32Tbl[0], sizeof(au32Tbl));
        if (!rc)
        {
            uint32_t idxL1 = PspVAddrPg >> PSP_PAGE_L1_IDX_SHIFT;
            uint32_t idxL2 = (PspVAddrPg >> 12) & 0xff;
            uint32_t u32L1Desc = au32Tbl[idxL1];

            if (penmPgTblWalk)
                *penmPgTblWalk = PSPCOREPGTBLWALKSTS_L1;

            /* Coarse page table.*/
            if ((u32L1Desc & 0x3) == 0x1)
            {
                PSPPADDR PhysAddrL2 = u32L1Desc & 0xfffffc00;
                rc = PSPEmuCoreMemRead(pThis, PhysAddrL2, &au32Tbl[0], _1K);
                if (!rc)
                {
                    uint32_t u32L2Desc = au32Tbl[idxL2];
                    if ((u32L2Desc & 0x2) == 0x2)
                    {
                        *pPspPAddrPg = u32L2Desc & 0xfffff000;
                        *pcbRegion   = _4K;
                    }
                    else if ((u32L2Desc & 0x3) == 0x1)
                    {
                        *pPspPAddrPg = u32L2Desc & 0xffff0000;
                        *pcbRegion   = 64 * _1K;
                    }
                    else
                        rc = -1;
                }

                if (penmPgTblWalk)
                    *penmPgTblWalk = PSPCOREPGTBLWALKSTS_L2;
            }
            else if (   (u32L1Desc & 0x2) == 0x2
                     && (u32L1Desc & BIT(18)) == 0x0)
            {
                /* Section. */
                PSPPADDR PhysAddrSection = u32L1Desc & 0xfff00000;
                *pPspPAddrPg = PhysAddrSection + idxL2 * _4K;
                *pcbRegion   = _4K;
            }
            else
                rc = -1; /** @todo Support supersections. */
        }
    }

    return rc;
}


/**
 * Tries to resolve a given virtual PSP address to a physical one.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   PspVAddr                Virtual PSP address to resolve.
 * @param   pPspPAddr               Where to store the physical address on success.
 * @param   pcbRegion               Where to store the size of the resolved contiguous physical memory region on success.
 * @param   penmPgTblWak            Where to store the information about the page table walk, optional.
 *
 * @todo Extract access permissions.
 */
static int pspEmuCoreMmuPAddrQueryFromVAddr(PPSPCOREINT pThis, PSPVADDR PspVAddr, PSPPADDR *pPspPAddr, size_t *pcbRegion,
                                            PPSPCOREPGTBLWALKSTS penmPgTblWalk)
{
    PSPVADDR PspVAddrPg = PspVAddr & ~(PSP_PAGE_SIZE - 1);
    uint32_t offPg = PspVAddr & (PSP_PAGE_SIZE - 1);

    int rc = pspEmuCoreMmuPAddrQueryFromVAddrPageAligned(pThis, PspVAddrPg, pPspPAddr, pcbRegion, penmPgTblWalk);
    if (STS_SUCCESS(rc))
    {
        *pPspPAddr |= offPg;
        *pcbRegion -= offPg;
    }

    return rc;
}


/**
 * Tries to resolve a given physical PSP address to a virtual one.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   PspPAddr                Physical PSP address.
 * @param   cbPhysRegion            The physical region size.
 * @param   pPspVAddr               Where to store the virtual address on success.
 * @param   pcbRegion               Where to store the size of the resolved contiguous virtual memory region on success.
 */
static int pspEmuCoreMmuVAddrQueryFromPAddr(PPSPCOREINT pThis, PSPPADDR PspPAddr, size_t cbPhysRegion,
                                            PSPVADDR *pPspVAddr, size_t *pcbRegion,
                                            uint32_t *pidxL1, uint32_t *pidxL2)
{
    PSPPADDR PspPAddrPg = PspPAddr & ~(PSP_PAGE_SIZE - 1);
    PSPPADDR offPg = PspPAddr - PspPAddrPg;

    PSPPADDR PhysAddrPgTbl = 0;
    int rc = pspEmuCoreMmuPgTblQueryRoot(pThis, &PhysAddrPgTbl);
    if (!rc)
    {
        uint32_t au32Tbl[32];

        rc = PSPEmuCoreMemRead(pThis, PhysAddrPgTbl, &au32Tbl[0], sizeof(au32Tbl));
        if (!rc)
        {
            /* Scan the page tables for the physical address. */
            for (uint32_t i = *pidxL1; i < ELEMENTS(au32Tbl) && !rc; i++)
            {
                if ((au32Tbl[i] & 0x3) == 0x1)
                {
                    PSPPADDR PhysAddrL2 = au32Tbl[i] & 0xfffffc00;
                    uint32_t au32TblL2[1024 / sizeof(uint32_t)];

                    rc = PSPEmuCoreMemRead(pThis, PhysAddrL2, &au32TblL2[0], sizeof(au32TblL2));
                    if (!rc)
                    {
                        for (uint32_t idxL2 = *pidxL2; idxL2 < ELEMENTS(au32TblL2) && !rc; idxL2++)
                        {
                            PSPPADDR PhysStart = pspEmuCoreMmuPgTblL2GetPhysAddrFromDesc(au32TblL2[idxL2], idxL2);
                            if (PhysStart == 0xffffffff)
                                continue;

                            if (PspPAddrPg == PhysStart)
                            {
                                /* Check for adjacent regions. */
                                PSPVADDR PspVAddrStart = i * _1M + idxL2 * _4K;
                                size_t cbVRegion = _4K;

                                idxL2++;
                                PspPAddrPg += _4K;
                                while (   idxL2 < ELEMENTS(au32TblL2)
                                       && cbVRegion < cbPhysRegion)
                                {
                                    PhysStart = pspEmuCoreMmuPgTblL2GetPhysAddrFromDesc(au32TblL2[idxL2], idxL2);
                                    if (PhysStart != PspPAddrPg)
                                        break;
                                    cbVRegion  += _4K;
                                    PspPAddrPg += _4K;
                                    idxL2++;
                                }

                                *pPspVAddr = PspVAddrStart | offPg;
                                *pcbRegion = MIN(cbPhysRegion, cbVRegion);
                                *pidxL1 = i;
                                *pidxL2 = idxL2;
                                return 0;
                            }
                        }

                        *pidxL2 = 0;
                    }
                }
                else if (   (au32Tbl[i] & 0x2) == 0x2
                         && (au32Tbl[i] & BIT(18)) == 0x0)
                {
                    /* Section. */
                    PSPPADDR PhysStartSection = au32Tbl[i] & 0xfff00000;
                    size_t cbSection = _1M;

                    if (   PspPAddrPg >= PhysStartSection
                        && PspPAddrPg < PhysStartSection + cbSection)
                    {
                        *pPspVAddr = (i * _1M + (PspPAddrPg - PhysStartSection)) | offPg;
                        *pcbRegion = MIN(cbPhysRegion, cbSection);
                        *pidxL1 = i + 1;
                        *pidxL2 = 0;
                        return 0;
                    }
                }
                else if ((au32Tbl[i] & 0x3) != 0x0)
                    printf("No support for super sections right now %#x!\n", au32Tbl[i]);
            }

            if (!rc)
                rc = -1; /* If we got here we found nothing :(. */
        }
    }

    return rc;
}


/**
 * Unicorn MMIO read wrapper for the MMU enabled case.
 *
 * @returns Data read.
 * @param   pUcEngine               The unicorn engine pointer.
 * @param   pvUser                  Opaque user data.
 * @param   uAddr                   MMIO address read.
 * @param   cbInsn                  Size of the read (1, 2, 4 or 8 bytes).
 */
static uint64_t pspEmuCoreMmuMapMmioRead(struct uc_struct* pUcEngine, void *pvUser, uint64_t uAddr, unsigned cb)
{
    PCPSPCOREMMUMAP pMmuMap = (PCPSPCOREMMUMAP)pvUser;

    /* The address is from the start of our MMU mapping. */
    PSPADDR offPhys = pMmuMap->offPhysMap + (uint32_t)uAddr;
    return pspEmuCoreMmioRead(pUcEngine, (void *)pMmuMap->pMemRegion, offPhys, cb);
}


/**
 * Unicorn MMIO write wrapper for the MMU enabled case.
 *
 * @returns nothing.
 * @param   pUcEngine               The unicorn engine pointer.
 * @param   pvUser                  Opaque user data.
 * @param   uAddr                   MMIO address written.
 * @param   uVal                    Value written.
 * @param   cbInsn                  Size of the write (1, 2, 4 or 8 bytes).
 */
static void pspEmuCoreMmuMapMmioWrite(struct uc_struct* pUcEngine, void *pvUser, uint64_t uAddr, uint64_t uVal, unsigned cb)
{
    PCPSPCOREMMUMAP pMmuMap = (PCPSPCOREMMUMAP)pvUser;

    /* The address is from the start of our MMU mapping. */
    PSPADDR offPhys = pMmuMap->offPhysMap + (uint32_t)uAddr;
    pspEmuCoreMmioWrite(pUcEngine, (void *)pMmuMap->pMemRegion, offPhys, uVal, cb);
}


/**
 * Clears all virtual memory mappings registered with unicorn by the MMU.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 */
static int pspEmuCoreMmuMappingsClear(PPSPCOREINT pThis)
{
    PPSPCOREMMUMAP pMmuMap = pThis->pMmuMappingsHead;
    while (pMmuMap)
    {
        PPSPCOREMMUMAP pFree = pMmuMap;
        pMmuMap = pMmuMap->pNext;
        uc_err rcUc = uc_mem_unmap(pThis->pUcEngine, pFree->PspAddrVStart, pFree->cbRegion);
        /** @todo assert(rcUrc == UC_ERR_OK) */
        free(pFree);
    }

    pThis->pMmuMappingsHead = NULL;
    return 0;
}


/**
 * Unicorn write hook wrapper for the page table region.
 *
 * @returns nothing.
 * @param   pUcEngine               The unicorn engine pointer.
 * @param   uAddr                   Address being written.
 * @param   cb                      Size of the write (1, 2, 4 or 8 bytes).
 * @param   iVal                    Value written.
 * @param   pvUser                  Opaque user data.
 */
static void pspEmuCoreMmuPgTblWrite(struct uc_struct* pUcEngine, uc_mem_type enmMemType, uint64_t uAddr, int cb, int64_t iVal, void *pvUser)
{
    PCPSPCOREPGTBLTRACK pPgTblTrack = (PCPSPCOREPGTBLTRACK)pvUser;
    PPSPCOREINT pThis = pPgTblTrack->pThis;

    printf("Page table write at address %#llx with value %#llx (cb=%u)\n", uAddr, iVal, cb);
    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE, "Page table write at address %#llx with value %#llx (cb=%u)\n", uAddr, iVal, cb);

    /* As the page tables have changed we have to clear all mappings and start all over. */
    pspEmuCoreMmuMappingsClear(pThis);
}


/**
 * Creates a new MMU mapping and sets up the unicorn instance.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   pMemRegion              The physical memory region to create an MMU mapping for.
 * @param   PspVAddrPg              Page aligned virtual start address.
 * @param   PspPAddrPg              Page aligned physical start address.
 * @param   offMap                  Offset of the mapping into the physical region.
 * @param   cbMap                   Size of the mapping.
 */
static int pspEmuCoreMmuMappingCreate(PPSPCOREINT pThis, PCPSPCOREMEMREGION pMemRegion,
                                      PSPVADDR PspVAddrPg, PSPPADDR PspPAddrPg,
                                      uint32_t offMap, size_t cbMap)
{
    /* Create a new MMU mapping and register with unicorn. */
    int rc = 0;
    PPSPCOREMMUMAP pMmuMap = (PPSPCOREMMUMAP)calloc(1, sizeof(*pMmuMap));
    if (pMmuMap)
    {
        pMmuMap->pNext         = NULL;
        pMmuMap->pPspCore      = pThis;
        pMmuMap->pMemRegion    = pMemRegion;
        pMmuMap->PspAddrVStart = PspVAddrPg;
        pMmuMap->PspAddrPStart = PspPAddrPg;
        pMmuMap->cbRegion      = cbMap;
        pMmuMap->offPhysMap    = offMap;

        rc = pspEmuCoreMmuMappingInsert(pThis, pMmuMap);
        if (!rc)
        {
            /* Register with unicorn now. */
            uc_err rcUc = UC_ERR_OK;

            if (!pMemRegion->fMmio)
            {
                /* We use the assigned protection of the memory backing instead of what the page tables say. */
                int32_t fUcProt = pspEmuCoreMemRegionProt2UcProt(pMemRegion->u.Ram.fProt);
                uint8_t *pbBacking = (uint8_t *)pMemRegion->u.Ram.pvBacking + offMap;
                rcUc = uc_mem_map_ptr(pThis->pUcEngine, PspVAddrPg, cbMap, fUcProt, pbBacking);
            }
            else
            {
                /* Register our own wrappers so we can translate addresses. */
                rcUc = uc_mmio_map(pThis->pUcEngine, PspVAddrPg, cbMap,
                                   pspEmuCoreMmuMapMmioRead, pspEmuCoreMmuMapMmioWrite, pMmuMap);
            }

            if (rcUc != UC_ERR_OK)
                rc = pspEmuCoreErrConvertFromUcErr(rcUc);
        }
    }
    else
        rc = -1;

    return rc;
}


/**
 * Tries to map the given virtual PSP address to a physical one by traversing the page tables
 * and cerate a new unicorn mapping for it.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   PspVAddr                The virtual PSP address to resolve.
 * @param   pfHandled               Where to store a flag whether the request could be handled successfully.
 */
static int pspEmuCoreMmuMap(PPSPCOREINT pThis, PSPVADDR PspVAddr, bool *pfHandled)
{
    /* Try to resolve the page from the root. */
    PSPVADDR PspVAddrPg = PspVAddr & ~(PSP_PAGE_SIZE - 1);
    PSPPADDR PspPAddrPg;
    size_t cbRegion;
    int rc = pspEmuCoreMmuPAddrQueryFromVAddr(pThis, PspVAddrPg, &PspPAddrPg, &cbRegion, NULL /*penmPgTblWalk*/);
    if (!rc)
    {
        //printf("pspEmuCoreMmuMap: PspVAddr=%#lx PspPAddr=%#lx\n", PspVAddr, PspPAddrPg);

        /* Walk the physical memory regions registered and create appropriate mappings. */
        PCPSPCOREMEMREGION pMemRegion = pspEmuCoreMemRegionFindByAddr(pThis, PspPAddrPg, NULL /*ppPrevRegion*/);
        while (   cbRegion
               && pMemRegion
               && !rc)
        {
            uint32_t offRegion = PspPAddrPg - pMemRegion->PspAddrStart;
            size_t cbThisRegion = MIN(cbRegion, pMemRegion->cbRegion - offRegion);

            /* Create a new MMU mapping for this region and register with unicorn. */
            rc = pspEmuCoreMmuMappingCreate(pThis, pMemRegion, PspVAddrPg, PspPAddrPg, offRegion, cbThisRegion);
            if (!rc)
            {
                pMemRegion = pMemRegion->pNext;
                PspPAddrPg += cbThisRegion;
                PspVAddrPg += cbThisRegion;
                cbRegion   -= cbThisRegion;
            }
        }

        if (!rc)
            *pfHandled = true;
    }
    else
    {
        *pfHandled = false;
        rc = 0;
    }

    //printf("pspEmuCoreMmuMap: rc=%d fHandled=%u\n", rc, *pfHandled);
    return rc;
}


/**
 * Sets up page table tracking for the given range.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   PspPAddrPgTbl           The physical address of the page table region to track.
 * @param   cbPgTbl                 Size of the region in bytes.
 * @param   fL2PgTbl                Flag whether this tracks a L1 or L2 page table.
 */
static int pspEmuCoreMmuPgTblTrackingCreate(PPSPCOREINT pThis, PSPPADDR PspPAddrPgTbl, size_t cbPgTbl, bool fL2PgTbl)
{
    PSPVADDR PspVAddrPgTbl = 0;
    size_t cbVPgTbl = 0;
    uint32_t idxL1 = 0;
    uint32_t idxL2 = 0;
    int rc = STS_INF_SUCCESS;

    do
    {
        rc = pspEmuCoreMmuVAddrQueryFromPAddr(pThis, PspPAddrPgTbl, cbPgTbl,
                                              &PspVAddrPgTbl, &cbVPgTbl,
                                              &idxL1, &idxL2);

        printf("pspEmuCoreMmuPgTblTrackingCreate: PspPAddrPgTbl=%#x cbPgTbl=%zu PspVAddrPgTbl=%#x cbVPgTbl=%zu\n",
                                                  PspPAddrPgTbl, cbPgTbl, PspVAddrPgTbl, cbVPgTbl);
        if (STS_SUCCESS(rc))
        {
            if (cbVPgTbl >= cbPgTbl)
            {
                PPSPCOREPGTBLTRACK pPgTblTrack = (PPSPCOREPGTBLTRACK)calloc(1, sizeof(*pPgTblTrack));
                if (pPgTblTrack)
                {
                    pPgTblTrack->pNext    = NULL;
                    pPgTblTrack->pThis    = pThis;
                    pPgTblTrack->fL2PgTbl = fL2PgTbl;
                    pPgTblTrack->PhysAddrPgTblStart = PspPAddrPgTbl;
                    pPgTblTrack->PspAddrVPgTbl      = PspVAddrPgTbl;
                    pPgTblTrack->cbPgTbl            = cbPgTbl;

                    uc_err rcUc = uc_hook_add(pThis->pUcEngine, &pPgTblTrack->hUcHookWrites, UC_HOOK_MEM_WRITE, (void *)(uintptr_t)pspEmuCoreMmuPgTblWrite,
                                              pPgTblTrack, pPgTblTrack->PspAddrVPgTbl, pPgTblTrack->PspAddrVPgTbl + cbPgTbl - 1);
                    if (rcUc == UC_ERR_OK)
                    {
                        pPgTblTrack->pNext = pThis->pMmuPgTblTrackingHead;
                        pThis->pMmuPgTblTrackingHead = pPgTblTrack;
                    }
                    else
                        rc = pspEmuCoreErrConvertFromUcErr(rcUc);
                }
                else
                    rc = STS_ERR_NO_MEMORY;
            }
            else
            {
                printf("We don't allow individual page tables spanning multiple pages for now...\n");
                rc = STS_ERR_INVALID_PARAMETER;
            }
        }
        else
            printf("pspEmuCoreMmuPgTblTrackingCreate: rc=%d\n", rc);
    } while (STS_SUCCESS(rc));

    rc = 0;
    return rc;
}


/**
 * Sets up the page table tracking when the MMU gets enabled.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 */
static int pspEmuCoreMmuSetupPgTblTracking(PPSPCOREINT pThis)
{
    PSPPADDR PhysAddrPgTbl = 0;
    int rc = pspEmuCoreMmuPgTblQueryRoot(pThis, &PhysAddrPgTbl);
    if (STS_SUCCESS(rc))
    {
        uint32_t au32Tbl[32/*4096*/];

        rc = pspEmuCoreMmuPgTblTrackingCreate(pThis, PhysAddrPgTbl, sizeof(au32Tbl), false /*fL1PgTBl*/);
        if (STS_SUCCESS(rc))
        {
            rc = PSPEmuCoreMemRead(pThis, PhysAddrPgTbl, &au32Tbl[0], sizeof(au32Tbl));
            if (!rc)
            {
                for (uint32_t i = 0; i < ELEMENTS(au32Tbl) && STS_SUCCESS(rc); i++)
                {
                    if ((au32Tbl[i] & 0x3) == 0x1) /* Only page table entries contain a L2 table. */
                    {
                        PSPPADDR PhysAddrL2 = au32Tbl[i] & 0xfffffc00;

                        rc = pspEmuCoreMmuPgTblTrackingCreate(pThis, PhysAddrL2, _1K, true /*fL2PgTbl*/);
                    }
                }
            }
        }
    }

    return rc;
}


/**
 * Removes all page table tracking regions.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 */
static int pspEmuCoreMmuPgTblTrackingRemove(PPSPCOREINT pThis)
{
    int rc = STS_INF_SUCCESS;
    PPSPCOREPGTBLTRACK pCur = pThis->pMmuPgTblTrackingHead;

    while (pCur)
    {
        PPSPCOREPGTBLTRACK pFree = pCur;
        pCur = pCur->pNext;

        uc_err rcUc = uc_hook_del(pThis->pUcEngine, pFree->hUcHookWrites);
        /** @todo assert(rcUc == UC_ERR_OK) */
        free(pFree);
    }

    pThis->pMmuPgTblTrackingHead = NULL;
    return rc;
}


/**
 * Sets up or tears down the MMU state based on the current MMU setting.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 */
static int pspEmuCoreMmuSetupTeardown(PPSPCOREINT pThis)
{
    bool fMmuEnabledOld = pThis->fMmuEnabled;
    bool fMmuEnabledNew = pspEmuCoreCpIsSctrlMmuEnabled(pThis);

    /*
     * If the MMU status didn't change there must have been a page table writes
     * Clear all the mappings and restart.
     */
    if (   pspEmuCoreIsSecure(pThis) == pThis->fMmuSecure
        && fMmuEnabledNew == fMmuEnabledOld)
        return STS_INF_SUCCESS;

    int rc = STS_INF_SUCCESS;
    /* Clear the old state. */
    if (fMmuEnabledOld)
    {
        rc = pspEmuCoreMmuMappingsClear(pThis);
        if (STS_SUCCESS(rc))
            rc = pspEmuCoreMmuPgTblTrackingRemove(pThis);
    }
    else
        rc = pspEmuCoreMemRegionsUnregisterAll(pThis);

    if (STS_SUCCESS(rc))
    {
        pThis->fMmuSecure = pspEmuCoreIsSecure(pThis);
        if (!fMmuEnabledNew)
        {
            /* MMU got disabled, restore physical addressing. */
            rc = pspEmuCoreMemRegionsRegisterAll(pThis);
            pThis->fMmuEnabled = false;
        }
        else
        {
            /* MMU got enabled, set up the page table tracking structures. */
            rc = pspEmuCoreMmuSetupPgTblTracking(pThis);
            pThis->fMmuEnabled = true;
        }
    }

    printf("pspEmuCoreMmuSetupTeardown: rc=%d\n", rc);
    return rc;
}


/**
 * Callback for invalid memory accesses so the MMU can map in regions lazily.
 *
 * @returns Flag whether the invalid memory access was handled successfully, false will stop emulation
 *          and cause an exception event injection.
 * @param   pUcEngine               The unicorn engine instance.
 * @param   enmMemType              Memory access type.
 * @param   uAddr                   The address causing the invalid access.
 * @param   cbAcc                   Size of the access.
 * @param   i64Val                  The value being written, ignored for reads.
 * @param   pvUser                  Opaque user data passed during callback registration.
 */
static bool pspEmuCoreMemMemInvAccess(uc_engine *pUcEngine, uc_mem_type enmMemType, uint64_t uAddr,
                                      int cbAcc, int64_t i64Val, void *pvUser)
{
    PPSPCOREINT pThis = (PPSPCOREINT)pvUser;

#if 0
    printf("pspEmuCoreMemMemInvAccess: enmMemType=%#x uAddr=%#llx cbAcc=%u i64Val=%#llx\n",
           enmMemType, uAddr, cbAcc, i64Val);
#endif
    if (pspEmuCoreCpIsSctrlMmuEnabled(pThis))
    {
        bool fHandled;
        int rc = pspEmuCoreMmuMap(pThis, uAddr, &fHandled);
        if (   !rc
            && fHandled)
            return true;

        PPSPCORECPBANK pCpBank = pspEmuCoreCpGetBank(pThis);
        pCpBank->u32RegDfsr = 0x5; /* Section translation fault. */
        pCpBank->u32RegDfar = (PSPADDR)uAddr;

        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_CORE,
                                "pspEmuCoreMemMemInvAccess: PC=%#x cbAcc=%u i64Val=%#lld rc=%d fHandled=%u",
                                (PSPADDR)uAddr, cbAcc, i64Val, rc, fHandled);
        PSPEmuCoreStateDump(pThis, PSPEMU_CORE_STATE_DUMP_F_DEFAULT, 0 /*cInsns*/);
    }
    else
    {
        /* Map in a region lazily. */
        PPSPCOREMEMREGION pMemRegion = pspEmuCoreMemRegionFindByAddr(pThis, uAddr, NULL /*ppPrevRegion*/);
        if (   pMemRegion
            && !pMemRegion->fMapped)
        {
            int rc = pspEmuCoreMemRegionMap(pThis, pMemRegion);
            if (!rc)
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
 * @param   enmCoreMode         New processor mode to switch to.
 * @param   idxExcpVecTbl       Index in the exception vector table to jump to.
 * @param   PspAddrPcOld        The PC value when the exception was raised.
 * @param   fUseMVBar           Flag whether to use the MVBAR register instead of the standard VBAR one.
 */
static int pspEmuCoreExcpInject(PPSPCOREINT pThis, PSPCOREMODE enmCoreMode, uint32_t idxExcpVecTbl, PSPADDR PspAddrPcOld,
                                bool fUseMVBar)
{
    uint32_t uCpsrOld = 0;

    uc_err rcUc = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_CPSR, &uCpsrOld);

    /* Set new mode. */
    //printf("pspEmuCoreExcpInject: Switching from mode %s to %s\n", pspEmuCoreModeToStr(pThis->enmCoreMode),
    //       pspEmuCoreModeToStr(enmCoreMode));
    pThis->enmCoreMode = enmCoreMode;
    uint32_t uMode = pspEmuCoreModeToCpsr(enmCoreMode);
    uint32_t uCpsr = (uCpsrOld & ~0x1f) | uMode | BIT(7); /* IRQs are always disabled. */
    pThis->u32RegCpsr = uCpsr;
    if (enmCoreMode == PSPCOREMODE_MON)
    {
        int rc = pspEmuCoreMmuSetupTeardown(pThis);
        if (STS_FAILURE(rc))
            printf("MMU failed during world switch %d\n", rc);
    }
    if (rcUc == UC_ERR_OK)
        rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_CPSR, &uCpsr);
    if (rcUc == UC_ERR_OK)
        rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_SPSR, &uCpsrOld); /* Save CPSR into SPSR after switching modes. */
    if (rcUc == UC_ERR_OK)
        rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_LR, &PspAddrPcOld); /* PC is advanced already. */

    PCPSPCORECPBANK pCpBank = pspEmuCoreCpGetBank(pThis);
    uint32_t u32VBar = fUseMVBar ? pCpBank->u32RegMVBar : pCpBank->u32RegVBar;
    PSPADDR PspAddrPc = u32VBar + idxExcpVecTbl * sizeof(uint32_t); /* Switches to ARM mode. */

    if (rcUc == UC_ERR_OK)
        rcUc = uc_reg_write(pThis->pUcEngine, UC_ARM_REG_PC, &PspAddrPc);
    if (rcUc == UC_ERR_OK)
        pThis->PspAddrExecNext = PspAddrPc;

    return pspEmuCoreErrConvertFromUcErr(rcUc);
}


/**
 * Handles the currently pending exception.
 *
 * @returns Status code.
 * @param   pThis                   The PSP core instance.
 * @param   PspAddrPc               PC following the one causing the exception.
 * @param   fThumb                  Flag whether the CPU is executing in thumb mode.
 */
static int pspEmuCoreExcpHandle(PPSPCOREINT pThis, PSPADDR PspAddrPc, bool fThumb)
{
    int rc = STS_INF_SUCCESS;

    if (pThis->enmExcpPending == PSPCOREEXCP_SWI)
    {
        /* Handle any SVC injections before passing control to any supervisor code. */
        bool fSwitchToSvc = true;
        rc = pspEmuCoreSvcBefore(pThis, PspAddrPc, fThumb, &fSwitchToSvc);
        if (STS_SUCCESS(rc))
        {
            if (fSwitchToSvc) /** @todo Set temporary breakpoint to call SVC injection handlers afterwards. */
                rc = pspEmuCoreExcpInject(pThis, PSPCOREMODE_SVC, 0x2, PspAddrPc, false /*fUseMVBar*/);
            else
            {
                pspEmuCoreSvcAfter(pThis);

                /* Return to the caller. */
                PspAddrPc |= fThumb ? 1 : 0;
                pThis->PspAddrExecNext = PspAddrPc;
            }
        }
    }
    else if (pThis->enmExcpPending == PSPCOREEXCP_SMC)
    {
        /* Handle any SMC injections before passing control to any monitor code. */
        bool fSwitchToSmc = true;
        rc = pspEmuCoreSmcBefore(pThis, PspAddrPc, fThumb, &fSwitchToSmc);
        if (STS_SUCCESS(rc))
        {
            if (fSwitchToSmc) /** @todo Set temporary breakpoint to call SVC injection handlers afterwards. */
                rc = pspEmuCoreExcpInject(pThis, PSPCOREMODE_MON, 0x2, PspAddrPc, true /*fUseMVBar*/);
            else
            {
                pspEmuCoreSmcAfter(pThis);

                /* Return to the caller. */
                PspAddrPc |= fThumb ? 1 : 0;
                pThis->PspAddrExecNext = PspAddrPc;
            }
        }
    }
    else if (pThis->enmExcpPending == PSPCOREEXCP_IRQ)
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE, "IRQ exception");
        rc = pspEmuCoreExcpInject(pThis, PSPCOREMODE_IRQ, 0x6, PspAddrPc + 4, false /*fUseMVBar*/);
    }

    pThis->enmExcpPending = PSPCOREEXCP_NONE;
    return rc;
}


const char *PSPEmuCoreModeToStr(PSPCOREMODE enmCoreMode)
{
    return pspEmuCoreModeToStr(enmCoreMode);
}


int PSPEmuCoreCreate(PPSPCORE phCore)
{
    int rc = 0;
    PPSPCOREINT pThis = (PPSPCOREINT)calloc(1, sizeof(*pThis));

    if (pThis)
    {
        uc_err err;

        pThis->pTraceHooksHead       = NULL;
        pThis->pMemRegionsHead       = NULL;
        pThis->pSvcReg               = NULL;
        pThis->pvSvcUser             = NULL;
        pThis->fExecStop             = false;
        pThis->enmCoreMode           = PSPCOREMODE_SVC;
        pThis->enmExcpPending        = PSPCOREEXCP_NONE;
        pThis->hUcHookSvcAfter       = 0;
        pThis->hUcHookCpWrite        = 0;
        pThis->hUcHookCpRead         = 0;
        pThis->fMmuChanged           = false;
        pThis->fMmuSecure            = true;
        pThis->fMmuEnabled           = false;
        pThis->pMmuMappingsHead      = NULL;
        pThis->pMmuPgTblTrackingHead = NULL;
        pThis->u32RegCpsr            = 0;
        pThis->Cp15.u32RegScr        = 0;
        memset(&pThis->Cp15.aBankedRegs[0], 0, sizeof(pThis->Cp15.aBankedRegs));

        /* Initialize unicorn engine in ARM mode. */
        err = uc_open(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_ARM_NO_MMU, &pThis->pUcEngine);
        if (!err)
        {
            if (!rc)
            {
                err = uc_hook_add(pThis->pUcEngine, &pThis->pUcHookIntr, UC_HOOK_INTR, (void *)(uintptr_t)pspEmuCoreExcpWrapper, pThis, 1, 0);
                if (!err)
                    err = uc_hook_add(pThis->pUcEngine, &pThis->hUcHookCpWrite, UC_HOOK_ARM_CP_WRITE, (void *)(uintptr_t)pspEmuCoreCpWriteWrapper, pThis, 1, 0);
                if (!err)
                    err = uc_hook_add(pThis->pUcEngine, &pThis->hUcHookCpRead, UC_HOOK_ARM_CP_READ, (void *)(uintptr_t)pspEmuCoreCpReadWrapper, pThis, 1, 0);
                if (!err)
                    err = uc_hook_add(pThis->pUcEngine, &pThis->hUcHookCpsrChange, UC_HOOK_ARM_CPSR_WRITE, (void *)(uintptr_t)pspEmuCoreCpsrChangeWrapper, pThis, 1, 0);
                if (!err)
                    err = uc_hook_add(pThis->pUcEngine, &pThis->hUcInvMemAcc, UC_HOOK_MEM_INVALID, (void *)(uintptr_t)pspEmuCoreMemMemInvAccess, pThis, 1, 0);
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

        free(pThis);
    }
    else
        rc = -1;

    return rc;
}

void PSPEmuCoreDestroy(PSPCORE hCore)
{
    PPSPCOREINT pThis = hCore;

    /* Unmap all memory regions. */
    PPSPCOREMEMREGION pMemCur = pThis->pMemRegionsHead;
    while (pMemCur)
    {
        PPSPCOREMEMREGION pFree = pMemCur;

        pMemCur = pMemCur->pNext;
        uc_err rcUc = uc_mem_unmap(pThis->pUcEngine, pFree->PspAddrStart, pFree->cbRegion);
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

    pThis->pMemRegionsHead = NULL;
    uc_free(pThis->pUcCtxReset);
    uc_close(pThis->pUcEngine);
    free(pThis);
}

int PSPEmuCoreMemWrite(PSPCORE hCore, PSPADDR AddrPspWrite, const void *pvData, size_t cbData)
{
    PPSPCOREINT pThis = hCore;

    /*
     * Walk each region and act upon the type there, as soon as an unmapped address is encountered
     * we stop with an error.
     */
    int rc = 0;
    const uint8_t *pbData = (const uint8_t *)pvData;
    while (   cbData
           && !rc)
    {
        PPSPCOREMEMREGION pRegion = pspEmuCoreMemRegionFindByAddr(pThis, AddrPspWrite, NULL /*ppPrev*/);
        if (pRegion)
        {
            PSPADDR offStart = AddrPspWrite - pRegion->PspAddrStart;
            size_t cbThisWrite = MIN(cbData, pRegion->cbRegion - offStart);

            if (!pRegion->fMmio)
            {
                /* Just memcpy into the backing memory. */
                memcpy((uint8_t *)pRegion->u.Ram.pvBacking + offStart, pbData, cbThisWrite);
            }
            else
            {
                /** @todo Handle ourselves. */
                uc_err rcUc = uc_mem_write(pThis->pUcEngine, AddrPspWrite, pbData, cbThisWrite);
                if (rcUc != UC_ERR_OK)
                    rc = pspEmuCoreErrConvertFromUcErr(rcUc);
            }

            AddrPspWrite += cbThisWrite;
            pbData       += cbThisWrite;
            cbData       -= cbThisWrite;
        }
        else
            rc = -1;
    }

    return rc;
}

int PSPEmuCoreMemRead(PSPCORE hCore, PSPADDR AddrPspRead, void *pvDst, size_t cbDst)
{
    PPSPCOREINT pThis = hCore;

    /*
     * Walk each region and act upon the type there, as soon as an unmapped address is encountered
     * we stop with an error.
     */
    int rc = 0;
    uint8_t *pbDst = (uint8_t *)pvDst;
    while (   cbDst
           && !rc)
    {
        PPSPCOREMEMREGION pRegion = pspEmuCoreMemRegionFindByAddr(pThis, AddrPspRead, NULL /*ppPrev*/);
        if (pRegion)
        {
            PSPADDR offStart = AddrPspRead - pRegion->PspAddrStart;
            size_t cbThisRead = MIN(cbDst, pRegion->cbRegion - offStart);

            if (!pRegion->fMmio)
            {
                /* Just memcpy into the backing memory. */
                memcpy(pbDst, (const uint8_t *)pRegion->u.Ram.pvBacking + offStart, cbThisRead);
            }
            else
            {
                /** @todo Handle ourselves. */
                uc_err rcUc = uc_mem_read(pThis->pUcEngine, AddrPspRead, pbDst, cbDst);
                if (rcUc != UC_ERR_OK)
                    rc = pspEmuCoreErrConvertFromUcErr(rcUc);
            }

            AddrPspRead += cbThisRead;
            pbDst       += cbThisRead;
            cbDst       -= cbThisRead;
        }
        else
            rc = -1;
    }

    return rc;
}

int PSPEmuCoreMemWriteVirt(PSPCORE hCore, PSPVADDR AddrPspVWrite, const void *pvData, size_t cbData)
{
    PPSPCOREINT pThis = hCore;
    int rc = STS_INF_SUCCESS;

    if (!pspEmuCoreCpIsSctrlMmuEnabled(pThis)) /* No MMU enabled means virtual address equals physical one. */
        rc = PSPEmuCoreMemWrite(hCore, AddrPspVWrite, pvData, cbData);
    else
    {
        const uint8_t *pbSrc = (const uint8_t *)pvData;
        while (   cbData
               && STS_SUCCESS(rc))
        {
            PSPPADDR PspPAddr;
            size_t cbThisWrite;
            rc = pspEmuCoreMmuPAddrQueryFromVAddr(pThis, AddrPspVWrite, &PspPAddr, &cbThisWrite, NULL /*penmPgTblWalk*/);
            if (STS_SUCCESS(rc))
            {
                cbThisWrite = MIN(cbThisWrite, cbData);
                rc = PSPEmuCoreMemWrite(hCore, PspPAddr, pbSrc, cbThisWrite);

                pbSrc         += cbThisWrite;
                cbData        -= cbThisWrite;
                AddrPspVWrite += cbThisWrite;
            }
        }
    }

    return rc;
}

int PSPEmuCoreMemReadVirt(PSPCORE hCore, PSPVADDR AddrPspVRead, void *pvDst, size_t cbDst)
{
    PPSPCOREINT pThis = hCore;
    int rc = STS_INF_SUCCESS;

    if (!pspEmuCoreCpIsSctrlMmuEnabled(pThis)) /* No MMU enabled means virtual address equals physical one. */
        rc = PSPEmuCoreMemRead(hCore, AddrPspVRead, pvDst, cbDst);
    else
    {
        uint8_t *pbDst = (uint8_t *)pvDst;
        while (   cbDst
               && STS_SUCCESS(rc))
        {
            PSPPADDR PspPAddr;
            size_t cbThisRead;
            rc = pspEmuCoreMmuPAddrQueryFromVAddr(pThis, AddrPspVRead, &PspPAddr, &cbThisRead, NULL /*penmPgTblWalk*/);
            if (STS_SUCCESS(rc))
            {
                cbThisRead = MIN(cbThisRead, cbDst);
                rc = PSPEmuCoreMemRead(hCore, PspPAddr, pbDst, cbThisRead);

                pbDst        += cbThisRead;
                cbDst        -= cbThisRead;
                AddrPspVRead += cbThisRead;
            }
        }
    }

    return rc;
}

int PSPEmuCoreMemRegionAdd(PSPCORE hCore, PSPADDR AddrStart, size_t cbRegion, uint32_t fProt,
                           void *pvBacking)
{
    PPSPCOREINT pThis = hCore;

    /* Don't allow without backing. */
    if (!pvBacking)
        return -1;

    /* Create a new RAM backed region. */
    int rc = 0;
    PPSPCOREMEMREGION pRegion = (PPSPCOREMEMREGION)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->PspAddrStart    = AddrStart;
        pRegion->cbRegion        = cbRegion;
        pRegion->pPspCore        = pThis;
        pRegion->fMmio           = false;
        pRegion->fMapped         = false;
        pRegion->u.Ram.pvBacking = pvBacking;
        pRegion->u.Ram.fProt     = fProt;

        rc = pspEmuCoreMemRegionInsert(pThis, pRegion);
        if (!rc)
            return 0;

        free(pRegion);
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuCoreMemRegionRemove(PSPCORE hCore, PSPADDR AddrStart, size_t cbRegion)
{
    PPSPCOREINT pThis = hCore;

    /* Clear all mappings if MMU is enabled and start from scratch. */
    int rc = 0;
    if (pspEmuCoreCpIsSctrlMmuEnabled(pThis))
        rc = pspEmuCoreMmuMappingsClear(pThis);

    if (!rc)
    {
        PPSPCOREMEMREGION pRegion = pspEmuCoreMemRegionFindAndUnlinkByAddr(pThis, AddrStart, cbRegion);
        if (pRegion)
        {
            if (!pspEmuCoreCpIsSctrlMmuEnabled(pThis))
            {
                uc_err rcUc = uc_mem_unmap(pThis->pUcEngine, AddrStart, cbRegion);
                /** @todo assert(rcUc == UC_ERR_OK) */
            }
            free(pRegion);
        }
        else
            rc = -1;
    }

    return rc;
}

int PSPEmuCoreSvcInjectSet(PSPCORE hCore, PCPSPCORESVMCREG pSvcReg, void *pvUser)
{
    PPSPCOREINT pThis = hCore;

    pThis->pSvcReg   = pSvcReg;
    pThis->pvSvcUser = pvUser;
    return 0;
}

int PSPEmuCoreSmcInjectSet(PSPCORE hCore, PCPSPCORESVMCREG pSmcReg, void *pvUser)
{
    PPSPCOREINT pThis = hCore;

    pThis->pSmcReg   = pSmcReg;
    pThis->pvSmcUser = pvUser;
    return STS_INF_SUCCESS;
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

int PSPEmuCoreExecRun(PSPCORE hCore, uint32_t fFlags, uint32_t cInsnExec, uint32_t msExec)
{
    PPSPCOREINT pThis = hCore;

    int rc = 0;

    if (!cInsnExec)
        cInsnExec = UINT32_MAX;
    if (!msExec)
        msExec = 1;

    pThis->fExecStop = false;

    bool fSingleStep = fFlags & PSPEMU_CORE_EXEC_F_DUMP_CORE_STATE ? true : false;
    while (!rc && cInsnExec && msExec && !pThis->fExecStop)
    {
        uint64_t usUcExec = msExec == PSPEMU_CORE_EXEC_INDEFINITE ? 0 : (uint64_t)msExec * 1000;
        uc_err rcUc = uc_emu_start(pThis->pUcEngine, pThis->PspAddrExecNext, 0xffffffff, usUcExec, fSingleStep ? 1 : cInsnExec);
        if (rcUc == UC_ERR_OK)
        {
            cInsnExec--; /* Executed at least one instruction. */

            /* Query the PC and execution mode. */
            uint32_t uPc = 0;
            bool     fThumb = false;
            bool     fCont = true;
            size_t   ucCpuMode = 0;
            uc_err rcUc2 = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_PC, &uPc);
            if (rcUc2 == UC_ERR_OK)
                rcUc2 = uc_query(pThis->pUcEngine, UC_QUERY_MODE, &ucCpuMode);

            fThumb = (ucCpuMode & UC_MODE_THUMB) ? true : false;

            if (rcUc2 == UC_ERR_OK)
            {
                if (pThis->enmExcpPending != PSPCOREEXCP_NONE)
                {
                    rc = pspEmuCoreExcpHandle(pThis, uPc, fThumb);
                    fCont = false;
                }

                if (pThis->fMmuChanged)
                {
                    rc = pspEmuCoreMmuSetupTeardown(pThis);
                    if (STS_SUCCESS(rc))
                    {
                        uPc |= fThumb ? 1 : 0;
                        pThis->PspAddrExecNext = (PSPADDR)uPc;
                        pThis->fMmuChanged = false;
                    }
                }
                else if (pspEmuCoreInsnIsWfi(pThis, uPc, fThumb))
                {
                    if (pThis->pfnWfiReached)
                    {
                        pspEmuCoreIrqCheckAndInject(pThis, uPc, true /*fWait*/);
                        if (pThis->enmExcpPending != PSPCOREEXCP_NONE)
                        {
                            rc = pspEmuCoreExcpHandle(pThis, uPc, fThumb);
                            fCont = false;
                        }
                        else
                        {
                            uPc |= fThumb ? 1 : 0;
                            pThis->PspAddrExecNext = (PSPADDR)uPc;
                        }
                    }
                    else
                    {
                        rc = STS_INF_PSP_EMU_CORE_INSN_WFI_REACHED;
                        break;
                    }
                }
                else if (fCont)
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
        else if (rcUc == UC_ERR_FETCH_PROT || rcUc == UC_ERR_FETCH_UNMAPPED)
        {
            /* Cause an abort exception. */
            uint32_t uPc = 0;
            uc_err rcUc2 = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_PC, &uPc);
            if (rcUc2 == UC_ERR_OK)
            {
                printf("PREFETCH ABORT on PC %#x (+8 = %#x)\n", uPc, uPc + 8);
                rc = pspEmuCoreExcpInject(pThis, PSPCOREMODE_ABRT, 0x03, uPc + 8, false /*fUseMVBar*/);
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
        }
        else if (rcUc == UC_ERR_WRITE_UNMAPPED || rcUc == UC_ERR_READ_UNMAPPED)
        {
            /* Cause a data abort exception. */
            uint32_t uPc = 0;
            uc_err rcUc2 = uc_reg_read(pThis->pUcEngine, UC_ARM_REG_PC, &uPc);
            if (rcUc2 == UC_ERR_OK)
            {
                printf("DATA ABORT on PC %#x (+8 = %#x)\n", uPc, uPc + 8);
                rc = pspEmuCoreExcpInject(pThis, PSPCOREMODE_ABRT, 0x04, uPc + 8, false /*fUseMVBar*/);

                PSPEmuCoreStateDump(pThis, PSPEMU_CORE_STATE_DUMP_F_DEFAULT, 0 /*cInsns*/);
            }
            else
                rc = pspEmuCoreErrConvertFromUcErr(rcUc2);
        }
        else if (rcUc == UC_ERR_TIMEOUT)
            break;
        else
            rc = pspEmuCoreErrConvertFromUcErr(rcUc);

        if (fSingleStep)
            PSPEmuCoreStateDump(pThis, PSPEMU_CORE_STATE_DUMP_F_NO_STACK, 1 /*cInsns*/);
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
                            uint32_t fFlags, ARMASID idAsid, PFNPSPCORETRACE pfnTrace, void *pvUser)
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
        pHook->idAsid       = idAsid;
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
    PPSPCOREMEMREGION pRegion = (PPSPCOREMEMREGION)calloc(1, sizeof(*pRegion));
    if (pRegion)
    {
        pRegion->PspAddrStart    = uPspAddrMmioStart;
        pRegion->cbRegion        = cbMmio;
        pRegion->pPspCore        = pThis;
        pRegion->fMmio           = true;
        pRegion->fMapped         = false;
        pRegion->u.Mmio.pfnRead  = pfnRead;
        pRegion->u.Mmio.pfnWrite = pfnWrite;
        pRegion->u.Mmio.pvUser   = pvUser;

        rc = pspEmuCoreMemRegionInsert(pThis, pRegion);
        if (!rc)
            return 0;

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

    /* Clear all mappings if MMU is enabled and start from scratch. */
    if (pspEmuCoreCpIsSctrlMmuEnabled(pThis))
        rc = pspEmuCoreMmuMappingsClear(pThis);

    /* Search for the right hook and deregister. */
    PPSPCOREMEMREGION pRegion = pspEmuCoreMemRegionFindAndUnlinkByAddr(pThis, uPspAddrMmioStart, cbMmio);
    if (pRegion)
    {
        if (!pspEmuCoreCpIsSctrlMmuEnabled(pThis))
        {
            uc_err rcUc = uc_mem_unmap(pThis->pUcEngine, uPspAddrMmioStart, cbMmio);
            /** @todo assert(rcUc == UC_ERR_OK) */
        }
        free(pRegion);
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

int PSPEmuCoreIrqSet(PSPCORE hCore, bool fAssert)
{
    PPSPCOREINT pThis = hCore;

    pThis->fIrq = fAssert;
    return STS_INF_SUCCESS;
}

int PSPEmuCoreFiqSet(PSPCORE hCore, bool fAssert)
{
    PPSPCOREINT pThis = hCore;

    pThis->fFiq = fAssert;
    return STS_INF_SUCCESS;
}

void PSPEmuCoreStateDump(PSPCORE hCore, uint32_t fFlags, uint32_t cInsns)
{
    PPSPCOREINT pThis = hCore;

    uint32_t au32Reg[ELEMENTS(g_aenmRegQueryBatch) + 1];
    int rc = PSPEmuCoreQueryRegBatch(hCore, &g_aenmRegQueryBatch[0], ELEMENTS(g_aenmRegQueryBatch), &au32Reg[1]);
    if (!rc)
    {
        /* Dump a few instructions. */
        uint8_t abInsn[5 * sizeof(uint32_t)];
        char achBuf[_1K];
        int rc = PSPEmuCoreMemReadVirt(hCore, au32Reg[PSPCOREREG_PC], &abInsn[0], sizeof(abInsn));
        if (!rc)
        {
            size_t ucCpuMode = 0;

            uc_err rcUc = uc_query(pThis->pUcEngine, UC_QUERY_MODE, &ucCpuMode);
            if (rcUc == UC_ERR_OK)
                rc = PSPEmuDisasm(&achBuf[0], sizeof(achBuf), cInsns, &abInsn[0], sizeof(abInsn), au32Reg[PSPCOREREG_PC], (ucCpuMode & UC_MODE_THUMB) ? true : false);
            else
                fprintf(stderr, "Querying CPU mode failed with %d\n", pspEmuCoreErrConvertFromUcErr(rcUc));
        }

        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE,
                "R0  > 0x%08x | R1  > 0x%08x | R2 > 0x%08x | R3 > 0x%08x\n"
                "R4  > 0x%08x | R5  > 0x%08x | R6 > 0x%08x | R7 > 0x%08x\n"
                "R8  > 0x%08x | R9  > 0x%08x | R10> 0x%08x | R11> 0x%08x\n"
                "R12 > 0x%08x | SP  > 0x%08x | LR > 0x%08x | PC > 0x%08x\n"
                "CPSR> 0x%08x | SPSR> 0x%08x\n"
                "Disasm:\n"
                "%s",
                au32Reg[PSPCOREREG_R0],   au32Reg[PSPCOREREG_R1], au32Reg[PSPCOREREG_R2],  au32Reg[PSPCOREREG_R3],
                au32Reg[PSPCOREREG_R4],   au32Reg[PSPCOREREG_R5], au32Reg[PSPCOREREG_R6],  au32Reg[PSPCOREREG_R7],
                au32Reg[PSPCOREREG_R8],   au32Reg[PSPCOREREG_R9], au32Reg[PSPCOREREG_R10], au32Reg[PSPCOREREG_R11],
                au32Reg[PSPCOREREG_R12],  au32Reg[PSPCOREREG_SP], au32Reg[PSPCOREREG_LR],  au32Reg[PSPCOREREG_PC],
                au32Reg[PSPCOREREG_CPSR], au32Reg[PSPCOREREG_SPSR], &achBuf[0]);

        if (!(fFlags & PSPEMU_CORE_STATE_DUMP_F_NO_STACK))
        {
            /* Dump last 0x20 bytes of stack memory */
            uint32_t au32Stack[8];
            rc = PSPEmuCoreMemReadVirt(hCore, au32Reg[PSPCOREREG_SP], &au32Stack[0], sizeof(au32Stack));
            if (!rc)
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CORE,
                       "Stack:\n"
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
    }
    else
        printf("Querying the register set failed with %d\n", rc);
}

int PSPEmuCoreQueryState(PSPCORE hCore, PPSPCORESTATE pState)
{
    PPSPCOREINT pThis = hCore;

    pState->enmCoreMode  = pThis->enmCoreMode;
    pState->fSecureWorld = !(pThis->Cp15.u32RegScr & BIT(0));
    pState->fMmuEnabled  = pspEmuCoreCpIsSctrlMmuEnabled(pThis);

    int rc = pspEmuCoreMmuPgTblQueryRoot(pThis, &pState->PspPAddrPgTblRoot);
    if (STS_SUCCESS(rc))
    {
        rc = PSPEmuCoreQueryReg(pThis, PSPCOREREG_PC, &pState->PspAddrPc);
        if (STS_SUCCESS(rc))
        {
            rc = PSPEmuCoreQueryReg(pThis, PSPCOREREG_LR, &pState->PspAddrLr);
            if (STS_SUCCESS(rc))
            {
                uint32_t u32RegCpsr;
                rc = PSPEmuCoreQueryReg(pThis, PSPCOREREG_CPSR, &u32RegCpsr);
                if (STS_SUCCESS(rc))
                {
                    pState->fIrqMasked = !!(u32RegCpsr & BIT(7));
                    pState->fFiqMasked = !!(u32RegCpsr & BIT(6));
                }
            }
        }
    }

    return rc;
}

int PSPEmuCoreQueryPAddrFromVAddr(PSPCORE hCore, PSPVADDR PspVAddr, PSPPADDR *pPspPAddr,
                                  PPSPCOREPGTBLWALKSTS penmPgTblWalk)
{
    PPSPCOREINT pThis = hCore;
    int rc = STS_INF_SUCCESS;

    if (!pspEmuCoreCpIsSctrlMmuEnabled(pThis))
    {
        *pPspPAddr = PspVAddr;
        if (penmPgTblWalk)
            *penmPgTblWalk = PSPCOREPGTBLWALKSTS_NO_MMU;
    }
    else
    {
        size_t cbRegion = 0;
        rc = pspEmuCoreMmuPAddrQueryFromVAddr(pThis, PspVAddr, pPspPAddr, &cbRegion, penmPgTblWalk);
    }

    return rc;
}

