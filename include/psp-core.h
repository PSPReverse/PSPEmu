/** @file
 * PSP Emulator - API for a single emulated PSP core
 */

/*
 * Copyright (C) 2019-2020 Alexander Eichner <alexander.eichner@campus.tu-berlin.de>
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
#ifndef __psp_core_h
#define __psp_core_h

#include <common/types.h>

#include <stdint.h>
#include <stddef.h>

/** An ARM ASID. */
typedef uint32_t ARMASID;

/** Any ASID. */
#define ARMASID_ANY UINT32_MAX

/** Opaque PSP emulation core handle. */
typedef struct PSPCOREINT *PSPCORE;
/** Pointer to a PSP emulation core handle. */
typedef PSPCORE *PPSPCORE;


/** Opaque PSP trace point handle. */
typedef struct PSPCORETPINT *PSPCORETP;
/** Pointer to a PSP core trace point handle. */
typedef PSPCORETP *PPSPCORETP;


/**
 * Trace hook handler.
 *
 * @returns nothing.
 * @param   hCore                   The core handle triggering the callback.
 * @param   hTp                     The trace point handle this callback is triggered on.
 * @param   fTpFlags                Flag indicating the access triggering the tracepoint, see PSPEMU_CORE_TRACE_F_XXX.
 * @param   uPspAddr                The PSP address triggering (always virtual), for exec trace hooks
 *                                  this is the PC of the instruction. For memory accesses this denotes the
 *                                  memory address being accessed.
 * @param   cb                      The access size, for exec trace hooks this is the size of the instruction.
 *                                  For memory accesses this denotes the size of the memory access being made.
 * @param   pvVal                   Pointer to the value being written for write memory trace hooks, undefined otherwise.
 * @param   pvUser                  Opaque user data passed during trace hook registration.
 */
typedef void (FNPSPCORETRACE)(PSPCORE hCore, PSPCORETP hTp, uint32_t fTpFlags, PSPADDR uPspAddr, uint32_t cb, const void *pvVal, void *pvUser);
/** Trace hook handler pointer. */
typedef FNPSPCORETRACE *PFNPSPCORETRACE;

/** MMIO read handler. */
typedef void (FNPSPCOREMMIOREAD)(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser);
/** MMIO read handler pointer. */
typedef FNPSPCOREMMIOREAD *PFNPSPCOREMMIOREAD;

/** MMIO write handler. */
typedef void (FNPSPCOREMMIOWRITE)(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser);
/** MMIO write handler pointer. */
typedef FNPSPCOREMMIOWRITE *PFNPSPCOREMMIOWRITE;


/**
 * WFI instruction reached callback.
 *
 * @returns Status code.
 * @retval  0 if the emulation core should return execution at the appropriate exception handler.
 * @retval  <n> PSPEmuCoreExecRun() returns with that status code.
 * @param   hCore                   The PSP core handle encountering the WFI instruction.
 * @param   PspAddrPc               Instruction address following the WFI.
 * @param   fFlags                  Flags controlling the behavior.
 * @param   pfIrq                   Where to store whether a IRQ is pending upon return.
 * @param   pfFirq                  Where to store whether a FIRQ is pending upon return.
 * @param   pvUser                  Opaque user data passed during callback registration.
 */
typedef int (FNPSPCOREWFI)(PSPCORE hCore, PSPADDR PspAddrPc, uint32_t fFlags, bool *pfIrq, bool *pfFirq, void *pvUser);
/** Pointer to a WFI reached callback. */
typedef FNPSPCOREWFI *PFNPSPCOREWFI;

/** Just check for a pending interrupt but don't block. */
#define PSPEMU_CORE_WFI_CHECK                   BIT(0)


/**
 * ARM core mode.
 */
typedef enum PSPCOREMODE
{
    /** Invalid mode. */
    PSPCOREMODE_INVALID = 0,
    /** User mode. */
    PSPCOREMODE_USR,
    /** FIQ mode. */
    PSPCOREMODE_FIQ,
    /** IRQ mode. */
    PSPCOREMODE_IRQ,
    /** Supervisor mode. */
    PSPCOREMODE_SVC,
    /** Abort mode. */
    PSPCOREMODE_ABRT,
    /** Undefined instruction mode. */
    PSPCOREMODE_UNDEF,
    /** System mode. */
    PSPCOREMODE_SYS,
    /** Monitor mode. */
    PSPCOREMODE_MON,
    /** 32 bit hack. */
    PSPCOREMODE_32BIT_HACK = 0x7fffffff
} PSPCOREMODE;


/**
 * PSP core register.
 */
typedef enum PSPCOREREG
{
    /** Invalid register, do not use. */
    PSPCOREREG_INVALID = 0,
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
    PSPCOREREG_SPSR,
    PSPCOREREG_LAST = PSPCOREREG_SPSR
} PSPCOREREG;


/**
 * Page table walking status.
 */
typedef enum PSPCOREPGTBLWALKSTS
{
    /** Invalid status, do not use. */
    PSPCOREPGTBLWALKSTS_INVALID = 0,
    /** MMU is disabled virtual address equals physical one. */
    PSPCOREPGTBLWALKSTS_NO_MMU,
    /** Only the L1 table was examined to determine the final address. */
    PSPCOREPGTBLWALKSTS_L1,
    /** A L2 table walk was required. */
    PSPCOREPGTBLWALKSTS_L2,
    /** 32bit hack. */
    PSPCOREPGTBLWALKSTS_32BIT_HACK = 0x7fffffff
} PSPCOREPGTBLWALKSTS;
/** Pointer to a page tabel walking status. */
typedef PSPCOREPGTBLWALKSTS *PPSPCOREPGTBLWALKSTS;


/** Callback is triggered when an instruction is executed from the specified range. */
#define PSPEMU_CORE_TRACE_F_EXEC                BIT(0)
/** Callback is triggered when data is read from the specified range. */
#define PSPEMU_CORE_TRACE_F_READ                BIT(1)
/** Callback is triggered when data is written the specified range. */
#define PSPEMU_CORE_TRACE_F_WRITE               BIT(2)
/** Callback triggers on the basic block instead of the particular instruction for PSPEMU_CORE_TRACE_F_EXEC. */
#define PSPEMU_CORE_TRACE_F_EXEC_BASIC_BLOCK    BIT(3)


/** The mapped memory region has execute permissions. */
#define PSPEMU_CORE_MEM_REGION_PROT_F_EXEC      BIT(0)
/** The mapped memory region has read permissions. */
#define PSPEMU_CORE_MEM_REGION_PROT_F_READ      BIT(1)
/** The mapped memory region has write permissions. */
#define PSPEMU_CORE_MEM_REGION_PROT_F_WRITE     BIT(2)


/** Disables any execution timeouts. */
#define PSPEMU_CORE_EXEC_INDEFINITE             UINT32_MAX
/** Default flags for PSPEmuCoreExecRun(). */
#define PSPEMU_CORE_EXEC_F_DEFAULT              (0)
/** Print CPU state after each instruction. */
#define PSPEMU_CORE_EXEC_F_DUMP_CORE_STATE      BIT(0)


/** Default dump config. */
#define PSPEMU_CORE_STATE_DUMP_F_DEFAULT        (0)
/** Don't output the stack. */
#define PSPEMU_CORE_STATE_DUMP_F_NO_STACK       BIT(0)


/**
 * Overriden SVC/SMC handler.
 *
 * @returns true when the SVC/SMC call should be considered handled and execution should return to the caller
 *          or false to forward the call to the supervisor/monitor code.
 * @param   hCore                   The PSP core handle causing the SVC/SMC call.
 * @param   idxCall                 The immediate encoded in the instruction.
 * @param   fFlags                  Flags for this call, see PSPEMU_CORE_SVMC_F_XXX.
 * @param   pvUser                  Opaque user data passed when the handler was registered.
 */
typedef bool (FNPSPCORESVMCHANDLER)(PSPCORE hCore, uint32_t idxCall, uint32_t fFlags, void *pvUser);
/** SVC/SMC handler pointer. */
typedef FNPSPCORESVMCHANDLER *PFNPSPCORESVMCHANDLER;


/**
 * SVC/SMC descriptor.
 */
typedef struct PSPCORESVMCDESC
{
    /** Syscall name (used for tracing/logging). */
    const char                  *pszName;
    /** Pointer to the SVC handler. */
    PFNPSPCORESVMCHANDLER       pfnSvmcHnd;
    /** Flags controlling when this handler is called, see PSPEMU_CORE_SVMC_F_XXX. */
    uint32_t                    fFlags;
} PSPCORESVMCDESC;
/** Pointer to a syscall descriptor. */
typedef PSPCORESVMCDESC *PPSPCORESVMCDESC;
/** Pointer to a const syscall descriptor. */
typedef const PSPCORESVMCDESC *PCPSPCORESVMCDESC;


/** The SVC/SMC handler is invoked before control is passed to the supervisor/monitor code. */
#define PSPEMU_CORE_SVMC_F_BEFORE               BIT(0)
/** The SVC/SMC handler is invoked after control was passed to the supervisor/monitor code and is about to return to the caller.
 * The return value of the handler is of no interest. */
#define PSPEMU_CORE_SVMC_F_AFTER                BIT(1)


/**
 * SVC/SMC injection registration record.
 */
typedef struct PSPCORESVMCREG
{
    /** Global handler which is called regardless of the call being executed. */
    PSPCORESVMCDESC             GlobalSvmc;
    /** Number of per SVC/SMC descriptors. */
    uint32_t                    cSvmcDescs;
    /** Pointer to an array of SVC/SMC descriptors. The number of entries indicates the maximum
     * of overriden calls. To override only particular calls initialize the descriptors
     * inbetween with NULL entries. */
    PCPSPCORESVMCDESC           paSvmcDescs;
} PSPCORESVMCREG;
/** Pointer to a SVC/SMC injection registration record. */
typedef PSPCORESVMCREG *PPSPCORESVMCREG;
/** Pointer to a const SVC/SMC injection registration record. */
typedef const PSPCORESVMCREG *PCPSPCORESVMCREG;


/**
 * Core state as returned by PSPEmuCoreQueryState().
 */
typedef struct PSPCORESTATE
{
    /** The current CPU mode we are in. */
    PSPCOREMODE                 enmCoreMode;
    /** The current PC value. */
    PSPVADDR                    PspAddrPc;
    /** The current LR value. */
    PSPVADDR                    PspAddrLr;
    /** Flag whether we are in secure world. */
    bool                        fSecureWorld;
    /** Flag whether the MMU is enabled for the current world. */
    bool                        fMmuEnabled;
    /** Flag whether IRQs are masked. */
    bool                        fIrqMasked;
    /** Flag whether FIQs are masked. */
    bool                        fFiqMasked;
    /** The physical PSP address of the page table root if MMU is enabled. */
    PSPPADDR                    PspPAddrPgTblRoot;
} PSPCORESTATE;
/** Pointer to the PSP core state info struct. */
typedef PSPCORESTATE *PPSPCORESTATE;
/** Pointer to a const PSP core state info struct. */
typedef const PSPCORESTATE *PCPSPCORESTATE;


/**
 * Converts the given core mode to a human readable version.
 *
 * @returns Human readable string for the given core mode.
 * @param   enmCoreMode             The core mode.
 */
const char *PSPEmuCoreModeToStr(PSPCOREMODE enmCoreMode);

/**
 * Creates a new emulated PSP core.
 *
 * @returns Status code.
 * @param   phCore                  Where to store the core handle on success.
 */
int PSPEmuCoreCreate(PPSPCORE phCore);

/**
 * Destroys a given PSP core.
 *
 * @returns nothing.
 * @param   hCore                   The PSP core handle to destroy.
 */
void PSPEmuCoreDestroy(PSPCORE hCore);

/**
 * Writes data to the given memory address for the given PSP core.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   AddrPspWrite            The PSP address to write to.
 * @param   pvData                  The data to write.
 * @param   cbData                  Amount of bytes to write.
 */
int PSPEmuCoreMemWrite(PSPCORE hCore, PSPADDR AddrPspWrite, const void *pvData, size_t cbData);

/**
 * Reads data from the given memory address of the given PSP core.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   AddrPspWrite            The PSP address to start reading from.
 * @param   pvDst                   Where to store the read data.
 * @param   cbDst                   Amount of bytes to read.
 */
int PSPEmuCoreMemRead(PSPCORE hCore, PSPADDR AddrPspRead, void *pvDst, size_t cbDst);

/**
 * Writes data to the given virtual memory address for the given PSP core.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   AddrPspVWrite           The virtual PSP address to write to.
 * @param   pvData                  The data to write.
 * @param   cbData                  Amount of bytes to write.
 */
int PSPEmuCoreMemWriteVirt(PSPCORE hCore, PSPVADDR AddrPspVWrite, const void *pvData, size_t cbData);

/**
 * Reads data from the given virtual memory address of the given PSP core.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   AddrPspVWrite           The virtual PSP address to start reading from.
 * @param   pvDst                   Where to store the read data.
 * @param   cbDst                   Amount of bytes to read.
 */
int PSPEmuCoreMemReadVirt(PSPCORE hCore, PSPVADDR AddrPspVRead, void *pvDst, size_t cbDst);

/**
 * Adds a region of memory not initially backed by memory on the original PSP
 * (will be used for executing the TEE stuff located on a secure DRAM region).
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   AddrStart               The start address of the region.
 * @param   cbRegion                Size of the region in bytes.
 * @param   fProt                   Protection flags, see PSPEMU_CORE_MEM_REGION_PROT_F_XXX.
 * @param   pvBacking               THe backing memory, if NULL a default backing is created.
 */
int PSPEmuCoreMemRegionAdd(PSPCORE hCore, PSPADDR AddrStart, size_t cbRegion, uint32_t fProt,
                           void *pvBacking);

/**
 * Removes a previously added memory region.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   AddrStart               The start address of the region.
 * @param   cbRegion                Size of the region in bytes.
 *
 * @note AddrStart and cbRegion must exactly match what was given when the region was added.
 */
int PSPEmuCoreMemRegionRemove(PSPCORE hCore, PSPADDR AddrStart, size_t cbRegion);

/**
 * Sets the SVC injection to use for any executed svc instructions.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   pSvcReg                 The SVC injection registration record, use NULL to deregister.
 * @param   pvUser                  Opaque user data to pass to the svc handlers.
 */
int PSPEmuCoreSvcInjectSet(PSPCORE hCore, PCPSPCORESVMCREG pSvcReg, void *pvUser);

/**
 * Sets the SMC injection to use for any executed smc instructions.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   pSmcReg                 The SMC injection registration record, use NULL to deregister.
 * @param   pvUser                  Opaque user data to pass to the svc handlers.
 */
int PSPEmuCoreSmcInjectSet(PSPCORE hCore, PCPSPCORESVMCREG pSmcReg, void *pvUser);

/**
 * Sets a specific register to a given value.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   enmReg                  The register to set.
 * @param   uVal                    The value to set the register to.
 */
int PSPEmuCoreSetReg(PSPCORE hCore, PSPCOREREG enmReg, uint32_t uVal);

/**
 * Queries the value of a specific register.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   enmReg                  The register to query.
 * @param   puVal                   Where to store the value of the register on success.
 */
int PSPEmuCoreQueryReg(PSPCORE hCore, PSPCOREREG enmReg, uint32_t *puVal);

/**
 * Queries the content of a set of registers.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   paenmReg                Array of registers to query.
 * @param   cRegs                   Number of registers in the array.
 * @param   pauVal                  Where to store the values of the registers on success.
 */
int PSPEmuCoreQueryRegBatch(PSPCORE hCore, const PSPCOREREG *paenmReg, uint32_t cRegs, uint32_t *pauVal);

/**
 * Sets the address to start executing instructions from on the next PSPEmuCoreExecRun() call.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   AddrExecStart           The address to start executing from.
 */
int PSPEmuCoreExecSetStartAddr(PSPCORE hCore, PSPADDR AddrExecStart);

/**
 * Execute a bunch of instructions or until the timespan ran out.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   fFlags                  Combination of PSPEMU_CORE_EXEC_F_XXX
 * @param   cInsnExec               Number of instructions to execute.
 * @param   msExec                  Number of milliseconds to execute instructions,
 *                                  use PSPEMU_CORE_EXEC_INDEFINITE to disable any timeouts.
 */
int PSPEmuCoreExecRun(PSPCORE hCore, uint32_t fFlags, uint32_t cInsnExec, uint32_t msExec);

/**
 * Stop emulation of the code.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 */
int PSPEmuCoreExecStop(PSPCORE hCore);

/**
 * Performs a CPU state reset.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 *
 * @note This doesn't undo any mappings, trace registrations, etc. It merely
 *       resets the register state and PC.
 */
int PSPEmuCoreExecReset(PSPCORE hCore);

/**
 * Registers a new trace callback triggered whenever an instruction in the given range is executed.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   uPspAddrStart           Start address of the region to trace.
 * @param   uPspAddrEnd             End address of the region to trace (inclusive).
 * @param   fFlags                  Flags controlling the trigger conditions, see PSPEMU_CORE_TRACE_F_XXX.
 * @param   idAsid                  The ASID to trigger on, use ARMASID_ANY to not care about the ASID.
 * @param   pfnTrace                The trace callback to execute.
 * @param   pvUser                  Opaque user data passed to the trace callback.
 * @param   phTp                    Where to store the handle to trace point on success.
 */
int PSPEmuCoreTraceRegister(PSPCORE hCore, PSPADDR uPspAddrStart, PSPADDR uPspAddrEnd,
                            uint32_t fFlags, ARMASID idAsid, PFNPSPCORETRACE pfnTrace, void *pvUser,
                            PPSPCORETP phTp);

/**
 * Deregisters a previously registered trace hook.
 *
 * @returns Status code.
 * @param   hTp                     The trace point handle to deregister.
 */
int PSPEmuCoreTraceDeregister(PSPCORETP hTp);

/**
 * Register a new MMIO region with the given read/write handlers.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   uPspAddrMmioStart       The start address of the MMIO region.
 * @param   cbMmio                  Size of the MMIO region in bytes.
 * @param   pfnRead                 Read handler.
 * @param   pfnWrite                Write handler.
 * @param   pvUser                  Opaque user data.
 */
int PSPEmuCoreMmioRegister(PSPCORE hCore, PSPADDR uPspAddrMmioStart, size_t cbMmio,
                           PFNPSPCOREMMIOREAD pfnRead, PFNPSPCOREMMIOWRITE pfnWrite,
                           void *pvUser);

/**
 * Deregisters a previously registered MMIO region.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   uPspAddrMmioStart       The start address of the MMIO region.
 * @param   cbMmio                  Size of the MMIO region in bytes.
 */
int PSPEmuCoreMmioDeregister(PSPCORE hCore, PSPADDR uPspAddrMmioStart, size_t cbMmio);

/**
 * Sets the WFI callback to call whenever a WFI instruction is reached.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   pfnWfiReached           The WFI callback.
 * @param   pvUser                  Opaque user data to pass to the callback.
 */
int PSPEmuCoreWfiSet(PSPCORE hCore, PFNPSPCOREWFI pfnWfiReached, void *pvUser);

/**
 * Signals an IRQ line assert/de-assert change.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   fAssert                 Flag whether the IRQ line is asserted or not.
 */
int PSPEmuCoreIrqSet(PSPCORE hCore, bool fAssert);

/**
 * Signals an FIQ line assert/de-assert change.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   fAssert                 Flag whether the FIQ line is asserted or not.
 */
int PSPEmuCoreFiqSet(PSPCORE hCore, bool fAssert);

/**
 * Dumps the emulation core state to stdout.
 *
 * @returns nothing.
 * @param   hCore                   The PSP core handle.
 * @param   cInsns                  Number of instructions to disassemble, 0 for default.
 * @param   fFlags                  Combination of PSPEMU_CORE_STATE_DUMP_F_XXX.
 */
void PSPEmuCoreStateDump(PSPCORE hCore, uint32_t fFlags, uint32_t cInsns);

/**
 * Queries a subset of the given PSP core state.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   pState                  The state struct to fill.
 */
int PSPEmuCoreQueryState(PSPCORE hCore, PPSPCORESTATE pState);

/**
 * Queries the physical address from the given virtual address.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   PspVAddr                The virtual address to resolve.
 * @param   pPspPAddr               Where to store the physical address on success.
 * @param   penmPgTblWak            Where to store the information about the page table walk, optional.
 */
int PSPEmuCoreQueryPAddrFromVAddr(PSPCORE hCore, PSPVADDR PspVAddr, PSPPADDR *pPspPAddr,
                                  PPSPCOREPGTBLWALKSTS penmPgTblWalk);

#endif /* __psp_core_h */
