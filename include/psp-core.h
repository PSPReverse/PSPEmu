/** @file
 * PSP Emulator - API for a single emulated PSP core
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
#ifndef __psp_core_h
#define __psp_core_h

#include <common/types.h>

#include <stdint.h>
#include <stddef.h>

/** Opaque PSP emulation core handle. */
typedef struct PSPCOREINT *PSPCORE;
/** Pointer to a PSP emulation core handle. */
typedef PSPCORE *PPSPCORE;


/** Trace hook handler. */
typedef void (FNPSPCORETRACE)(PSPCORE hCore, PSPADDR uPspAddr, uint32_t cbInsn, void *pvUser);
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
 * Core emulation mode.
 */
typedef enum PSPCOREMODE
{
    /** Invalid mode, do not use. */
    PSPCOREMODE_INVALID = 0,
    /** A single usermode application is executed and the svc interface is emulated. */
    PSPCOREMODE_APP,
    /** Full system emulation mode with the supervisor code being executed as well. */
    PSPCOREMODE_SYSTEM,
    /** Full system emulation mode with the supervisor and on chip bootloader code being executed as well. */
    PSPCOREMODE_SYSTEM_ON_CHIP_BL
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
    PSPCOREREG_SPSR
} PSPCOREREG;


/** Callback is triggered when an instruction is executed from the specified range. */
#define PSPEMU_CORE_TRACE_F_EXEC                BIT(0)
/** Callback is triggered when data is read from the specified range. */
#define PSPEMU_CORE_TRACE_F_READ                BIT(1)
/** Callback is triggered when data is written the specified range. */
#define PSPEMU_CORE_TRACE_F_WRITE               BIT(2)


/**
 * Overriden SVC handler.
 *
 * @returns true when the SVC call should be considered handled and execution should return to the caller
 *          or false to forward the call to the supervisor code.
 * @param   hCore                   The PSP core handle causing the SVC call.
 * @param   idxSyscall              The syscall being called.
 * @param   fFlags                  Flags for this call, see PSPEMU_CORE_SVC_F_XXX.
 * @param   pvUser                  Opaque user data passed when the handler was registered.
 */
typedef bool (FNPSPCORESVCHANDLER)(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
/** Syscall handler pointer. */
typedef FNPSPCORESVCHANDLER *PFNPSPCORESVCHANDLER;


/**
 * Syscall descriptor.
 */
typedef struct PSPCORESVCDESC
{
    /** Syscall name (used for tracing/logging). */
    const char                  *pszName;
    /** Pointer to the SVC handler. */
    PFNPSPCORESVCHANDLER        pfnSvcHnd;
    /** Flags controlling when this handler is called, see PSPEMU_CORE_SVC_F_XXX. */
    uint32_t                    fFlags;
} PSPCORESVCDESC;
/** Pointer to a syscall descriptor. */
typedef PSPCORESVCDESC *PPSPCORESVCDESC;
/** Pointer to a const syscall descriptor. */
typedef const PSPCORESVCDESC *PCPSPCORESVCDESC;


/** The syscall handler is invoked before control is passed to the supervisor code. */
#define PSPEMU_CORE_SVC_F_BEFORE                BIT(0)
/** The syscall handler is invoked after control was passed to the supervisor code and is about to return to the caller.
 * The return value of the handler is of no interest. */
#define PSPEMU_CORE_SVC_F_AFTER                 BIT(1)


/**
 * Syscall injection registration record.
 */
typedef struct PSPCORESVCREG
{
    /** Global handler which is called regardless of the syscall being executed. */
    PSPCORESVCDESC              GlobalSvc;
    /** Number of per syscall descriptors. */
    uint32_t                    cSvcDescs;
    /** Pointer to an array of svc descriptors. The number of entries indicates the maximum
     * of overriden syscalls. To override only particular syscalls initialize the descriptors
     * inbetween with NULL entries. */
    PCPSPCORESVCDESC            paSvcDescs;
} PSPCORESVCREG;
/** Pointer to a syscall injection registration record. */
typedef PSPCORESVCREG *PPSPCORESVCREG;
/** Pointer to a const syscall injection registration record. */
typedef const PSPCORESVCREG *PCPSPCORESVCREG;


/**
 * Creates a new emulated PSP core.
 *
 * @returns Status code.
 * @param   phCore                  Where to store the core handle on success.
 * @param   enmMode                 The emulation mode the core operates in.
 */
int PSPEmuCoreCreate(PPSPCORE phCore, PSPCOREMODE enmMode);

/**
 * Destroys a given PSP core.
 *
 * @returns nothing.
 * @param   hCore                   The PSP core handle to destroy.
 */
void PSPEmuCoreDestroy(PSPCORE hCore);

/**
 * Sets the CCD ID the given PSP core is part of.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   idCcd                   The CCD ID to set.
 */
int PSPEmuCoreCcdSet(PSPCORE hCore, uint32_t idCcd);

/**
 * Queries the set CCD of the given PSP core handle.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   pidCcd                  Where to store the CCD on success.
 */
int PSPEmuCoreQueryCcd(PSPCORE hCore, uint32_t *pidCcd);

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
 * Adds a region of memory not initially backed by memory on the original PSP (used
 * for the emulated PSP syscall interface to initialize the stack mapping).
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   AddrStart               The start address of the region.
 * @param   cbRegion                Size of the region in bytes.
 */
int PSPEmuCoreMemAddRegion(PSPCORE hCore, PSPADDR AddrStart, size_t cbRegion);

/**
 * Sets the SVC injection to use for any executed svc instructions.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   pSvcReg                 The SVC injection registration record, use NULL to deregister.
 * @param   pvUser                  Opaque user data to pass to the svc handlers.
 */
int PSPEmuCoreSvcInjectSet(PSPCORE hCore, PCPSPCORESVCREG pSvcReg, void *pvUser);

/**
 * Initializes the on chip bootloader ROM region with the given data.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   pvOnChipBl              The on chip bootloader memory.
 * @param   cbOnChipBl              Size of the on chip bootloader.
 */
int PSPEmuCoreSetOnChipBl(PSPCORE hCore, void *pvOnChipBl, size_t cbOnChipBl);

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
 * @param   cInsnExec               Number of insturctions to execute.
 * @param   msExec                  Number of milliseconds to execute instructions.
 */
int PSPEmuCoreExecRun(PSPCORE hCore, uint32_t cInsnExec, uint32_t msExec);

/**
 * Stop emulation of the code.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 */
int PSPEmuCoreExecStop(PSPCORE hCore);

/**
 * Registers a new trace callback triggered whenever an instruction in the given range is executed.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   uPspAddrStart           Start address of the region to trace.
 * @param   uPspAddrEnd             End address of the region to trace (inclusive).
 * @param   fFlags                  Flags controlling the trigger conditions, see PSPEMU_CORE_TRACE_F_XXX.
 * @param   pfnTrace                The trace callback to execute.
 * @param   pvUser                  Opaque user data passed to the trace callback.
 */
int PSPEmuCoreTraceRegister(PSPCORE hCore, PSPADDR uPspAddrStart, PSPADDR uPspAddrEnd,
                            uint32_t fFlags, PFNPSPCORETRACE pfnTrace, void *pvUser);

/**
 * Deregisters a previously registered trace hook.
 *
 * @returns Status code.
 * @param   hCore                   The PSP core handle.
 * @param   uPspAddrStart           Start address of the region deregister the trace hook (must match the address during registration).
 * @param   uPspAddrEnd             End address of the region to deregister the trace hook (must match the address during registration).
 */
int PSPEmuCoreTraceDeregister(PSPCORE hCore, PSPADDR uPspAddrStart, PSPADDR uPspAddrEnd);

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
 * Dumps the emulation core state to stdout.
 *
 * @returns nothing.
 * @param   hCore                   The PSP core handle.
 */
void PSPEmuCoreStateDump(PSPCORE hCore);

#endif /* __psp_core_h */
