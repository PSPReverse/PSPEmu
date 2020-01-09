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
    PSPCOREREG_PC
} PSPCOREREG;


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
int PSPEmuCoreMemWrite(PSPCORE hCore, PSPADDR AddrPspWrite, void *pvData, size_t cbData);

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

#endif /* __psp_core_h */
