/** @file
 * PSP Emulator - Debugger API.
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
#ifndef __psp_dbg_h
#define __psp_dbg_h

#include <common/types.h>

#include <psp-ccd.h>


/** PSP debugger handle. */
typedef struct PSPDBGINT *PSPDBG;
/** Pointer to a PSP debugger handle. */
typedef PSPDBG *PPSPDBG;


/**
 * Creates a new debugger instance for the given CCDs listening at the given port.
 *
 * @returns Status code.
 * @param   phDbg                   Where to store the debugger handle on success.
 * @param   uPort                   The port to listen on.
 * @param   cInsnStep               Number of instructions to step in a single round
 *                                  when the CCD is running, 0 for default count.
 *                                  Only use something different when you know what you are doing.
 * @param   PspAddrRunUpTo          Runs until this address is hit like without a debugger enabled
 *                                  and drops into it when hit.
 * @param   pahCcds                 Array of CCD handles to handle with this debugger instance.
 * @param   cCcds                   NUmber of entris in the given array.
 */
int PSPEmuDbgCreate(PPSPDBG phDbg, uint16_t uPort, uint32_t cInsnsStep, PSPADDR PspAddrRunUpTo, const PPSPCCD pahCcds, uint32_t cCcds);

/**
 * Destroys the given debugger handle.
 *
 * @returns Status code.
 * @param   hDbg                    The debugger handle to destroy.
 */
int PSPEmuDbgDestroy(PSPDBG hDbg);

/**
 * Executes the main debugger runloop, listening for requests from the client and executing them.
 *
 * @returns Status code.
 * @param   hDbg                    The debugger handle.
 *
 * @note Don't access the assigned CCD handles directly when this is active, weird things could happen.
 */
int PSPEmuDbgRunloop(PSPDBG hDbg);

/**
 * Kicks the given debugger handle out of the runloop.
 *
 * @returns Status code.
 * @param   hDbg                    The debugger handle.
 */
int PSPEmuDbgKick(PSPDBG hDbg);

#endif /* __psp_dbg_h */
