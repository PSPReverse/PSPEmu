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

#include <psp-core.h>


/** PSP debugger handle. */
typedef struct PSPDBGINT *PSPDBG;
/** Pointer to a PSP debugger handle. */
typedef PSPDBG *PPSPDBG;


/**
 * Creates a new debugger instance for the given PSP core listening at the given port.
 *
 * @returns Status code.
 * @param   phDbg                   Where to store the debugger handle on success.
 * @param   hCore                   The core controlled by the debugger.
 * @param   uPort                   The port to listen on.
 */
int PSPEmuDbgCreate(PPSPDBG phDbg, PSPCORE hCore, uint16_t uPort);

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
 * @note Don't access the PSP core handle directly when this is active, weird things could happen.
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
