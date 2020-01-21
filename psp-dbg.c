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
#include <libgdbstub.h>

#include <common/types.h>
#include <common/cdefs.h>

#include <psp-dbg.h>


/**
 * PSP debugger instance data.
 */
typedef struct PSPDBGINT
{
    /** The PSP core handle under control of the debugger. */
    PSPCORE                 hCore;
} PSPDBGINT;
/** Pointer to the debugger instance data. */
typedef PSPDBGINT *PPSPDBGINT;


int PSPEmuDbgCreate(PPSPDBG phDbg, PSPCORE hCore, uint16_t uPort)
{
    return -1;
}


int PSPEmuDbgDestroy(PSPDBG hDbg)
{
    return -1;
}


int PSPEmuDbgRunloop(PSPDBG hDbg)
{
    return -1;
}


int PSPEmuDbgKick(PSPDBG hDbg)
{
    return -1;
}
