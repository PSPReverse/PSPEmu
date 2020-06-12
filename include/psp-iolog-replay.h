/** @file
 * PSP Emulator - I/O log replay.
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
#ifndef INCLUDED_psp_iolog_replay_h
#define INCLUDED_psp_iolog_replay_h

#include <common/types.h>

#include <psp-ccd.h>


/** Opaque PSP I/O log replay handle. */
typedef struct PSPIOLOGREPLAYINT *PSPIOLOGREPLAY;
/** Pointer to a PSP I/O log replay handle. */
typedef PSPIOLOGREPLAY *PPSPIOLOGREPLAY;


/**
 * Creates a new I/O log replay instance.
 *
 * @returns Status code.
 * @param   phIoLogReplay           Where to store the handle to the I/O log replay instance on success.
 * @param   pszIoLogFilename        The I/O log to use for replay.
 */
int PSPIoLogReplayCreate(PPSPIOLOGREPLAY phIoLogReplay, const char *pszIoLogFilename);


/**
 * Destroys the given I/O log replay instance.
 *
 * @returns nothing.
 * @param   hIoLogReplay            The I/O log replay handle to destroy.
 */
void PSPIoLogReplayDestroy(PSPIOLOGREPLAY hIoLogReplay);


/**
 * Registers the given CCD handle with the I/O log replay instance.
 *
 * @returns Status code.
 * @param   hIoLogReplay            The I/O log replay.
 * @param   hCcd                    The CCD handle to register.
 */
int PSPIoLogReplayCcdRegister(PSPIOLOGREPLAY hIoLogReplay, PSPCCD hCcd);


/**
 * Deregisters the given CCD handle from the given I/O log replay instance.
 *
 * @returns Status code.
 * @param   hProxy                  The proxy handle.
 * @param   hCcd                    The CCD handle to deregister.
 */
int PSPIoLogReplayCcdDeregister(PSPIOLOGREPLAY hIoLogReplay, PSPCCD hCcd);

#endif /* !INCLUDED_psp_iolog_replay_h */

