/** @file
 * PSP Emulator - Coverage tracing API.
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
#ifndef __psp_cov_h
#define __psp_cov_h

#include <common/types.h>
#include <common/cdefs.h>

#include <psp-core.h>

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>


/** Opaque PSP coverage tracer handle. */
typedef struct PSPCOVINT *PSPCOV;
/** Pointer to a PSP coverage tracer handle. */
typedef PSPCOV *PPSPCOV;


/**
 * Creates a new coverage tracer instance.
 *
 * @returns Status code.
 * @param   phCov                   Where to store the coverage tracer handle on success.
 * @param   hPspCore                PSP core handle to create the coverage trace for.
 * @param   PspAddrBegin            Where to start collecting coverage information.
 * @param   PspAddrEnd              Where to stop collecting coverage information, inclusive.
 */
int PSPEmuCovCreate(PPSPCOV phCov, PSPCORE hPspCore, PSPADDR PspAddrBegin, PSPADDR PspAddrEnd);

/**
 * Destroys a given coverage tracer handle.
 *
 * @returns nothing.
 * @param   hCov                    The coverage tracer handle to destroy.
 */
void PSPEmuCovDestroy(PSPCOV hCov);


/**
 * Resets the state of the given coverage tracer to a clean one.
 *
 * @returns nothing.
 * @param   hCov                    The coverage tracer handle.
 */
void PSPEmuCovReset(PSPCOV hCov);


/**
 * Dumps the currently collected coverage information to the given file.
 *
 * @returns Status code.
 * @param   hCov                    The coverage tracer handle.
 * @param   pszFilename             Filename to dump the information to.
 *
 * @note The file format is supposed to be compatible with DynamoRIOs drcov format.
 */
int PSPEmuCovDumpToFile(PSPCOV hCov, const char *pszFilename);

#endif /* __psp_cov_h */
