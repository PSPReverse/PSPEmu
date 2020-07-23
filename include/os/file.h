/** @file
 * PSP Emulator - OS abstraction for file accesses.
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
#ifndef INCLUDED_os_file_h
#define INCLUDED_os_file_h

#include <common/types.h>

/**
 * Loads the everything from the given file into the process memory space and returning an appropriate memory buffer (mmap'ed for example).
 *
 * @returns Status code.
 * @param   pszFilename             The filename to laod the flash content from.
 * @param   ppv                     Where to store the pointer to the flash content on success.
 * @param   pcb                     Where to store the size of the flash region on success.
 */
int OSFileLoadAll(const char *pszFilename, void **ppv, size_t *pcb);

/**
 * Frees the file loaded with OSFileLoadAll().
 *
 * @returns Status code.
 * @param   pv                      Pointer to the start of the file as returned by OSFileLoadAll().
 * @param   cb                      Size of the file as returned by OSFileLoadAll().
 */
int OSFileLoadAllFree(void *pv, size_t cb);

#endif /* !INCLUDED_os_file_h */
