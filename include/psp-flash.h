/** @file
 * PSP Emulator - API for handling the flash filesystem
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
#ifndef __psp_flash_h
#define __psp_flash_h

#include <common/types.h>

/**
 * Loads the flash from the given filename returning an appropriate memory buffer (mmap'ed for example).
 *
 * @returns Status code.
 * @param   pszFilename             The filename to laod the flash content from.
 * @param   ppv                     Where to store the pointer to the flash content on success.
 * @param   pcb                     Where to store the size of the flash region on success.
 */
int PSPEmuFlashLoadFromFile(const char *pszFilename, void **ppv, size_t *pcb);

/**
 * Frees the flash region created with PSPEmuFlashLoadFromFile().
 *
 * @returns Status code.
 * @param   pv                      Pointer to the start of the flash region as returned by PSPEmuFlashLoadFromFile().
 * @param   cb                      Size of the region as returned by PSPEmuFlashLoadFromFile().
 */
int PSPEmuFlashFree(void *pv, size_t cb);

/**
 * Reads the given entry from the flash region parsing the directories etc.
 *
 * @returns Status code.
 * @param   enmEntryId              The entry ID to read.
 * @param   pvFlash                 The start of the flash region.
 * @param   cbFlash                 Size of the flash region.
 * @param   pvDst                   Where to store the entry body on success.
 * @param   cbDst                   Size of the destination buffer.
 */
int PSPEmuFlashReadEntry(uint32_t enmEntryId, void *pvFlash, size_t cbFlash, void *pvDst, size_t cbDst);

#endif /* __psp_flash_h */
