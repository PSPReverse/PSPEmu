/** @file
 * PSP Emulator - API for handling the flash filesystem
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
#ifndef __psp_flash_h
#define __psp_flash_h

#include <common/types.h>


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
