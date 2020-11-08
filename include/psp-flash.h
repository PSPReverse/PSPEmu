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
#ifndef INCLUDED_psp_flash_h
#define INCLUDED_psp_flash_h

#include <common/types.h>

#include <psp-fw/ffs.h>

#include <psp-profile.h>


/** Opaque PSP flash filesystem handle. */
typedef struct PSPFFSINT *PSPFFS;
/** Pointer to a PSP flash filesystem handle. */
typedef PSPFFS *PPSPFFS;


/**
 * Creates a new flash filesystem instance for the given flash image and config.
 *
 * @returns Status code.
 * @param   phFfs                   Where to store the handle to the filesystem instance on success.
 * @param   idPsp                   The PSP identification value to load the correct directories from any combo directory.
 * @param   pvFlash                 The start of the flash region.
 * @param   cbFlash                 Size of the flash region.
 */
int PSPFlashFsCreate(PPSPFFS phFfs, uint32_t idPsp, const void *pvFlash, size_t cbFlash);


/**
 * Destroys the given flash filesystem instance.
 *
 * @returns nothing.
 * @param   hFfs                    The flash filesystem instance handle.
 */
void PSPFlashFsDestroy(PSPFFS hFfs);


/**
 * Queries the L1 PSP directory from the given flash image.
 *
 * @returns Status code.
 * @param   hFfs                    The flash filesystem instance handle.
 * @param   ppDirL1                 Where to store the pointer to the verified L1 directory on success.
 * @param   pcbDirL1                Where to store the size of the L1 directory on success.
 */
int PSPFlashFsQueryL1Dir(PSPFFS hFfs, PCPSPFFSDIR *ppDirL1, size_t *pcbDirL1);


/**
 * Queries the directory from the selected L1 and possibly L2 directory and copies it
 * to the given buffer.
 *
 * @return Status code.
 * @param   hFfs                    The flash filesystem instance handle.
 * @param   pDirHdr                 The directory header to fill in (L1 directory magic), optional.
 * @param   paDirEntries            Where to store the merged entries.
 * @param   cEntriesMax             Maximum number of entries fitting into the array.
 * @param   fMergeL2                Flag whether to merge the L2 directory into this as well (kind of what the off chip BL is doing at the beginning).
 *
 * @note L2 directory entries are removed from the merged directory if merging is enabled.
 * @note Excessive entries not fitting into the buffer are cut off.
 */
int PSPFlashFsDirQuery(PSPFFS hFfs, PPSPFFSDIRHDR pDirHdr, PPSPFFSDIRENTRY paDirEntries, size_t cEntriesMax, bool fMergeL2);


/**
 * Queries the given entry from the flash region parsing the directories etc.
 *
 * @returns Status code.
 * @param   hFfs                    The flash filesystem instance handle.
 * @param   enmEntry                The entry type to read.
 * @param   ppvEntry                Where to store the pointer to the entry start on success.
 * @param   pcbEntry                Where to store the size of the entry on success.
 */
int PSPFlashFsQueryEntry(PSPFFS hFfs, PSPFFSDIRENTRYTYPE enmEntry, const void **ppvEntry, size_t *pcbEntry);

#endif /* !INCLUDED_psp_flash_h */
