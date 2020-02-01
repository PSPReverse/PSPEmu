/** @file
 * PSP Emulator - PSP system config descriptor.
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
#ifndef __psp_cfg_h
#define __psp_cfg_h

#include <common/types.h>

#include <psp-core.h>

/**
 * PSP emulator config.
 */
typedef struct PSPEMUCFG
{
    /** Emulation mode. */
    PSPCOREMODE             enmMode;
    /** The flash ROM path. */
    const char              *pszPathFlashRom;
    /** Path to the on chip bootloader if in appropriate mode. */
    const char              *pszPathOnChipBl;
    /** Binary to load, if NULL we get one from the flash image depending on the mode. */
    const char              *pszPathBinLoad;
    /** Path to the boot rom service page to inject (for system and app emulation mode). */
    const char              *pszPathBootRomSvcPage;
    /** Flag whether overwritten binaries have the 256 byte header prepended (affects the load address). */
    bool                    fBinContainsHdr;
    /** Debugger port to listen on, 0 means debugger is disabled. */
    uint16_t                uDbgPort;
    /** Pointer to the read flash rom content. */
    void                    *pvFlashRom;
    /** Size of the flash ROM in bytes. */
    size_t                  cbFlashRom;
} PSPEMUCFG;
/** Pointer to a PSPEmu config. */
typedef PSPEMUCFG *PPSPEMUCFG;
/** Pointer to a const PSPEmu config. */
typedef const PSPEMUCFG *PCPSPEMUCFG;

#endif /* __psp_cfg_h */

