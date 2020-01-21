/** @file
 * PSP Emulator - Disassembler API
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
#ifndef __psp_disasm_h
#define __psp_disasm_h

#include <common/types.h>

/**
 * Disassembles a bunch of instructions and formats them into the given destination buffer.
 *
 * @returns Status code.
 * @param   pchDst                  Pointer to the character buffer holding the zero terminated string on success.
 * @param   cch                     Size of the destination buffer.
 * @param   pbCode                  The code to disassemble.
 * @param   cbCode                  Number of code bytes.
 * @param   uAddrStart              The address of the first instruction.
 * @param   fThumb 					Flag whether to disassemble in THUMB or ARM mode.
 */
int PSPEmuDisasm(char *pchDst, size_t cch, uint8_t *pbCode, size_t cbCode, PSPADDR uAddrStart, bool fThumb);

#endif /* __psp_disasm_h */
