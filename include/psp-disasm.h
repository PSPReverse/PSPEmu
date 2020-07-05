/** @file
 * PSP Emulator - Disassembler API
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
#ifndef __psp_disasm_h
#define __psp_disasm_h

#include <common/types.h>

/**
 * Disassembles a bunch of instructions and formats them into the given destination buffer.
 *
 * @returns Status code.
 * @param   pchDst                  Pointer to the character buffer holding the zero terminated string on success.
 * @param   cch                     Size of the destination buffer.
 * @param   cInsnsDisasm            Maximum number of instructions to disassemble, 0 for as much as possible.
 * @param   pbCode                  The code to disassemble.
 * @param   cbCode                  Number of code bytes.
 * @param   uAddrStart              The address of the first instruction.
 * @param   fThumb                  Flag whether to disassemble in THUMB or ARM mode.
 */
int PSPEmuDisasm(char *pchDst, size_t cch, uint32_t cInsnsDisasm, uint8_t *pbCode, size_t cbCode, PSPADDR uAddrStart, bool fThumb);

#endif /* __psp_disasm_h */
