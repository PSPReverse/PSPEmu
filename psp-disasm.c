/** @file
 * PSP Emulator - Core API (interfacing with unicorn engine).
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
#include <capstone/capstone.h>
#include <string.h>

#include <common/types.h>
#include <common/cdefs.h>

#include <psp-disasm.h>

int PSPEmuDisasm(char *pchDst, size_t cch, uint32_t cInsnsDisasm, uint8_t *pbCode, size_t cbCode, PSPADDR uAddrStart, bool fThumb)
{
    int rc = 0;
    csh hCapStone;
    cs_insn *paInsn;

    /** @todo Thumb */
    if (cs_open(CS_ARCH_ARM, fThumb ? CS_MODE_THUMB : CS_MODE_ARM, &hCapStone) != CS_ERR_OK)
        return -1;

    size_t cInsn = cs_disasm(hCapStone, pbCode, cbCode, uAddrStart, 0, &paInsn);
    if (cInsn)
    {
        size_t cchLeft = cch;
        char *pszDst = pchDst;
        uint32_t i = 0;

        if (cInsnsDisasm)
            cInsn = MIN(cInsn, cInsnsDisasm);

        pchDst[0] = 0;

        while (i < cInsn)
        {
            size_t cchWritten = snprintf(pszDst, cchLeft, "%#08llx:    %s\t\t%s\n",
                                         paInsn[i].address, paInsn[i].mnemonic,
                                         paInsn[i].op_str);
            if (cchWritten >= cchLeft)
                break;

            cchLeft -= cchWritten;
            pszDst  += cchWritten;
            i++;
        }

        cs_free(paInsn, cInsn);
    }
    else
        rc = -1;

    cs_close(&hCapStone);

    return rc;
}

