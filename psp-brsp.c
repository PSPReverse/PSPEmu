/** @file
 * PSP Emulator - API for manipulating the Boot ROM Service Page.
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
/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#include <string.h>
#include <stdio.h>

#include <common/cdefs.h>
#include <common/status.h>

#include <psp-brsp.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

int PSPBrspGenerate(PPSPROMSVCPG pBrsp, PCPSPEMUCFG pCfg, uint32_t idCcd, uint32_t idSocket)
{
    int rc = STS_INF_SUCCESS;

    if (   pCfg->pvBootRomSvcPage
        && pCfg->cbBootRomSvcPage)
    {
        if (pCfg->cbBootRomSvcPage != _4K)
            return STS_ERR_INVALID_PARAMETER;

        if (pCfg->fBootRomSvcPageModify)
        {
            PSPROMSVCPG Brsp;

            memcpy(pBrsp, pCfg->pvBootRomSvcPage, sizeof(Brsp));

            if (pCfg->fPspDbgMode)
            {
                printf("Activating PSP firmware debug mode\n");
                pBrsp->Fields.u32BootMode = 1;
            }

            if (pCfg->fLoadPspDir)
            {
                printf("Loading PSP 1st level directory from flash image into boot ROM service page\n");
                uint8_t *pbFlashRom = (uint8_t *)pCfg->pvFlashRom;
                memcpy(&pBrsp->Fields.abFfsDir[0], &pbFlashRom[0x77000], sizeof(pBrsp->Fields.abFfsDir)); /** @todo */
            }

            pBrsp->Fields.idPhysDie      = (uint8_t)idCcd;
            pBrsp->Fields.idSocket       = (uint8_t)idSocket;
            pBrsp->Fields.cDiesPerSocket = (uint8_t)pCfg->cCcdsPerSocket;
            /** @todo u8PkgType, core info, cCcxs, cCores, etc. */
        }
    }

    return rc;
}

