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
#include <stdlib.h>

#include <common/cdefs.h>
#include <common/status.h>

#include <os/file.h>

#include <psp-brsp.h>
#include <psp-flash.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

int PSPBrspGenerate(PPSPROMSVCPG pBrsp, PCPSPEMUCFG pCfg, uint32_t idCcd, uint32_t idSocket)
{
    int rc = STS_INF_SUCCESS;

    memset(pBrsp, 0, sizeof(*pBrsp));

    if (pCfg->pszPathBootRomSvcPage)
    {
        void   *pvBrsp;
        size_t cbBrsp;

        rc = OSFileLoadAll(pCfg->pszPathBootRomSvcPage, &pvBrsp, &cbBrsp);
        if (STS_FAILURE(rc))
        {
            fprintf(stderr, "Loading the boot ROM service page from the given file failed with %d\n", rc);
            return rc;
        }

        if (cbBrsp == _4K)
            memcpy(pBrsp, pvBrsp, cbBrsp);
        else
        {
            fprintf(stderr, "The BRSP must be exactly 4096 byte in size\n");
            rc = STS_ERR_INVALID_PARAMETER;
        }

        OSFileLoadAllFree(pvBrsp, cbBrsp);
    }

    if (pCfg->fBootRomSvcPageModify)
    {
        if (pCfg->fPspDbgMode)
        {
            printf("Activating PSP firmware debug mode\n");
            pBrsp->Fields.u32BootMode = 1;
        }

        PSPFFS hFfs = NULL;
        rc = PSPFlashFsCreate(&hFfs, pCfg->pPspProfile->enmMicroArch, pCfg->pvFlashRom, pCfg->cbFlashRom);
        if (STS_SUCCESS(rc))
        {
            /* Load the merged PSP directory into the BRSP. */
            rc = PSPFlashFsDirQueryMerged(hFfs, &pBrsp->Fields.FfsDirHdr, &pBrsp->Fields.aFfsDirEntries[0], ELEMENTS(pBrsp->Fields.aFfsDirEntries));
            if (STS_SUCCESS(rc))
            {
                /* Query AMD public key from flash and insert into BRSP. */
                const void *pvAmdPubKey = NULL;
                size_t cbAmdPubKey = 0;
                rc = PSPFlashFsQueryEntry(hFfs, PSPFFSDIRENTRYTYPE_AMD_PUBLIC_KEY, &pvAmdPubKey, &cbAmdPubKey);
                if (STS_SUCCESS(rc))
                {
                    if (cbAmdPubKey == sizeof(pBrsp->Fields.abAmdPubKey))
                    {
                        memcpy(&pBrsp->Fields.abAmdPubKey[0], pvAmdPubKey, sizeof(pBrsp->Fields.abAmdPubKey));
                        pBrsp->Fields.idPhysDie      = (uint8_t)idCcd;
                        pBrsp->Fields.idSocket       = (uint8_t)idSocket;
                        pBrsp->Fields.cDiesPerSocket = (uint8_t)pCfg->cCcdsPerSocket;
                        pBrsp->Fields.cSysSockets    = (uint8_t)pCfg->cSockets;
                        /** @todo u8PkgType, core info, cCcxs, cCores, etc. */
                    }
                    else
                    {
                        printf("Loaded AMD public key doesn't match expected size: %zu vs %zu expected\n", cbAmdPubKey, sizeof(pBrsp->Fields.abAmdPubKey));
                        rc = STS_ERR_INVALID_PARAMETER;
                    }
                }
                else
                    printf("Loading AMD public key into BRSP failed with %d!\n", rc);
            }

            PSPFlashFsDestroy(hFfs);
        }
        else
            printf("Creating flash filesystem read instance failed with %d\n", rc);
    }

    return rc;
}

