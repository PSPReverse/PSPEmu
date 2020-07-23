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

    //PSPBrspDump(pBrsp); /* For debug purposes */
    return rc;
}


int PSPBrspDump(PPSPROMSVCPG pBrsp)
{
    printf("FfsDirHdr.u32Magic:               %#x\n"
           "FfsDirHdr.u32ChkSumFletcher32:    %#x\n"
           "FfsDirHdr.cEntries:               %u\n"
           "FfsDirHdr.u32Rsvd0:               %#x\n",
           pBrsp->Fields.FfsDirHdr.u32Magic, pBrsp->Fields.FfsDirHdr.u32ChkSumFletcher32,
           pBrsp->Fields.FfsDirHdr.cEntries, pBrsp->Fields.FfsDirHdr.u32Rsvd0);
    for (uint32_t i = 0; i < pBrsp->Fields.FfsDirHdr.cEntries; i++)
    {
        PCPSPFFSDIRENTRY pEntry = &pBrsp->Fields.aFfsDirEntries[i];

        printf("aFfsDirEntries[%u].enmType:      %#x\n"
               "aFfsDirEntries[%u].cbEntry:      %u\n"
               "aFfsDirEntries[%u].FfsAddrStart: %#x\n"
               "aFfsDirEntries[%u].u32Rsvd0:     %#x\n",
               i, pEntry->enmType,
               i, pEntry->cbEntry,
               i, pEntry->FfsAddrStart,
               i, pEntry->u32Rsvd0);
    }

    /** @todo AMD public key. */

    printf("u32BootMode:                      %#x\n"
           "abUnknown[0..5]:                  %#x %#x %#x %#x %#x\n"
           "cCores:                           %u\n"
           "cCcxs:                            %u\n"
           "cCoresEnabledOnDie:               %u\n"
           "bUnknown2:                        %#x\n"
           "logCoresPerComplex[0]:            %u\n"
           "logCoresPerComplex[1]:            %u\n",
           pBrsp->Fields.u32BootMode,
           pBrsp->Fields.abUnknown1[0], pBrsp->Fields.abUnknown1[1], pBrsp->Fields.abUnknown1[2],
           pBrsp->Fields.abUnknown1[3], pBrsp->Fields.abUnknown1[4], pBrsp->Fields.abUnknown1[5],
           pBrsp->Fields.cCores, pBrsp->Fields.cCcxs, pBrsp->Fields.cCoresEnabledOnDie,
           pBrsp->Fields.bUnknown2,
           pBrsp->Fields.logCoresPerComplex[0], pBrsp->Fields.logCoresPerComplex[1]);

    for (uint32_t i = 0; i < ELEMENTS(pBrsp->Fields.aCoreInfo); i++)
    {
        const PSPCOREINFO *pCoreInfo = &pBrsp->Fields.aCoreInfo[i];

        printf("aCoreInfo[%u].idCcx:                %u\n"
               "aCoreInfo[%u].idCore:               %u\n",
               i, pCoreInfo->idCcx,
               i, pCoreInfo->idCore);
    }

    printf("abUnknown3[0..5]:                 %#x %#x %#x %#x %#x\n"
           "abUnknown3[6..11]:                %#x %#x %#x %#x %#x\n"
           "idPhysDie:                        %u\n"
           "idSocket:                         %u\n"
           "u8PkgType:                        %#x\n"
           "cSysSockets:                      %u\n"
           "bUnk4:                            %#x\n"
           "cDiesPerSocket:                   %u\n",
           pBrsp->Fields.abUnknown3[0], pBrsp->Fields.abUnknown3[1], pBrsp->Fields.abUnknown3[2],
           pBrsp->Fields.abUnknown3[3], pBrsp->Fields.abUnknown3[4], pBrsp->Fields.abUnknown3[5],
           pBrsp->Fields.abUnknown3[6], pBrsp->Fields.abUnknown3[7], pBrsp->Fields.abUnknown3[8],
           pBrsp->Fields.abUnknown3[9], pBrsp->Fields.abUnknown3[10], pBrsp->Fields.abUnknown3[11],
           pBrsp->Fields.idPhysDie, pBrsp->Fields.idSocket, pBrsp->Fields.u8PkgType,
           pBrsp->Fields.cSysSockets, pBrsp->Fields.bUnk4, pBrsp->Fields.cDiesPerSocket);

    return STS_INF_SUCCESS;
}

