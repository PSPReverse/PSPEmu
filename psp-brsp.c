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
        else
            pBrsp->Fields.u32BootMode = 2;

        PSPFFS hFfs = NULL;
        rc = PSPFlashFsCreate(&hFfs, pCfg->pPspProfile->u32PspOnChipBlVersion, pCfg->pvFlashRom, pCfg->cbFlashRom);
        if (STS_SUCCESS(rc))
        {
            /* Load the merged PSP directory into the BRSP. */
            rc = PSPFlashFsDirQuery(hFfs, &pBrsp->Fields.FfsDirHdr, &pBrsp->Fields.aFfsDirEntries[0], ELEMENTS(pBrsp->Fields.aFfsDirEntries), false /*fMergeL2*/);
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

                        PCPSPAMDCPUPROFILE pCpuProfile = pCfg->pCpuProfile;
                        pBrsp->Fields.cCoresPerCcx = (uint8_t)pCpuProfile->cCoresPerCcx;
                        pBrsp->Fields.cCcxs        = (uint8_t)pCpuProfile->cCcxs;
                        pBrsp->Fields.cCoresPerCcd = (uint8_t)pCpuProfile->cCoresPerCcd;

                        /** @todo This below is all guesswork, figure this out by checking different CPUs. */
                        pBrsp->Fields.logCoresPerComplex[0] = (uint8_t)pCpuProfile->cCoresPerCcx;
                        if (pCpuProfile->cCcxs == 2)
                            pBrsp->Fields.logCoresPerComplex[1] = (uint8_t)pCpuProfile->cCoresPerCcx;

                        /*
                         * Current assumption is that first come the 'real' cores and second the ones for the SMT
                         * (need to figure out where SMT is indicated, the bUnknown2 looks promising but to little data right now)
                         */
                        for (uint32_t idxCcx = 0; idxCcx < pCpuProfile->cCcxs; idxCcx++)
                        {
                            for (uint32_t idxCore = 0; idxCore < pCpuProfile->cCoresPerCcx; idxCore++)
                            {
                                uint32_t idxEntry    = idxCcx * pCpuProfile->cCoresPerCcx + idxCore;
                                uint32_t idxEntrySmt = idxEntry + (pCpuProfile->cCcxs * pCpuProfile->cCoresPerCcx);
                                pBrsp->Fields.aCoreInfo[idxEntry].idCcx  = (uint8_t)idxCcx;
                                pBrsp->Fields.aCoreInfo[idxEntry].idCore = (uint8_t)idxCore;

                                /** @todo Determine whether SMT is enabled. */
                                pBrsp->Fields.aCoreInfo[idxEntrySmt].idCcx  = (uint8_t)idxCcx;
                                pBrsp->Fields.aCoreInfo[idxEntrySmt].idCore = (uint8_t)idxCore;
                            }
                        }
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
    printf("FfsDirHdr.u32Magic:                 %#x\n"
           "FfsDirHdr.u32ChkSumFletcher32:      %#x\n"
           "FfsDirHdr.cEntries:                 %u\n"
           "FfsDirHdr.u32Rsvd0:                 %#x\n",
           pBrsp->Fields.FfsDirHdr.u32Magic, pBrsp->Fields.FfsDirHdr.u32ChkSumFletcher32,
           pBrsp->Fields.FfsDirHdr.cEntries, pBrsp->Fields.FfsDirHdr.u32Rsvd0);
    for (uint32_t i = 0; i < pBrsp->Fields.FfsDirHdr.cEntries; i++)
    {
        PCPSPFFSDIRENTRY pEntry = &pBrsp->Fields.aFfsDirEntries[i];

        printf("aFfsDirEntries[%02u].enmType:         %#x\n"
               "aFfsDirEntries[%02u].cbEntry:         %u\n"
               "aFfsDirEntries[%02u].FfsAddrStart:    %#x\n"
               "aFfsDirEntries[%02u].u32Rsvd0:        %#x\n",
               i, pEntry->enmType,
               i, pEntry->cbEntry,
               i, pEntry->FfsAddrStart,
               i, pEntry->u32Rsvd0);
    }

    /** @todo AMD public key. */

    printf("u32BootMode:                        %#x\n"
           "abUnknown[0..5]:                    %#x %#x %#x %#x %#x %#x\n"
           "cCoresPerCcx:                       %u\n"
           "cCcxs:                              %u\n"
           "cCoresPerCcd:                       %u\n"
           "bUnknown2:                          %#x\n"
           "logCoresPerComplex[0]:              %u\n"
           "logCoresPerComplex[1]:              %u\n",
           pBrsp->Fields.u32BootMode,
           pBrsp->Fields.abUnknown1[0], pBrsp->Fields.abUnknown1[1], pBrsp->Fields.abUnknown1[2],
           pBrsp->Fields.abUnknown1[3], pBrsp->Fields.abUnknown1[4], pBrsp->Fields.abUnknown1[5],
           pBrsp->Fields.cCoresPerCcx, pBrsp->Fields.cCcxs, pBrsp->Fields.cCoresPerCcd,
           pBrsp->Fields.bUnknown2,
           pBrsp->Fields.logCoresPerComplex[0], pBrsp->Fields.logCoresPerComplex[1]);

    for (uint32_t i = 0; i < ELEMENTS(pBrsp->Fields.aCoreInfo); i++)
    {
        const PSPCOREINFO *pCoreInfo = &pBrsp->Fields.aCoreInfo[i];

        printf("aCoreInfo[%02u].idCcx:                %u\n"
               "aCoreInfo[%02u].idCore:               %u\n",
               i, pCoreInfo->idCcx,
               i, pCoreInfo->idCore);
    }

    printf("abUnknown3[0..5]:                   %#x %#x %#x %#x %#x %#x\n"
           "abUnknown3[6..11]:                  %#x %#x %#x %#x %#x %#x\n"
           "idPhysDie:                          %u\n"
           "idSocket:                           %u\n"
           "u8PkgType:                          %#x\n"
           "cSysSockets:                        %u\n"
           "bUnk4:                              %#x\n"
           "cDiesPerSocket:                     %u\n",
           pBrsp->Fields.abUnknown3[0], pBrsp->Fields.abUnknown3[1], pBrsp->Fields.abUnknown3[2],
           pBrsp->Fields.abUnknown3[3], pBrsp->Fields.abUnknown3[4], pBrsp->Fields.abUnknown3[5],
           pBrsp->Fields.abUnknown3[6], pBrsp->Fields.abUnknown3[7], pBrsp->Fields.abUnknown3[8],
           pBrsp->Fields.abUnknown3[9], pBrsp->Fields.abUnknown3[10], pBrsp->Fields.abUnknown3[11],
           pBrsp->Fields.idPhysDie, pBrsp->Fields.idSocket, pBrsp->Fields.u8PkgType,
           pBrsp->Fields.cSysSockets, pBrsp->Fields.bUnk4, pBrsp->Fields.cDiesPerSocket);

    return STS_INF_SUCCESS;
}

