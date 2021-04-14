/** @file
 * PSP Emulator - Flash ROM device attached to SMN.
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <common/cdefs.h>

#include <os/time.h>

#include <psp-devs.h>


/**
 * Flash device instance data.
 */
typedef struct PSPDEVFLASH
{
    /** Device instance pointer. */
    PPSPDEV                     pDev;
    /** SMN region handle. */
    PSPIOMREGIONHANDLE          hSmn;
    /** SMN region handle to the control interface living at 0x2dc4000. */
    PSPIOMREGIONHANDLE          hSmnCtrl;
    /** SMN region handle to the bank control interface living at 0x2dc405c for Zen2+ systems. */
    PSPIOMREGIONHANDLE          hSmnBankCtrl;
    /** The currently selected flash bank (16MB chunks). */
    uint32_t                    uBank;
    /** SPI flash trace file if configured. */
    FILE                        *pSpiFlashTrace;
    /** Start timestamp. */
    uint64_t                    tsStart;
    /** Last accessed offset. */
    SMNADDR                     offAccLast;
    /** Packet ID. */
    uint64_t                    idPacket;
} PSPDEVFLASH;
/** Pointer to the device instance data. */
typedef PSPDEVFLASH *PPSPDEVFLASH;


static uint32_t pspDevFlashGetBankedOffset(PPSPDEVFLASH pThis, SMNADDR offSmn)
{
    if (pThis->uBank * 16 * _1M < pThis->pDev->pCfg->cbFlashRom)
        return offSmn + pThis->uBank * 16 * _1M;

    return offSmn;
}


static void *pspDevFlashGetBankedStart(PPSPDEVFLASH pThis, SMNADDR offSmn)
{

    return (uint8_t *)pThis->pDev->pCfg->pvFlashRom + pspDevFlashGetBankedOffset(pThis, offSmn);
}


static void pspDevFlashRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;
    const uint8_t *pbFlash = (const uint8_t *)pspDevFlashGetBankedStart(pThis, offSmn);

    if (offSmn + cbRead <= 16 * _1M)
        memcpy(pvDst, pbFlash, cbRead);
    else
        printf("%s: ATTEMPTED out of bounds read from offSmn=%#x cbRead=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbRead);

    /* Log the access if enabled. */
    if (pThis->pSpiFlashTrace)
    {
        /* Generate a new packet ID and read command if the last access isn't adjacent to this one. */
        uint32_t offFlash = pspDevFlashGetBankedOffset(pThis, offSmn);
        uint64_t tsCmd = OSTimeTsGetNano() - pThis->tsStart;
        uint64_t tsCmdSec = tsCmd / (1000 * 1000 * 1000);
        uint64_t tsCmdNs = tsCmd % (1000 * 1000 * 1000);

        if (offSmn != pThis->offAccLast)
        {
            pThis->idPacket++;
            int cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%llu,0x03,0xFF\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket);
            cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%llu,0x%02x,0xFF\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket, (offFlash >> 16) & 0xff);
            cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%llu,0x%02x,0xFF\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket, (offFlash >> 8) & 0xff);
            cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%llu,0x%02x,0xFF\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket, offFlash & 0xff);
        }

        pThis->offAccLast = offSmn + cbRead;
        while (cbRead)
        {
            int cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%llu,0x00,0x%02x\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket, *pbFlash);
            pbFlash++;
            cbRead--;
        }
        fflush(pThis->pSpiFlashTrace);
    }
}


static void pspDevFlashWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    if (offSmn + cbWrite <= 16 * _1M)
        memcpy(pspDevFlashGetBankedStart(pThis, offSmn), pvVal, cbWrite);
    else
        printf("%s: ATTEMPTED out of bounds write from offSmn=%#x cbWrite=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbWrite);
}


static void pspDevFlashSpiCtrlRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    printf("%s: ATTEMPTED read from offSmn=%#x cbRead=%zu -> return all 0\n", __FUNCTION__, offSmn, cbRead);
    memset(pvDst, 0, cbRead);
}


static void pspDevFlashSpiCtrlWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    printf("%s: ATTEMPTED write access to offSmn=%#x cbWrite=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbWrite);
}


static void pspDevFlashSpiBankCtrlRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    *(uint32_t *)pvDst = pThis->uBank;
}


static void pspDevFlashSpiBankCtrlWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    pThis->uBank = *(uint32_t *)pvVal & 0xff;
}


static int pspDevFlashInit(PPSPDEV pDev)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)&pDev->abInstance[0];

    pThis->pDev       = pDev;
    pThis->uBank      = 0;
    pThis->offAccLast = UINT32_MAX - 1;
    pThis->idPacket   = 0;

    SMNADDR SmnAddrFlash = pDev->pCfg->pPspProfile->SmnAddrFlashStart;
    int rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, SmnAddrFlash, 16 * _1M,
                                    pspDevFlashRead, pspDevFlashWrite, pThis,
                                    "SPI flash", &pThis->hSmn);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x2dc4000, 0x20,
                                    pspDevFlashSpiCtrlRead, pspDevFlashSpiCtrlWrite, pThis,
                                    "SPI Control", &pThis->hSmnCtrl);
    if (   !rc
        && pDev->pCfg->pPspProfile->enmMicroArch >= PSPEMUMICROARCH_ZEN2)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x2dc405c, 4,
                                    pspDevFlashSpiBankCtrlRead, pspDevFlashSpiBankCtrlWrite, pThis,
                                    "SPI Bank Ctrl", &pThis->hSmnBankCtrl);
    if (   !rc
        && pDev->pCfg->pszSpiFlashTrace)
    {
        pThis->pSpiFlashTrace = fopen(pDev->pCfg->pszSpiFlashTrace, "wb");
        if (pThis->pSpiFlashTrace)
        {
            /* Write the header. */
            const char szHdr[] = "Time [s],Packet ID,MOSI,MISO\n";
            size_t cWritten = fwrite(&szHdr[0], sizeof(szHdr) - 1, 1, pThis->pSpiFlashTrace);
            if (cWritten != 1)
                rc = -1;
            pThis->tsStart = OSTimeTsGetNano();
        }
        else
            rc = -1;
    }

    return rc;
}


static void pspDevFlashDestruct(PPSPDEV pDev)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)&pDev->abInstance[0];

    if (pThis->pSpiFlashTrace)
        fclose(pThis->pSpiFlashTrace);
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegFlash =
{
    /** pszName */
    "flash",
    /** pszDesc */
    "Flash device",
    /** cbInstance */
    sizeof(PSPDEVFLASH),
    /** pfnInit */
    pspDevFlashInit,
    /** pfnDestruct */
    pspDevFlashDestruct,
    /** pfnReset */
    NULL
};

