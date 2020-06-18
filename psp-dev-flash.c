/** @file
 * PSP Emulator - Flash ROM device attached to SMN.
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>

#include <poll.h>
#include <sys/ioctl.h>

#include <pthread.h>

#include <common/cdefs.h>

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



/**
 * Gets the nanosecond timestamp.
 *
 * @returns Nanoseconds elapsed (monotonic increasing).
 */
static uint64_t pspDevFlashGetTimeNs(void)
{
    struct timespec Tp;
    int rcPsx = clock_gettime(CLOCK_MONOTONIC, &Tp);
    if (!rcPsx)
        return ((uint64_t)Tp.tv_sec * 1000ULL * 1000ULL * 1000ULL) + Tp.tv_nsec;

    return 0;
}


static void pspDevFlashRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    if (offSmn + cbRead <= pThis->pDev->pCfg->cbFlashRom)
        memcpy(pvDst, (uint8_t *)pThis->pDev->pCfg->pvFlashRom + offSmn, cbRead);
    else
        printf("%s: ATTEMPTED out of bounds read from offSmn=%#x cbRead=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbRead);

    /* Log the access if enabled. */
    if (pThis->pSpiFlashTrace)
    {
        /* Generate a new packet ID and read command if the last access isn't adjacent to this one. */
        uint64_t tsCmd = pspDevFlashGetTimeNs() - pThis->tsStart;
        uint64_t tsCmdSec = tsCmd / (1000 * 1000 * 1000);
        uint64_t tsCmdNs = tsCmd % (1000 * 1000 * 1000);

        if (offSmn != pThis->offAccLast)
        {
            pThis->idPacket++;
            int cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%u,0x03,0xFF\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket);
            cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%u,0x%02x,0xFF\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket, (offSmn >> 16) & 0xff);
            cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%u,0x%02x,0xFF\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket, (offSmn >> 8) & 0xff);
            cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%u,0x%02x,0xFF\n",
                                     tsCmdSec, tsCmdNs++, pThis->idPacket, offSmn & 0xff);
        }

        pThis->offAccLast = offSmn + cbRead;

        uint8_t *pbFlash = (uint8_t *)pThis->pDev->pCfg->pvFlashRom + offSmn;
        while (cbRead)
        {
            int cchWritten = fprintf(pThis->pSpiFlashTrace, "%llu.%llu000000,%u,0x00,0x%02x\n",
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

    if (offSmn + cbWrite <= pThis->pDev->pCfg->cbFlashRom)
        memcpy((uint8_t *)pThis->pDev->pCfg->pvFlashRom + offSmn, pvVal, cbWrite);
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


static int pspDevFlashInit(PPSPDEV pDev)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)&pDev->abInstance[0];

    pThis->pDev       = pDev;
    pThis->offAccLast = UINT32_MAX - 1;
    pThis->idPacket   = 0;

    SMNADDR SmnAddrFlash = pDev->pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 0x44000000 : 0x0a000000;
    int rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, SmnAddrFlash, pDev->pCfg->cbFlashRom,
                                    pspDevFlashRead, pspDevFlashWrite, pThis,
                                    "SPI flash", &pThis->hSmn);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x2dc4000, 0x20,
                                    pspDevFlashSpiCtrlRead, pspDevFlashSpiCtrlWrite, pThis,
                                    "SPI Control", &pThis->hSmnCtrl);
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
            pThis->tsStart = pspDevFlashGetTimeNs();
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

