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
} PSPDEVFLASH;
/** Pointer to the device instance data. */
typedef PSPDEVFLASH *PPSPDEVFLASH;


static void pspDevFlashRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    if (offSmn + cbRead <= pThis->pDev->pCfg->cbFlashRom)
        memcpy(pvDst, (uint8_t *)pThis->pDev->pCfg->pvFlashRom + offSmn, cbRead);
    else
        printf("%s: ATTEMPTED out of bounds read from offSmn=%#x cbRead=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbRead);
}


static void pspDevFlashWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    printf("%s: ATTEMPTED write access to offSmn=%#x cbWrite=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbWrite);
}


static int pspDevFlashInit(PPSPDEV pDev)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)&pDev->abInstance[0];

    pThis->pDev = pDev;

    int rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0a000000, pDev->pCfg->cbFlashRom,
                                    pspDevFlashRead, pspDevFlashWrite, pThis,
                                    &pThis->hSmn);
    return rc;
}


static void pspDevFlashDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
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
};

