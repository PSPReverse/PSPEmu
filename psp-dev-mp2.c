/** @file
 * PSP Emulator - MP2 device (ARM core configured as I2C controller) attached to SMN.
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
 * MP2 device instance data.
 */
typedef struct PSPDEVMP2
{
    /** SMN region handle for the firmware region. */
    PSPIOMREGIONHANDLE          hSmnFw;
    /** SMN region handle for the SRAM1 region. */
    PSPIOMREGIONHANDLE          hSmnSram1;
    /** The memory the firmware is loaded to residing at SMN address 0x3f00000. */
    uint8_t                     abFw[192 * _1K];
    /** An SRAM1 region used for some sort of config residing at SMN address 0x3f50000. */
    uint8_t                     abSram1[1376];
} PSPDEVMP2;
/** Pointer to the device instance data. */
typedef PSPDEVMP2 *PPSPDEVMP2;


static void pspDevMp2FwRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVMP2 pThis = (PPSPDEVMP2)pvUser;

    memcpy(pvDst, &pThis->abFw[offSmn], cbRead);
}


static void pspDevMp2FwWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVMP2 pThis = (PPSPDEVMP2)pvUser;

    memcpy(&pThis->abFw[offSmn], pvVal, cbWrite);
}


static void pspDevMp2Sram1Read(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVMP2 pThis = (PPSPDEVMP2)pvUser;

    memcpy(pvDst, &pThis->abSram1[offSmn], cbRead);
}


static void pspDevMp2Sram1Write(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVMP2 pThis = (PPSPDEVMP2)pvUser;

    memcpy(&pThis->abSram1[offSmn], pvVal, cbWrite);
}


static int pspDevMp2Init(PPSPDEV pDev)
{
    PPSPDEVMP2 pThis = (PPSPDEVMP2)&pDev->abInstance[0];

    int rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x03f00000, sizeof(pThis->abFw),
                                    pspDevMp2FwRead, pspDevMp2FwWrite, pThis,
                                    &pThis->hSmnFw);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x03f50000, sizeof(pThis->abSram1),
                                    pspDevMp2Sram1Read, pspDevMp2Sram1Write, pThis,
                                    &pThis->hSmnSram1);

    return rc;
}


static void pspDevMp2Destruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegMp2 =
{
    /** pszName */
    "mp2",
    /** pszDesc */
    "MP2 device",
    /** cbInstance */
    sizeof(PSPDEVMP2),
    /** pfnInit */
    pspDevMp2Init,
    /** pfnDestruct */
    pspDevMp2Destruct,
    /** pfnReset */
    NULL
};

