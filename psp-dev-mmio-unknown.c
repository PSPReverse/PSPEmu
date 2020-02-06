/** @file
 * PSP Emulator - Unknown devices mapped directly into MMIO space.
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

#include <psp-devs.h>


/**
 * Unknown device instance data.
 */
typedef struct PSPDEVUNK
{
    /** 0x03006038 register handle. */
    PSPIOMREGIONHANDLE          hMmio0x03006038;
    /** 0x03200044 register handle. */
    PSPIOMREGIONHANDLE          hMmio0x03200044;
    /** 0x03010104 register handle. */
    PSPIOMREGIONHANDLE          hMmio0x03010104;
} PSPDEVUNK;
/** Pointer to the device instance data. */
typedef PSPDEVUNK *PPSPDEVUNK;


static void pspDevUnkMmioRead0x03006038(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offMmio=%#x cbRead=%zu\n", __FUNCTION__, offMmio, cbRead);

    switch (offMmio)
    {
        case 0x0:
            /* The on chip bootloader waits for bit 0 to go 1. */
            *(uint32_t *)pvVal = 0x1;
            break;
    }
}

static void pspDevUnkMmioRead0x03010104(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offMmio=%#x cbRead=%zu\n", __FUNCTION__, offMmio, cbRead);

    switch (offMmio)
    {
        case 0x0:
            *(uint32_t *)pvVal = 0x1a0e0900;
            break;
    }
}


static int pspDevMmioUnkInit(PPSPDEV pDev)
{
    PPSPDEVUNK pThis = (PPSPDEVUNK)&pDev->abInstance[0];

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03006038, 4,
                                     pspDevUnkMmioRead0x03006038, NULL, pThis,
                                     &pThis->hMmio0x03006038);
    if (!rc)
        rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03010104, 4,
                                     pspDevUnkMmioRead0x03010104, NULL, pThis,
                                     &pThis->hMmio0x03010104);

#if 0
    if (!rc)
        rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03200044, 4,
                                     pspDevUnkMmioRead0x03006038, NULL, pThis,
                                     &pThis->hMmio0x03200044);
#endif
    return rc;
}


static void pspDevMmioUnkDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegMmioUnk =
{
    /** pszName */
    "mmio-unknown",
    /** pszDesc */
    "Unknown MMIO registers device",
    /** cbInstance */
    sizeof(PSPDEVUNK),
    /** pfnInit */
    pspDevMmioUnkInit,
    /** pfnDestruct */
    pspDevMmioUnkDestruct
};

