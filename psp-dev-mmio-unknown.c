/** @file
 * PSP Emulator - Unknown devices mapped directly into MMIO space.
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

#include <psp-devs.h>


/**
 * Unknown device instance data.
 */
typedef struct PSPDEVUNK
{
    /** Pointer to the owning device instance. */
    PPSPDEV                     pDev;
    /** 0x03006038 register handle. */
    PSPIOMREGIONHANDLE          hMmio0x03006038;
    /** 0x03200044 register handle. */
    PSPIOMREGIONHANDLE          hMmio0x03200044;
    /** 0x0301003c register handle. */
    PSPIOMREGIONHANDLE          hMmio0x0301003c;
    /** 0x030101c0 register handle for Zen2. */
    PSPIOMREGIONHANDLE          hMmio0x030101c0;
    /** 0x0320004c register handle. */
    PSPIOMREGIONHANDLE          hMmio0x0320004c;
    /** 0x03200048 register handle. */
    PSPIOMREGIONHANDLE          hMmio0x03200048;

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

static void pspDevUnkMmioRead0x0301003c(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVUNK pThis = (PPSPDEVUNK)pvUser;
    bool fPspDbgMode = pThis->pDev->pCfg->fPspDbgMode;

    *(uint32_t *)pvVal = fPspDbgMode ? 0x1 : 0; /* Enables debug output on a Ryzen Pro off chip bootloaders. */
}

static void pspDevUnkMmioRead0x030101c0(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVUNK pThis = (PPSPDEVUNK)pvUser;
    bool fPspDbgMode = pThis->pDev->pCfg->fPspDbgMode;

    *(uint32_t *)pvVal = fPspDbgMode ? 0x80102 : 0x100; /* Disables signature verification in Zen2 off chip BLs. */
}

static void pspDevUnkMmioRead0x0320004c(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0xbc090000;
}

static void pspDevUnkMmioRead0x03200048(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0xbc0b0500;
}


static int pspDevMmioUnkInit(PPSPDEV pDev)
{
    PPSPDEVUNK pThis = (PPSPDEVUNK)&pDev->abInstance[0];

    pThis->pDev = pDev;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03006038, 4,
                                     pspDevUnkMmioRead0x03006038, NULL, pThis,
                                     NULL /*pszDesc*/, &pThis->hMmio0x03006038);

    /* For the Ryzen off chip bootloader determining whether to print strings to x86 UART. */
    if (!rc)
        rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x0301003c, 4,
                                     pspDevUnkMmioRead0x0301003c, NULL, pThis,
                                     NULL /*pszDesc*/, &pThis->hMmio0x0301003c);

    if (   !rc
        && pDev->pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2)
        rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x030101c0, 4,
                                     pspDevUnkMmioRead0x030101c0, NULL, pThis,
                                     NULL /*pszDesc*/, &pThis->hMmio0x030101c0);

    if (!rc)
        rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x0320004c, 4,
                                     pspDevUnkMmioRead0x0320004c, NULL, pThis,
                                     NULL /*pszDesc*/, &pThis->hMmio0x0320004c);

    /* Zen2 Ryzen on chip BL reads that. */
    if (!rc)
        rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03200048, 4,
                                     pspDevUnkMmioRead0x03200048, NULL, pThis,
                                     NULL /*pszDesc*/, &pThis->hMmio0x03200048);

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
    pspDevMmioUnkDestruct,
    /** pfnReset */
    NULL
};

