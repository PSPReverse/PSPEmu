/** @file
 * PSP Emulator - Some sort of version(?) register mapped into MMIO space.
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

#include <psp-devs.h>


/**
 * Version device instance data.
 */
typedef struct PSPDEVVERS
{
    /** Pointer to the owning device instance. */
    PPSPDEV                     pDev;
    /** version register handle. */
    PSPIOMREGIONHANDLE          hMmioVersion;
    /** The version register value written. */
    uint32_t                    u32RegVersion;
} PSPDEVVERS;
/** Pointer to the device instance data. */
typedef PSPDEVVERS *PPSPDEVVERS;


static void pspDevVersMmioRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVVERS pThis = (PPSPDEVVERS)pvUser;
    *(uint32_t *)pvVal = pThis->u32RegVersion;
}


static void pspDevVersMmioWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    /*
     * This is written once by the on chip bootloader right at the beginning and
     * read later on to determine the L1 PSP directory to select.
     */
    PPSPDEVVERS pThis = (PPSPDEVVERS)pvUser;
    pThis->u32RegVersion = *(uint32_t *)pvVal;
}


static int pspDevMmioVersInit(PPSPDEV pDev)
{
    PPSPDEVVERS pThis = (PPSPDEVVERS)&pDev->abInstance[0];

    pThis->pDev = pDev;
    return PSPEmuIoMgrMmioRegister(pDev->hIoMgr, pDev->pCfg->pPspProfile->PspAddrMmioVersion, 4,
                                   pspDevVersMmioRead, pspDevVersMmioWrite, pThis,
                                   "RegVersion", &pThis->hMmioVersion);
}


static void pspDevMmioVersDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegMmioVersion =
{
    /** pszName */
    "version",
    /** pszDesc */
    "Version register device",
    /** cbInstance */
    sizeof(PSPDEVVERS),
    /** pfnInit */
    pspDevMmioVersInit,
    /** pfnDestruct */
    pspDevMmioVersDestruct,
    /** pfnReset */
    NULL
};

