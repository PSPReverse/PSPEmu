/** @file
 * PSP Emulator - Some sort of fuse information which is mapped into MMIO and SMN space.
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

#include <common/cdefs.h>

#include <psp-devs.h>


/**
 * Fuse device instance data.
 */
typedef struct PSPDEVFUSE
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE      hMmio;
    /** SMN region handle. */
    PSPIOMREGIONHANDLE      hSmn;
    /** MMIO region handle for some key size fuse on Zen2. */
    PSPIOMREGIONHANDLE      hMmioKeySz;
} PSPDEVFUSE;
/** Pointer to the device instance data. */
typedef PSPDEVFUSE *PPSPDEVFUSE;


static void pspDevFuseRegRead(uint32_t offReg, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVFUSE pThis = (PPSPDEVFUSE)pvUser;
    bool fPspDbgMode = pThis->pDev->pCfg->fPspDbgMode;

    switch (offReg)
    {
        case 0:
            /*
             * The on chip bootloader waits in on_chip_bl_main() until bit 8 is set
             * and this is also read from SMN and expected to match whats read from MMIO
             * in psp_verify_equal_fuse_info_on_all_ccx_hang_on_mismatch().
             */
            *(uint32_t *)pvVal = 0x1a060900 | (fPspDbgMode ? BIT(10) : 0); /* Value read from a real EPYC system. */
            break;
    }
}

static void pspDevFuseMmioRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    pspDevFuseRegRead(offMmio, cbRead, pvVal, pvUser);
}


static void pspDevFuseSmnRead(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    pspDevFuseRegRead(offSmn, cbRead, pvVal, pvUser);
}


static void pspDevFuseKeySzMmioRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    if (cbRead != sizeof(uint32_t))
    {
        printf("%s: offMmio=%#x cbRead=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbRead);
        return;
    }

    /* Zen2 uses 4096 bit modulus and the key size is determined from this register. */
    *(uint32_t *)pvVal = BIT(8) | BIT(9);
}


static int pspDevMmioFuseInit(PPSPDEV pDev)
{
    PPSPDEVFUSE pThis = (PPSPDEVFUSE)&pDev->abInstance[0];

    pThis->pDev = pDev;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03010104, 4,
                                     pspDevFuseMmioRead, NULL, pThis,
                                     "Fuse1", &pThis->hMmio);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x03810104, 4,
                                    pspDevFuseSmnRead, NULL, pThis,
                                    "Fuse1", &pThis->hSmn);
    if (   !rc
        && pDev->pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2)
        rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x3200050, 4,
                                     pspDevFuseKeySzMmioRead, NULL, pThis,
                                     "FuseKeySz", &pThis->hMmioKeySz);
    return rc;
}


static void pspDevMmioFuseDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegFuse =
{
    /** pszName */
    "fuse",
    /** pszDesc */
    "Fuse device mapped into MMIO and SMN space",
    /** cbInstance */
    sizeof(PSPDEVFUSE),
    /** pfnInit */
    pspDevMmioFuseInit,
    /** pfnDestruct */
    pspDevMmioFuseDestruct,
    /** pfnReset */
    NULL
};

