/** @file
 * PSP Emulator - Unknown device residing at 0x03200000.
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

#include <common/cdefs.h>

#include <psp-devs.h>


/**
 * Unknown device instance data.
 */
typedef struct PSPDEVUNK
{
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE      hMmio;
} PSPDEVUNK;
/** Pointer to the device instance data. */
typedef PSPDEVUNK *PPSPDEVUNK;

static void pspDevX86UnkMmioRead(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offMmio=%#llx cbRead=%zu\n", __FUNCTION__, offMmio, cbRead);

    if (cbRead != sizeof(uint8_t))
    {
        printf("%s: Unsupported read size cbRead=%zu\n", __FUNCTION__, cbRead);
        return;
    }

    switch (offMmio)
    {
        case 0:
            /* The off chip bootloader waits for bits 0-2 to be set. */
            *(uint8_t *)pvVal = 0x7;
            break;
    }
}

static int pspDevX86UnkInit(PPSPDEV pDev)
{
    PPSPDEVUNK pThis = (PPSPDEVUNK)&pDev->abInstance[0];

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfed81e77, 1,
                                        pspDevX86UnkMmioRead, NULL, NULL,
                                        NULL /*pszDesc*/, &pThis->hMmio);

    return rc;
}

static void pspDevX86UnkDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegX86Unk =
{
    /** pszName */
    "x86-unknown",
    /** pszDesc */
    "Unknown X86 MMIO registers device",
    /** cbInstance */
    sizeof(PSPDEVUNK),
    /** pfnInit */
    pspDevX86UnkInit,
    /** pfnDestruct */
    pspDevX86UnkDestruct,
    /** pfnReset */
    NULL
};

