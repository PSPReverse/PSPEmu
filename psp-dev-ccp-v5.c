/** @file
 * PSP Emulator - CCPv5 device.
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
 * CCP device instance data.
 */
typedef struct PSPDEVCCP
{
    uint8_t uDummy;
} PSPDEVCCP;
/** Pointer to the device instance data. */
typedef PSPDEVCCP *PPSPDEVCCP;

static int pspDevCcpInit(PPSPMMIODEV pDev)
{
    /* Nothing to do. */
    return 0;
}

static void pspDevCcpDestruct(PPSPMMIODEV pDev)
{
    /* Nothing to do so far. */
}

static void pspDevCcpMmioRead(PPSPMMIODEV pDev, PSPADDR offMmio, size_t cbRead, void *pvVal)
{
    printf("%s: offMmio=%#x cbRead=%zu\n", __FUNCTION__, offMmio, cbRead);
}

static void pspDevCcpMmioWrite(PPSPMMIODEV pDev, PSPADDR offMmio, size_t cbWrite, const void *pvVal)
{
    printf("%s: offMmio=%#x cbWrite=%zu\n", __FUNCTION__, offMmio, cbWrite);

    switch (cbWrite)
    {
        case 4:
            printf("    u32Val=%#x\n", *(uint32_t *)pvVal);
            break;
    }
}


/**
 * Device registration structure.
 */
const PSPMMIODEVREG g_MmioDevRegCcpV5 =
{
    /** pszName */
    "ccp-v5",
    /** pszDesc */
    "CCPv5",
    /** cbInstance */
    sizeof(PSPDEVCCP),
    /** cbMmio */
    2 * 4096,
    /** pfnInit */
    pspDevCcpInit,
    /** pfnDestruct */
    pspDevCcpDestruct,
    /** pfnMmioRead */
    pspDevCcpMmioRead,
    /** pfnMmioWrite */
    pspDevCcpMmioWrite
};

