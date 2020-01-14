/** @file
 * PSP Emulator - Unknown SMN device residing at 0x0005e000.
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
    uint8_t uDummy;
} PSPDEVUNK;
/** Pointer to the device instance data. */
typedef PSPDEVUNK *PPSPDEVUNK;

static int pspDevUnkInit(PPSPSMNDEV pDev)
{
    /* Nothing to do. */
    return 0;
}

static void pspDevUnkDestruct(PPSPSMNDEV pDev)
{
    /* Nothing to do so far. */
}

static void pspDevUnkSmnRead(PPSPSMNDEV pDev, SMNADDR offSmn, size_t cbRead, void *pvVal)
{
    printf("%s: offSmn=%#x cbRead=%zu\n", __FUNCTION__, offSmn, cbRead);

    switch (offSmn)
    {
        case 0x0:
            /* The on chip bootloader waits for bit 0 to go 1. */
            *(uint32_t *)pvVal = 0x1;
            break;
    }
}

static void pspDevUnkSmnWrite(PPSPSMNDEV pDev, SMNADDR offSmn, size_t cbWrite, const void *pvVal)
{
    printf("%s: offSmn=%#x cbWrite=%zu\n", __FUNCTION__, offSmn, cbWrite);

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
const PSPSMNDEVREG g_SmnDevRegUnk0x0005e000 =
{
    /** pszName */
    "smn-unk-0x0005e000",
    /** pszDesc */
    "Unknown SMN device starting at 0x0005e000",
    /** cbInstance */
    sizeof(PSPDEVUNK),
    /** cbSmn */
    4,
    /** pfnInit */
    pspDevUnkInit,
    /** pfnDestruct */
    pspDevUnkDestruct,
    /** pfnSmnRead */
    pspDevUnkSmnRead,
    /** pfnSmnWrite */
    pspDevUnkSmnWrite
};

