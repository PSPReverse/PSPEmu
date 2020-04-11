/** @file
 * PSP Emulator - Test device starting at 0x04000000.
 */

/*
 * Copyright (C) 2020 Niklas Jacob <hnj@posteo.de>
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
#include <stdlib.h>
#include <sys/ioctl.h>

#include <psp-devs.h>

/*
This test device is supposed to help debugging a firmware in an emulator.
The interface is very simple, at 0x04000000 there are three memmory mapped registers:

0x04000000: available register (32-bit, RO)
    bits 0-31 unsinged int
        How many bytes can currently be read from the read register.

0x04000004: read register (32-bit, RO)
    bits 0-7 char
        Reads the next char that is available as input or zero if none are available.
        Writing has no effect but might be reported.
    bits 8-31 unused
        Read as zero.
        Writing has no effect but might be reported.

0x04000008: write register (32-bit, RW)
    bits 0-7 char
        Writing to this register causes a char to be printed on the test console.
        Reads as zero.
    bits 8-31 unused
        Writing has no effect but might be reported.
        Read as zero.

0x0400000c: exit register (32-bit, W)
    bits 0-31
        Writing to this register cases the emulator to exit with
        (written value << 1) | 1 as exit code.
        Reads as zero.

*/

#define PSP_TEST_AVAILABLE_OFFSET 0
#define PSP_TEST_READ_OFFSET 4
#define PSP_TEST_WRITE_OFFSET 8
#define PSP_TEST_EXIT_OFFSET 12

/**
 * Test device instance data none required.
 */
typedef struct PSPDEVTEST
{
    /*+ MMIO region handle. */
    PSPIOMREGIONHANDLE  hMmio;
} PSPDEVTEST;

/** Pointer to the device instance data. */
typedef PSPDEVTEST  *PPSPDEVTEST;

static void pspDevTestMmioRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{

    if (cbRead != sizeof(uint32_t))
    {
        printf("%s: offMmio=%#x cbRead=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbRead);
        return;
    }

    uint32_t available;
    if (ioctl(0, FIONREAD, &available)) {
        perror("ioctl call for available bytes");
        available = 0;
    }

    uint32_t *pu32Ret = (uint32_t *)pvVal;
    *pu32Ret = 0;
    switch (offMmio)
    {
        case PSP_TEST_AVAILABLE_OFFSET:
            *pu32Ret = available;
            break;

        case PSP_TEST_READ_OFFSET:
            if (available)
                *pu32Ret = getchar();
            else
                printf("%s: Reading when no chars are available\n", __FUNCTION__);
            break;

        case PSP_TEST_WRITE_OFFSET:
            printf("%s: Reading form the write register\n", __FUNCTION__);
            break;

        case PSP_TEST_EXIT_OFFSET:
            printf("%s: Reading form the exit register\n", __FUNCTION__);
            break;

        default:
            printf("%s: offMmio=%#x cbRead=%zu -> Unsupported access address\n", __FUNCTION__, offMmio, cbRead);
    }
}

static void pspDevTestMmioWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    if (cbWrite != sizeof(uint32_t))
    {
        printf("%s: offMmio=%#x cbWrite=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbWrite);
        return;
    }

    uint32_t u32Val = *(uint32_t *)pvVal;
    switch (offMmio)
    {
        case PSP_TEST_AVAILABLE_OFFSET:
            printf("%s: Writing to available register\n", __FUNCTION__);
            break;

        case PSP_TEST_READ_OFFSET:
            printf("%s: Writing to read register\n", __FUNCTION__);
            break;

        case PSP_TEST_WRITE_OFFSET:
            putchar(u32Val);
            break;

        case PSP_TEST_EXIT_OFFSET:
            exit((u32Val << 1) | 1);
            break;

        default:
            printf("%s: offMmio=%#x cbWrite=%zu -> Unsupported access address\n", __FUNCTION__, offMmio, cbWrite);
    }
}

static int pspDevTestInit(PPSPDEV pDev)
{
    PPSPDEVTEST pThis = (PPSPDEVTEST)&pDev->abInstance[0];

    // disable buffering for sdtio
    setvbuf(stdin, NULL, _IONBF ,0);
    setvbuf(stdout, NULL, _IONBF ,0);

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03133700, 16,
                                     pspDevTestMmioRead, pspDevTestMmioWrite, pThis,
                                     "Test", &pThis->hMmio);
    return rc;
}

static void pspDevTestDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}

/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegTest =
{
    /** pszName */
    "test",
    /** pszDesc */
    "Test device starting at 0x03133700",
    /** cbInstance */
    sizeof(PSPDEVTEST),
    /** pfnInit */
    pspDevTestInit,
    /** pfnDestruct */
    pspDevTestDestruct,
    /** pfnReset */
    NULL
};

