/** @file
 * PSP Emulator - Timer device starting at 0x03010424.
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
 * Timer device instance data.
 */
typedef struct PSPDEVTIMER
{
    /** The control register perhaps. */
    uint32_t                        regCtrl;
    /** The counter running at 100MHz. */
    uint32_t                        regCnt100MHz;
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE              hMmio;
} PSPDEVTIMER;
/** Pointer to the device instance data. */
typedef PSPDEVTIMER *PPSPDEVTIMER;


static void pspDevTimerMmioRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVTIMER pThis = (PPSPDEVTIMER)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        printf("%s: offMmio=%#x cbRead=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbRead);
        return;
    }

    uint32_t *pu32Ret = (uint32_t *)pvVal;
    switch (offMmio)
    {
        case 0: /* Control register */
        {
            *pu32Ret = pThis->regCnt100MHz;
            break;
        }
        case 32: /* 100MHz counter. */
        {
            *pu32Ret = pThis->regCnt100MHz;
            if (pThis->regCtrl & 0x1) /* could be the enable bit 0x100 is another candidate. */
                pThis->regCnt100MHz++;
            break;
        }
        default:
            /* Ignore for now. */
            break;
    }
}

static void pspDevTimerMmioWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVTIMER pThis = (PPSPDEVTIMER)pvUser;

    if (cbWrite != sizeof(uint32_t))
    {
        printf("%s: offMmio=%#x cbWrite=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbWrite);
        return;
    }

    uint32_t u32Val = *(uint32_t *)pvVal;
    switch (offMmio)
    {
        case 0: /* Control register */
        {
            pThis->regCtrl = u32Val;
            break;
        }
        case 32: /* 100MHz counter. */
        {
            pThis->regCnt100MHz = u32Val;
            break;
        }
        default:
            /* Ignore for now. */
            break;
    }
}


static int pspDevTimerInit(PPSPDEV pDev)
{
    PPSPDEVTIMER pThis = (PPSPDEVTIMER)&pDev->abInstance[0];

    pThis->regCtrl      = 0;
    pThis->regCnt100MHz = 0;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03010424, 36,
                                     pspDevTimerMmioRead, pspDevTimerMmioWrite, pThis,
                                     &pThis->hMmio);
    return rc;
}

static void pspDevTimerDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegTimer =
{
    /** pszName */
    "timer",
    /** pszDesc */
    "Timer device starting at 0x03010424",
    /** cbInstance */
    sizeof(PSPDEVTIMER),
    /** pfnInit */
    pspDevTimerInit,
    /** pfnDestruct */
    pspDevTimerDestruct,
};

