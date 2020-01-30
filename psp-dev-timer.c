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

#include <common/cdefs.h>

#include <psp-devs.h>


/**
 * Sub timer structure.
 */
typedef struct PSPDEVSUBTIMER
{
    /** The control register perhaps. */
    uint32_t                        regCtrl;
    /** The counter running at 100MHz. */
    uint32_t                        regCnt100MHz;
} PSPDEVSUBTIMER;
/** Pointer to a sub timer. */
typedef PSPDEVSUBTIMER *PPSPDEVSUBTIMER;


/**
 * Timer device instance data.
 */
typedef struct PSPDEVTIMER
{
    /* Two sub timers:
     *     - 0x03010400
     *     - 0x03010424
     */
    PSPDEVSUBTIMER                  aSubTimers[2];
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
    PPSPDEVSUBTIMER pSubTimer = offMmio < 0x24 ? &pThis->aSubTimers[0] : &pThis->aSubTimers[1];

    if (offMmio >= 0x24)
        offMmio -= 0x24;

    switch (offMmio)
    {
        case 0: /* Control register */
        {
            *pu32Ret = pSubTimer->regCnt100MHz;
            break;
        }
        case 32: /* 100MHz counter. */
        {
            *pu32Ret = pSubTimer->regCnt100MHz;
            if (pSubTimer->regCtrl & 0x1)
                pSubTimer->regCnt100MHz++;
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

    if (   cbWrite != sizeof(uint32_t)
        && cbWrite != sizeof(uint8_t))
    {
        printf("%s: offMmio=%#x cbWrite=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbWrite);
        return;
    }

    uint32_t u32Val = 0;
    if (cbWrite == sizeof(uint32_t))
        u32Val = *(uint32_t *)pvVal;
    else
        u32Val = *(uint8_t *)pvVal;
    PPSPDEVSUBTIMER pSubTimer = offMmio < 0x24 ? &pThis->aSubTimers[0] : &pThis->aSubTimers[1];

    if (offMmio >= 0x24)
        offMmio -= 0x24;

    switch (offMmio)
    {
        case 0: /* Control register */
        {
            pSubTimer->regCtrl = u32Val;
            break;
        }
        case 1: /* XXX For single byte access by the on chip bl... */
        {
            pSubTimer->regCtrl |= u32Val << 8;
            break;
        }
        case 32: /* 100MHz counter. */
        {
            pSubTimer->regCnt100MHz = u32Val;
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

    for (uint32_t i = 0; i < ELEMENTS(pThis->aSubTimers); i++)
    {
        PPSPDEVSUBTIMER pSubTimer = &pThis->aSubTimers[i];

        pSubTimer->regCtrl      = 0;
        pSubTimer->regCnt100MHz = 0;
    }

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03010400, 2*36,
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

