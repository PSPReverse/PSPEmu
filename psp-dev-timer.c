/** @file
 * PSP Emulator - Timer device starting at 0x03010400 and 0x03010424.
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

#include <os/time.h>

#include <psp-devs.h>


/**
 * Timer device instance data.
 */
typedef struct PSPDEVTIMER
{
    /** Flag whether to run in realtime. */
    bool                            fRealtime;
    /** Last nanosecond timestamp. */
    uint64_t                        tsLast;
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
            *pu32Ret = pThis->regCtrl;
            break;
        }
        case 32: /* 100MHz counter. */
        {
            if (!pThis->fRealtime)
            {
                *pu32Ret = pThis->regCnt100MHz;
                if (pThis->regCtrl & 0x1)
                    pThis->regCnt100MHz++;
            }
            else
            {
                if (pThis->regCtrl & 0x1)
                {
                    uint64_t tsNow = OSTimeTsGetNano();
                    uint64_t tsElapsed = tsNow - pThis->tsLast;
                    pThis->regCnt100MHz += (uint32_t)(tsElapsed / 10); /* 10ns intervals. */
                    *pu32Ret = pThis->regCnt100MHz;
                    pThis->tsLast = tsNow;
                }
            }
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
    switch (offMmio)
    {
        case 0: /* Control register */
        {
            /* Read the time once if in realtime mode and the timer got enabled. */
            if (   pThis->fRealtime
                && (u32Val & 0x1)
                && !(pThis->regCtrl & 0x1))
                pThis->tsLast = OSTimeTsGetNano();
            pThis->regCtrl = u32Val;
            break;
        }
        case 1: /* XXX For single byte access by the on chip bl... */
        {
            pThis->regCtrl |= u32Val << 8;
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

    pThis->fRealtime    = pDev->pCfg->fTimerRealtime;
    pThis->tsLast       = OSTimeTsGetNano();
    pThis->regCtrl      = 0;
    pThis->regCnt100MHz = 0;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr,
                                       pDev->pReg == &g_DevRegTimer1
                                     ? 0x03010400
                                     : 0x03010424,
                                     sizeof(uint32_t) * 9,
                                     pspDevTimerMmioRead, pspDevTimerMmioWrite, pThis,
                                     pDev->pReg->pszName, &pThis->hMmio);
    return rc;
}

static void pspDevTimerDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegTimer1 =
{
    /** pszName */
    "timer1",
    /** pszDesc */
    "Timer device starting at 0x03010400",
    /** cbInstance */
    sizeof(PSPDEVTIMER),
    /** pfnInit */
    pspDevTimerInit,
    /** pfnDestruct */
    pspDevTimerDestruct,
    /** pfnReset */
    NULL
};


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegTimer2 =
{
    /** pszName */
    "timer2",
    /** pszDesc */
    "Timer device starting at 0x03010424",
    /** cbInstance */
    sizeof(PSPDEVTIMER),
    /** pfnInit */
    pspDevTimerInit,
    /** pfnDestruct */
    pspDevTimerDestruct,
    /** pfnReset */
    NULL
};

