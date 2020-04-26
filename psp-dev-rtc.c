/** @file
 * PSP Emulator - Standard RTC/CMOS device implementation.
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
#include <psp-trace.h>


/** 128 bytes per CMOS bank. */
#define PSPEMU_RTC_CMOS_BANK_SZ         128

/** Pointer to the device instance data. */
typedef struct PSPDEVRTC *PPSPDEVRTC;


/**
 * Single CMOS bank with values.
 */
typedef struct CMOSBANK
{
    /** Pointer to the owning device. */
    PPSPDEVRTC              pDev;
    /** MMIO region handle for this bank. */
    PSPIOMREGIONHANDLE      hMmioX86;
    /** The bank number. */
    uint32_t                idBank;
    /** The current selected offset in the CMOS bank. */
    uint8_t                 offBank;
    /** The CMOS bank data. */
    uint8_t                 abBank[PSPEMU_RTC_CMOS_BANK_SZ];
} CMOSBANK;
/** Pointer to a GPIO bank. */
typedef CMOSBANK *PCMOSBANK;
/** Pointer to a const bank. */
typedef const CMOSBANK *PCCMOSBANK;


/**
 * GPIO device instance data.
 */
typedef struct PSPDEVRTC
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** The GPIO banks. */
    CMOSBANK                aBanks[2];
} PSPDEVRTC;


static const char *s_apszCmosBankDesc[] =
{
    "CMOS Bank 0",
    "CMOS Bank 1"
};


static void pspDevRtcCmosBankRead(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PCCMOSBANK pBank = (PCCMOSBANK)pvUser;

    if (cbRead != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_GPIO,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    uint8_t *pbVal = (uint8_t *)pvVal;
    if (offMmio == 0)
        *pbVal = 0xff; /* Address register is write-only. */
    else
        *pbVal = pBank->abBank[pBank->offBank];
}


static void pspDevRtcCmosBankWrite(X86PADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PCMOSBANK pBank = (PCMOSBANK)pvUser;

    if (cbWrite != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_GPIO,
                                "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        return;
    }

    uint8_t bVal = *(const uint8_t *)pvVal;
    if (offMmio == 0)
        pBank->offBank = bVal & 0x7f;
    else
        pBank->abBank[pBank->offBank] = bVal;
}


static int pspDevRtcInit(PPSPDEV pDev)
{
    int rc = 0;
    PPSPDEVRTC pThis = (PPSPDEVRTC)&pDev->abInstance[0];

    pThis->pDev = pDev;

    for (uint32_t i = 0; i < ELEMENTS(pThis->aBanks) && !rc; i++)
    {
        PCMOSBANK pBank = &pThis->aBanks[i];

        pBank->pDev   = pThis;
        pBank->idBank = i;

        rc = PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfffdfc000070 + i * 2, 2,
                                        pspDevRtcCmosBankRead, pspDevRtcCmosBankWrite, pBank,
                                        s_apszCmosBankDesc[i], &pBank->hMmioX86);
    }

    return rc;
}


static void pspDevRtcDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegRtc =
{
    /** pszName */
    "rtc",
    /** pszDesc */
    "RTC/CMOS device",
    /** cbInstance */
    sizeof(PSPDEVRTC),
    /** pfnInit */
    pspDevRtcInit,
    /** pfnDestruct */
    pspDevRtcDestruct,
    /** pfnReset */
    NULL
};

