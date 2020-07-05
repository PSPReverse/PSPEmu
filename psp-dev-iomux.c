/** @file
 * PSP Emulator - IOMUX registers as obtained from AMD PPR.
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


/**
 * I/O MUX device instance data.
 */
typedef struct PSPDEVIOMUX
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE      hMmioX86;
    /** I/O mux register values. */
    uint8_t                 aIoMuxRegs[145];
} PSPDEVIOMUX;
/** Pointer to the device instance data. */
typedef struct PSPDEVIOMUX *PPSPDEVIOMUX;


static void pspDevX86IoMuxRead(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVIOMUX pThis = (PPSPDEVIOMUX)pvUser;

    if (cbRead != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_IOMUX,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    *(uint8_t *)pvVal = pThis->aIoMuxRegs[offMmio];
}


static void pspDevX86IoMuxWrite(X86PADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVIOMUX pThis = (PPSPDEVIOMUX)pvUser;

    if (cbWrite != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_IOMUX,
                                "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        return;
    }

    pThis->aIoMuxRegs[offMmio] = *(const uint8_t *)pvVal;
}


static int pspDevIoMuxInit(PPSPDEV pDev)
{
    PPSPDEVIOMUX pThis = (PPSPDEVIOMUX)&pDev->abInstance[0];

    pThis->pDev = pDev;

    return PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfed80d00, sizeof(pThis->aIoMuxRegs),
                                      pspDevX86IoMuxRead, pspDevX86IoMuxWrite, pThis,
                                      "I/O MUX", &pThis->hMmioX86);
}


static void pspDevIoMuxDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegIoMux =
{
    /** pszName */
    "iomux",
    /** pszDesc */
    "I/O MUX registers",
    /** cbInstance */
    sizeof(PSPDEVIOMUX),
    /** pfnInit */
    pspDevIoMuxInit,
    /** pfnDestruct */
    pspDevIoMuxDestruct,
    /** pfnReset */
    NULL
};

