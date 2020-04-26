/** @file
 * PSP Emulator - LPC host bridge device implementation.
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
 * LPC device instance data.
 */
typedef struct PSPDEVLPC
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** MMIO region handle for the SuperIO access port. */
    PSPIOMREGIONHANDLE      hMmioX86;
} PSPDEVLPC;
/** Pointer to an LPC device instance. */
typedef PSPDEVLPC *PPSPDEVLPC;


static void pspDevLpcRead(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVLPC pBank = (PPSPDEVLPC)pvUser;

    if (cbRead != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_LPC,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    /** @todo */
}


static void pspDevLpcWrite(X86PADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVLPC pBank = (PPSPDEVLPC)pvUser;

    if (cbWrite != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_LPC,
                                "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        return;
    }

    /** @todo */
}


static int pspDevLpcInit(PPSPDEV pDev)
{
    int rc = 0;
    PPSPDEVLPC pThis = (PPSPDEVLPC)&pDev->abInstance[0];

    pThis->pDev = pDev;
    /** @todo: Emulate PCI config space so we can catch the actual range used
     * for wide I/O instead of hardocding it here. */
    rc = PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfffdfc00164e, 2,
                                    pspDevLpcRead, pspDevLpcWrite, pThis,
                                    "LPC host bridge", &pThis->hMmioX86);

    return rc;
}


static void pspDevLpcDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegLpc =
{
    /** pszName */
    "lpc",
    /** pszDesc */
    "LPC host bridge",
    /** cbInstance */
    sizeof(PSPDEVLPC),
    /** pfnInit */
    pspDevLpcInit,
    /** pfnDestruct */
    pspDevLpcDestruct,
    /** pfnReset */
    NULL
};

