/** @file
 * PSP Emulator - ACPI PM interface accessible through x86 MMIO.
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
#include <psp-trace.h>


/**
 * ACPI device instance data.
 */
typedef struct PSPDEVACPI
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE      hMmioX86;
} PSPDEVACPI;
/** Pointer to the device instance data. */
typedef PSPDEVACPI *PPSPDEVACPI;

static void pspDevX86AcpiRead(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVACPI pThis = (PPSPDEVACPI)pvUser;

    if (cbRead != sizeof(uint16_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_ACPI,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    uint16_t *pu16Val = (uint16_t *)pvVal;
    switch (pThis->pDev->pCfg->enmAcpiState)
    {
        case PSPEMUACPISTATE_S0:
            *pu16Val = (0 & 0x7) << 10;
            break;
        case PSPEMUACPISTATE_S1:
            *pu16Val = (1 & 0x7) << 10;
            break;
        case PSPEMUACPISTATE_S2:
            *pu16Val = (2 & 0x7) << 10;
            break;
        case PSPEMUACPISTATE_S3:
            *pu16Val = (3 & 0x7) << 10;
            break;
        case PSPEMUACPISTATE_S4:
            *pu16Val = (4 & 0x7) << 10;
            break;
        case PSPEMUACPISTATE_S5:
            *pu16Val = (5 & 0x7) << 10;
            break;
        default:
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_ACPI,
                                    "Invalid ACPI state configured: %d", pThis->pDev->pCfg->enmAcpiState);
    }
}

static int pspDevAcpiInit(PPSPDEV pDev)
{
    PPSPDEVACPI pThis = (PPSPDEVACPI)&pDev->abInstance[0];

    pThis->pDev     = pDev;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfed80804, 2,
                                        pspDevX86AcpiRead, NULL, pThis,
                                        "AcpiPmCtrl", &pThis->hMmioX86);
    return rc;
}


static void pspDevAcpiDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegAcpi =
{
    /** pszName */
    "acpi",
    /** pszDesc */
    "ACPI related interfaces",
    /** cbInstance */
    sizeof(PSPDEVACPI),
    /** pfnInit */
    pspDevAcpiInit,
    /** pfnDestruct */
    pspDevAcpiDestruct,
    /** pfnReset */
    NULL
};

