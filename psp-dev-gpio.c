/** @file
 * PSP Emulator - GPIO registers as obtained from AMD PPR.
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


/** Number of register per GPIO bank. */
#define PSPEMU_GPIO_DEV_REGS_PER_BANK 64

/** Pointer to the device instance data. */
typedef struct PSPDEVGPIO *PPSPDEVGPIO;


/**
 * Single GPIO bank with values.
 */
typedef struct GPIOBANK
{
    /** Pointer to the owning device. */
    PPSPDEVGPIO             pDev;
    /** MMIO region handle for this bank. */
    PSPIOMREGIONHANDLE      hMmioX86;
    /** The bank number. */
    uint32_t                idBank;
    /** The GPIO register values - 64 registers per bank. */
    uint32_t                aGpioRegs[PSPEMU_GPIO_DEV_REGS_PER_BANK];
} GPIOBANK;
/** Pointer to a GPIO bank. */
typedef GPIOBANK *PGPIOBANK;
/** Pointer to a const bank. */
typedef const GPIOBANK *PCGPIOBANK;


/**
 * GPIO device instance data.
 */
typedef struct PSPDEVGPIO
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** The GPIO banks. */
    GPIOBANK                aBanks[4];
} PSPDEVGPIO;


static const char *s_apszGpioBankDesc[] =
{
    "GPIO Bank 0",
    "GPIO Bank 1",
    "GPIO Bank 2",
    "GPIO Bank 3"
};


static void pspDevX86GpioBankRead(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PCGPIOBANK pBank = (PCGPIOBANK)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_GPIO,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    *(uint32_t *)pvVal = pBank->aGpioRegs[offMmio / sizeof(uint32_t)];
}


static void pspDevX86GpioBankWrite(X86PADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PGPIOBANK pBank = (PGPIOBANK)pvUser;

    if (cbWrite != sizeof(uint32_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_GPIO,
                                "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        return;
    }

    pBank->aGpioRegs[offMmio / sizeof(uint32_t)] = *(const uint32_t *)pvVal;
}


static int pspDevGpioInit(PPSPDEV pDev)
{
    int rc = 0;
    PPSPDEVGPIO pThis = (PPSPDEVGPIO)&pDev->abInstance[0];

    pThis->pDev = pDev;

    size_t cbBankMmio = PSPEMU_GPIO_DEV_REGS_PER_BANK * sizeof(uint32_t);
    for (uint32_t i = 0; i < ELEMENTS(pThis->aBanks) && !rc; i++)
    {
        PGPIOBANK pBank = &pThis->aBanks[i];

        pBank->pDev   = pThis;
        pBank->idBank = i;

        rc = PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfed81500 + i * cbBankMmio, cbBankMmio,
                                        pspDevX86GpioBankRead, pspDevX86GpioBankWrite, pBank,
                                        s_apszGpioBankDesc[i], &pBank->hMmioX86);
    }

    return rc;
}


static void pspDevGpioDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegGpio =
{
    /** pszName */
    "gpio",
    /** pszDesc */
    "GPIO register banks",
    /** cbInstance */
    sizeof(PSPDEVGPIO),
    /** pfnInit */
    pspDevGpioInit,
    /** pfnDestruct */
    pspDevGpioDestruct,
    /** pfnReset */
    NULL
};

