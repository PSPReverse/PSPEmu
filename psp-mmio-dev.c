/** @file
 * PSP Emulator - MMIO devices interface.
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

#include <stdlib.h>

#include <common/types.h>

#define IN_PSP_EMULATOR
#include <psp-mmio-dev.h>



static void pspEmuMmioDevRead(PSPCORE hCore, PSPADDR uPspAddr, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPMMIODEV pDev = (PPSPMMIODEV)pvUser;

    pDev->pReg->pfnMmioRead(pDev, uPspAddr, cbRead, pvDst);
}

static void pspEmuMmioDevWrite(PSPCORE hCore, PSPADDR uPspAddr, size_t cbWrite, const void *pvSrc, void *pvUser)
{
    PPSPMMIODEV pDev = (PPSPMMIODEV)pvUser;

    pDev->pReg->pfnMmioWrite(pDev, uPspAddr, cbWrite, pvSrc);
}


int PSPEmuMmioDevCreate(PSPCORE hPspCore, PCPSPMMIODEVREG pDevReg, PSPADDR PspAddrMmioStart, PPSPMMIODEV *ppMmioDev)
{
    int rc = 0;
    PPSPMMIODEV pDev = (PPSPMMIODEV)calloc(1, sizeof(*pDev) + pDevReg->cbInstance);
    if (pDev)
    {
        pDev->pReg     = pDevReg;
        pDev->hPspCore = hPspCore;
        pDev->MmioStart = PspAddrMmioStart;

        /* Initialize the device instance and register with the PSP core if successful. */
        rc = pDev->pReg->pfnInit(pDev);
        if (!rc)
        {
            rc = PSPEmuCoreMmioRegister(hPspCore, PspAddrMmioStart, pDevReg->cbMmio,
                                        pspEmuMmioDevRead, pspEmuMmioDevWrite,
                                        pDev);
            if (!rc)
            {
                *ppMmioDev = pDev;
                return 0;
            }

            pDev->pReg->pfnDestruct(pDev);
        }

        free(pDev);
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuMmioDevDestroy(PPSPMMIODEV pMmioDev)
{
    int rc = PSPEmuCoreMmioDeregister(pMmioDev->hPspCore, pMmioDev->MmioStart, pMmioDev->pReg->cbMmio);
    /** @todo assert(rc == 0) */

    free(pMmioDev);
}

