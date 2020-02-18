/** @file
 * PSP Emulator - Device interface.
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
#include <common/cdefs.h>

#include <psp-dev.h>


int PSPEmuDevCreate(PSPIOM hIoMgr, PCPSPDEVREG pDevReg, PCPSPEMUCFG pCfg, PPSPDEV *ppDev)
{
    int rc = 0;
    PPSPDEV pDev = (PPSPDEV)calloc(1, sizeof(*pDev) + pDevReg->cbInstance);
    if (pDev)
    {
        pDev->pReg      = pDevReg;
        pDev->hIoMgr    = hIoMgr;
        pDev->pCfg      = pCfg;

        /* Initialize the device instance and add to the list of known devices. */
        rc = pDev->pReg->pfnInit(pDev);
        if (!rc)
        {
            *ppDev = pDev;
            return 0;
        }

        free(pDev);
    }
    else
        rc = -1;

    return rc;
}

int PSPEmuDevDestroy(PPSPDEV pDev)
{
    pDev->pReg->pfnDestruct(pDev);
    free(pDev);
}

