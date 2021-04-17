/** @file
 * PSP Emulator - Device interface.
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
#include <stdlib.h>

#include <common/types.h>
#include <common/cdefs.h>
#include <common/status.h>

#include <psp-dev.h>


int PSPEmuDevCreate(PSPIOM hIoMgr, PCPSPDEVREG pDevReg, PCPSPDEVIF pDevIf, PCPSPEMUCFG pCfg, PPSPDEV *ppDev)
{
    int rc = 0;
    PPSPDEV pDev = (PPSPDEV)calloc(1, sizeof(*pDev) + pDevReg->cbInstance);
    if (pDev)
    {
        pDev->pReg      = pDevReg;
        pDev->pDevIf    = pDevIf;
        pDev->hIoMgr    = hIoMgr;
        pDev->pCfg      = pCfg;

        /* Initialize the device instance and add to the list of known devices. */
        rc = pDev->pReg->pfnInit(pDev);
        if (!rc)
        {
            *ppDev = pDev;
            return STS_INF_SUCCESS;
        }

        free(pDev);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}

int PSPEmuDevDestroy(PPSPDEV pDev)
{
    pDev->pReg->pfnDestruct(pDev);
    free(pDev);

    return STS_INF_SUCCESS;
}

