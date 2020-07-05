/** @file
 * PSP Emulator - x86 memory regions present in the system (secure DRAM, etc.).
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

#include <common/cdefs.h>

#include <psp-devs.h>


/**
 * x86 memory device instance data.
 */
typedef struct PSPDEVX86MEM
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** Secure DRAM region handle. */
    PSPIOMREGIONHANDLE      hMemSecureDram;
} PSPDEVX86MEM;
/** Pointer to the device instance data. */
typedef PSPDEVX86MEM *PPSPDEVX86MEM;


static int pspDevX86MemInit(PPSPDEV pDev)
{
    PPSPDEVX86MEM pThis = (PPSPDEVX86MEM)&pDev->abInstance[0];

    pThis->pDev = pDev;

    /* Register secure DRAM ranges. */
    int rc = PSPEmuIoMgrX86MemRegister(pDev->hIoMgr, 0xfffdf8000000, 64 * _1M, true /*fCanExec*/,
                                       NULL /*pfnFetch*/, NULL,
                                       "SecureDram", &pThis->hMemSecureDram);
    return rc;
}


static void pspDevX86MemDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegX86Mem =
{
    /** pszName */
    "x86-mem",
    /** pszDesc */
    "x86 memory",
    /** cbInstance */
    sizeof(PSPDEVX86MEM),
    /** pfnInit */
    pspDevX86MemInit,
    /** pfnDestruct */
    pspDevX86MemDestruct,
    /** pfnReset */
    NULL
};

