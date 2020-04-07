/** @file
 * PSP Emulator - x86 memory regions present in the system (secure DRAM, etc.).
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
    int rc = PSPEmuIoMgrX86MemRegister(pDev->hIoMgr, 0xfffdfb000000, 16 * _1M, true /*fCanExec*/,
                                       NULL /*pfnFetch*/, NULL, &pThis->hMemSecureDram);
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

