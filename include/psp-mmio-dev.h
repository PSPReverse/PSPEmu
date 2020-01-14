/** @file
 * PSP Emulator - MMIO devices interface
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
#ifndef __psp_mmio_dev_h
#define __psp_mmio_dev_h

#include <common/types.h>

#include <psp-core.h>

/** Pointer to a const PSP MMIO device registration record. */
typedef const struct PSPMMIODEVREG *PCPSPMMIODEVREG;
/** Pointer to a PSP MMIO device registration record. */
typedef struct PSPMMIODEVREG *PPSPMMIODEVREG;

/** PSP MMIO Manager handle. */
typedef struct PSPMMIOMINT *PSPMMIOM;
/** Pointer to a PSP MMIO Manager handle. */
typedef PSPMMIOM *PPSPMMIOM;


/**
 * PSP MMIO device instance.
 */
typedef struct PSPMMIODEV
{
    /** Pointer to the next device. */
    struct PSPMMIODEV       *pNext;
    /** Pointer to the device registration record. */
    PCPSPMMIODEVREG         pReg;
    /** The MMIO manager the device is attached to. */
    PSPMMIOM                hMmioMgr;
    /** Start MMIO address for the device. */
    PSPADDR                 MmioStart;
    /** Instance data - variable in size. */
    uint8_t                 abInstance[1];
} PSPMMIODEV;
typedef PSPMMIODEV *PPSPMMIODEV;
typedef const PSPMMIODEV *PCPSPMMIODEV;


/** Initialization handler. */
typedef int (FNPSPMMIODEVINIT)(PPSPMMIODEV pDev);
/** Initialization handler pointer. */
typedef FNPSPMMIODEVINIT *PFNPSPMMIODEVINIT;

/** Destruction handler. */
typedef void (FNPSPMMIODEVDESTRUCT)(PPSPMMIODEV pDev);
/** Initialization handler pointer. */
typedef FNPSPMMIODEVDESTRUCT *PFNPSPMMIODEVDESTRUCT;

/** MMIO read handler. */
typedef void (FNPSPMMIODEVMMIOREAD)(PPSPMMIODEV pDev, PSPADDR offMmio, size_t cbRead, void *pvVal);
/** MMIO read handler pointer. */
typedef FNPSPMMIODEVMMIOREAD *PFNPSPMMIODEVMMIOREAD;

/** MMIO write handler. */
typedef void (FNPSPMMIODEVMMIOWRITE)(PPSPMMIODEV pDev, PSPADDR offMmio, size_t cbRead, const void *pvVal);
/** MMIO write handler pointer. */
typedef FNPSPMMIODEVMMIOWRITE *PFNPSPMMIODEVMMIOWRITE;

/**
 * PSP MMIO device registration record.
 */
typedef struct PSPMMIODEVREG
{
    /** Device name. */
    const char              *pszName;
    /** Short device description. */
    const char              *pszDesc;
    /** Size of the device instance state. */
    size_t                  cbInstance;
    /** Size of MMIO area. */
    size_t                  cbMmio;
    /** Initialization callback. */
    PFNPSPMMIODEVINIT       pfnInit;
    /** Destruction callback. */
    PFNPSPMMIODEVDESTRUCT   pfnDestruct;
    /** MMIO read handler. */
    PFNPSPMMIODEVMMIOREAD   pfnMmioRead;
    /** MMIO write handler. */
    PFNPSPMMIODEVMMIOWRITE  pfnMmioWrite;
} PSPMMIODEVREG;


/**
 * Initializes the MMIO manager returning a handle.
 *
 * @returns Status code.
 * @param   phMmioMgr               Where to store the MMIO manager handle on success.
 * @param   hPspCore                The PSP core handle the MMIO manager belongs to.
 */
int PSPEmuMmioMgrCreate(PPSPMMIOM phMmioMgr, PSPCORE hPspCore);

/**
 * Destroys the MMIO manager including all attached devices.
 *
 * @returns Status code.
 * @param   hMmioMgr                The MMIO manager handle.
 */
int PSPEmuMmioMgrDestroy(PSPMMIOM hMmioMgr);

/**
 * Creates a new device instance of the given device registration record, iniitalizes it and
 * registers the MMIO handlers with the given PSP core.
 *
 * @returns Status code.
 * @param   hMmioMgr                The MMIO manager handle.
 * @param   pDevReg                 The device template to use.
 * @param   PspAddrMmioStart        The start MMIO address the device is behind.
 * @param   ppMmioDev               Where to store the MMIO device on success.
 */
int PSPEmuMmioDevCreate(PSPMMIOM hMmioMgr, PCPSPMMIODEVREG pDevReg, PSPADDR PspAddrMmioStart, PPSPMMIODEV *ppMmioDev);

/**
 * Destroys the given MMIO device instance.
 *
 * @returns Status code.
 * @param   pMmioDev                The MMIO device to destroy.
 */
int PSPEmuMmioDevDestroy(PPSPMMIODEV pMmioDev);

#endif /* __psp_mmio_dev_h */

