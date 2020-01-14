/** @file
 * PSP Emulator - SMN attached devices interface
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
#ifndef __psp_smn_dev_h
#define __psp_smn_dev_h

#include <common/types.h>

#include <psp-mmio-dev.h>

/** Pointer to a const PSP SMN device registration record. */
typedef const struct PSPSMNDEVREG *PCPSPSMNDEVREG;
/** Pointer to a PSP SMN device registration record. */
typedef struct PSPSMNDEVREG *PPSPSMNDEVREG;

/** PSP SMN Manager handle. */
typedef struct PSPSMNMINT *PSPSMNM;
/** Pointer to a PSP SMN Manager handle. */
typedef PSPSMNM *PPSPSMNM;


/**
 * PSP MMIO device instance.
 */
typedef struct PSPSMNDEV
{
    /** Pointer to the next device. */
    struct PSPSMNDEV       *pNext;
    /** Pointer to the device registration record. */
    PCPSPSMNDEVREG         pReg;
    /** The SMN manager the device is attached to. */
    PSPSMNM                hSmnMgr;
    /** Start SMN address for the device. */
    SMNADDR                SmnStart;
    /** Instance data - variable in size. */
    uint8_t                abInstance[1];
} PSPSMNDEV;
typedef PSPSMNDEV *PPSPSMNDEV;
typedef const PSPSMNDEV *PCPSPSMNDEV;


/** Initialization handler. */
typedef int (FNPSPSMNDEVINIT)(PPSPSMNDEV pDev);
/** Initialization handler pointer. */
typedef FNPSPSMNDEVINIT *PFNPSPSMNDEVINIT;

/** Destruction handler. */
typedef void (FNPSPSMNDEVDESTRUCT)(PPSPSMNDEV pDev);
/** Initialization handler pointer. */
typedef FNPSPSMNDEVDESTRUCT *PFNPSPSMNDEVDESTRUCT;

/** SMN read handler. */
typedef void (FNPSPSMNDEVREAD)(PPSPSMNDEV pDev, SMNADDR offSmn, size_t cbRead, void *pvVal);
/** SMN read handler pointer. */
typedef FNPSPSMNDEVREAD *PFNPSPSMNDEVREAD;

/** SMN write handler. */
typedef void (FNPSPSMNDEVWRITE)(PPSPSMNDEV pDev, SMNADDR offSmn, size_t cbWrite, const void *pvVal);
/** SMN write handler pointer. */
typedef FNPSPSMNDEVWRITE *PFNPSPSMNDEVWRITE;

/**
 * PSP SMN device registration record.
 */
typedef struct PSPSMNDEVREG
{
    /** Device name. */
    const char              *pszName;
    /** Short device description. */
    const char              *pszDesc;
    /** Size of the device instance state. */
    size_t                  cbInstance;
    /** Size of SMN area. */
    size_t                  cbSmn;
    /** Initialization callback. */
    PFNPSPSMNDEVINIT        pfnInit;
    /** Destruction callback. */
    PFNPSPSMNDEVDESTRUCT    pfnDestruct;
    /** SMN read handler. */
    PFNPSPSMNDEVREAD        pfnSmnRead;
    /** SMN write handler. */
    PFNPSPSMNDEVWRITE       pfnSmnWrite;
} PSPSMNDEVREG;


/**
 * Initializes the SMN manager returning a handle.
 *
 * @returns Status code.
 * @param   phSmnMgr                Where to store the SMN manager handle on success.
 * @param   hMmioMgr                The MMIO manager handle for processing the SMN read write accesses.
 */
int PSPEmuSmnMgrCreate(PPSPSMNM phSmnMgr, PSPMMIOM hMmioMgr);

/**
 * Destroys the SMN manager including all attached devices.
 *
 * @returns Status code.
 * @param   hSmnMgr                The SMN manager handle.
 */
int PSPEmuSmnMgrDestroy(PSPSMNM hSmnMgr);

/**
 * Creates a new device instance of the given device registration record, iniitalizes it and
 * registers the SMN handlers with the given SMN manager.
 *
 * @returns Status code.
 * @param   hSmnMgr                 The SMN manager handle.
 * @param   pDevReg                 The device template to use.
 * @param   SmnAddrStart            The start SMN address the device is behind.
 * @param   ppSmnDev                Where to store the SMN device on success.
 */
int PSPEmuSmnDevCreate(PSPSMNM hSmnMgr, PCPSPSMNDEVREG pDevReg, SMNADDR SmnAddrStart, PPSPSMNDEV *ppSmnDev);

/**
 * Destroys the given SMN device instance.
 *
 * @returns Status code.
 * @param   pSmnDev                The SMN device to destroy.
 */
int PSPEmuSmnDevDestroy(PPSPSMNDEV pSmnDev);

#endif /* __psp_smn_dev_h */

