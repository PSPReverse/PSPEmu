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
#ifndef __psp_dev_h
#define __psp_dev_h

#include <common/types.h>

#include <psp-cfg.h>
#include <psp-iom.h>

/** Pointer to a const PSP device registration record. */
typedef const struct PSPDEVREG *PCPSPDEVREG;
/** Pointer to a PSP device registration record. */
typedef struct PSPDEVREG *PPSPDEVREG;


/** Pointer to a const device interface callback table. */
typedef const struct PSPDEVIF *PCPSPDEVIF;

/**
 * Device interface callback table.
 */
typedef struct PSPDEVIF
{

    /**
     * Sets an interrupt request.
     *
     * @returns Status code.
     * @param   pDevIf              Pointer to this table.
     * @param   idPrio              The priority group of the device.
     * @param   idIrq               The interrupt ID of the device.
     * @param   fAssert             Flag whether to assert or de-assert the interrupt line.
     */
    int (*pfnIrqSet)(PCPSPDEVIF pDevIf, uint32_t idPrio, uint8_t idIrq, bool fAssert);

} PSPDEVIF;
/** Pointer to a device interface callback table. */
typedef PSPDEVIF *PPSPDEVIF;


/**
 * PSP device instance.
 */
typedef struct PSPDEV
{
    /** Pointer to the next device. */
    struct PSPDEV          *pNext;
    /** Pointer to the device registration record. */
    PCPSPDEVREG            pReg;
    /** Pointer to the device interface callback to use. */
    PCPSPDEVIF             pDevIf;
    /** The I/O manager the device is attached to. */
    PSPIOM                 hIoMgr;
    /** The global config structure. */
    PCPSPEMUCFG            pCfg;
    /** Instance data - variable in size. */
    uint8_t                abInstance[1];
} PSPDEV;
typedef PSPDEV *PPSPDEV;
typedef const PSPDEV *PCPSPDEV;


/** Initialization handler. */
typedef int (FNPSPDEVINIT)(PPSPDEV pDev);
/** Initialization handler pointer. */
typedef FNPSPDEVINIT *PFNPSPDEVINIT;

/** Destruction handler. */
typedef void (FNPSPDEVDESTRUCT)(PPSPDEV pDev);
/** Initialization handler pointer. */
typedef FNPSPDEVDESTRUCT *PFNPSPDEVDESTRUCT;

/**
 * PSP SMN device registration record.
 */
typedef struct PSPDEVREG
{
    /** Device name. */
    const char              *pszName;
    /** Short device description. */
    const char              *pszDesc;
    /** Size of the device instance state. */
    size_t                  cbInstance;
    /** Initialization callback. */
    PFNPSPDEVINIT           pfnInit;
    /** Destruction callback. */
    PFNPSPDEVDESTRUCT       pfnDestruct;

    /**
     * Reset the device state to the one right after initialization, optional.
     *
     * @returns Status code.
     * @param   pDev                The device instance to reset.s
     */
    int    (*pfnReset) (PPSPDEV pDev);
} PSPDEVREG;


/**
 * Creates a new device instance of the given device registration record, iniitalizes it and
 * registers the SMN handlers with the given SMN manager.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle this device will be attached to.
 * @param   pDevReg                 The device template to use.
 * @param   pDevIf                  The device interface callback table to use.
 * @param   pCfg                    The config to use for the device.
 * @param   ppDev                   Where to store the device on success.
 */
int PSPEmuDevCreate(PSPIOM hIoMgr, PCPSPDEVREG pDevReg, PCPSPDEVIF pDevIf, PCPSPEMUCFG pCfg, PPSPDEV *ppDev);


/**
 * Destroys the given SMN device instance.
 *
 * @returns Status code.
 * @param   pDev                   The device to destroy.
 */
int PSPEmuDevDestroy(PPSPDEV pDev);


#endif /* __psp_dev_h */

