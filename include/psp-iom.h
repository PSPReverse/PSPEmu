/** @file
 * PSP Emulator - I/O Manager.
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
#ifndef __psp_iom_h
#define __psp_iom_h

#include <common/types.h>

#include <psp-core.h>

/** PSP device I/O Manager handle. */
typedef struct PSPIOMINT *PSPIOM;
/** Pointer to a PSP I/O Manager handle. */
typedef PSPIOM *PPSPIOM;


/** A MMIO/SMN region handle. */
typedef struct PSPIOMREGIONHANDLEINT *PSPIOMREGIONHANDLE;
/** Pointer to a region handle. */
typedef PSPIOMREGIONHANDLE *PPSPIOMREGIONHANDLE;

/** SMN read handler. */
typedef void (FNPSPIOMSMNREAD)(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser);
/** SMN read handler pointer. */
typedef FNPSPIOMSMNREAD *PFNPSPIOMSMNREAD;

/** SMN write handler. */
typedef void (FNPSPIOMSMNWRITE)(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser);
/** SMN write handler pointer. */
typedef FNPSPIOMSMNWRITE *PFNPSPIOMSMNWRITE;


/** MMIO read handler. */
typedef void (FNPSPIOMMMIOREAD)(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser);
/** MMIO read handler pointer. */
typedef FNPSPIOMMMIOREAD *PFNPSPIOMMMIOREAD;

/** MMIO write handler. */
typedef void (FNPSPIOMMMIOWRITE)(PSPADDR offMmio, size_t cbRead, const void *pvVal, void *pvUser);
/** MMIO write handler pointer. */
typedef FNPSPIOMMMIOWRITE *PFNPSPIOMMMIOWRITE;


/** X86 MMIO read handler. */
typedef void (FNPSPIOMX86MMIOREAD)(X86PADDR offX86Mmio, size_t cbRead, void *pvVal, void *pvUser);
/** X86 MMIO read handler pointer. */
typedef FNPSPIOMX86MMIOREAD *PFNPSPIOMX86MMIOREAD;

/** X86 MMIO write handler. */
typedef void (FNPSPIOMX86MMIOWRITE)(X86PADDR offX86Mmio, size_t cbRead, const void *pvVal, void *pvUser);
/** X86 MMIO write handler pointer. */
typedef FNPSPIOMX86MMIOWRITE *PFNPSPIOMX86MMIOWRITE;


/**
 * Initializes the I/O manager returning a handle.
 *
 * @returns Status code.
 * @param   phIoMgr                 Where to store the I/O manager handle on success.
 * @param   hPspCore                The PSP core the I/O manager is attached to.
 */
int PSPEmuIoMgrCreate(PPSPIOM phIoMgr, PSPCORE hPspCore);


/**
 * Destroys the I/O manager including all attached devices.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 */
int PSPEmuIoMgrDestroy(PSPIOM hIoMgr);


/**
 * Registers read/write handlers for the given MMIO region.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PspAddrMmioStart        The MMIO start address of the region to register.
 * @param   cbMmio                  Size of the MMIO region in bytes.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means write only).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means readonly).
 * @param   pvUser                  Opaque user data passed in the callback.
 * @param   phMmio                  Where to store the handle to the MMIO region on success.
 */
int PSPEmuIoMgrMmioRegister(PSPIOM hIoMgr, PSPADDR PspAddrMmioStart, size_t cbMmio,
                            PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, void *pvUser,
                            PPSPIOMREGIONHANDLE phMmio);


/**
 * Registers read/write handlers for the given SMN region.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   SmnAddrStart            The SMN start address of the region to register.
 * @param   cbSmn                   Size of the SMN region in bytes.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means write only).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means readonly).
 * @param   pvUser                  Opaque user data passed in the callback.
 * @param   phSmn                   Where to store the handle to the SMN region on success.
 */
int PSPEmuIoMgrSmnRegister(PSPIOM hIoMgr, SMNADDR SmnAddrStart, size_t cbSmn,
                           PFNPSPIOMSMNREAD pfnRead, PFNPSPIOMSMNWRITE pfnWrite, void *pvUser,
                           PPSPIOMREGIONHANDLE phSmn);


/**
 * Registers read/write handlers for the given X86 MMIO region.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PhysX86AddrMmioStart    The X86 MMIO start address of the region to register.
 * @param   cbX86Mmio               Size of the X86 MMIO region in bytes.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means write only).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means readonly).
 * @param   pvUser                  Opaque user data passed in the callback.
 * @param   phX86Mmio               Where to store the handle to the X86 MMIO region on success.
 */
int PSPEmuIoMgrX86MmioRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrMmioStart, size_t cbX86Mmio,
                               PFNPSPIOMX86MMIOREAD pfnRead, PFNPSPIOMX86MMIOWRITE pfnWrite, void *pvUser,
                               PPSPIOMREGIONHANDLE phX86Mmio);


/**
 * Deregisters the region of the given handle (MMIO or SMN).
 *
 * @returns Status code.
 * @param   hRegion                 The region handle to deregister.
 */
int PSPEmuIoMgrDeregister(PSPIOMREGIONHANDLE hRegion);


#endif /* __psp_iom_h */

