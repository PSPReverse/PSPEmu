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

/**
 * SMN read handler.
 *
 * @returns nothing.
 * @param   offSmn                  Offset from the beginning of the registered range the read starts at
 *                                  (when used as the unassigned region callback this is the absolute address).
 * @param   cbRead                  Number of bytes to read.
 * @param   pvVal                   Where to store the read data.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMSMNREAD)(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser);
/** SMN read handler pointer. */
typedef FNPSPIOMSMNREAD *PFNPSPIOMSMNREAD;


/**
 * SMN write handler.
 *
 * @returns nothing.
 * @param   offSmn                  Offset from the beginning of the registered range the write starts at
 *                                  (when used as the unassigned region callback this is the absolute address).
 * @param   cbWrite                 Number of bytes to write.
 * @param   pvVal                   The data to write.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMSMNWRITE)(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser);
/** SMN write handler pointer. */
typedef FNPSPIOMSMNWRITE *PFNPSPIOMSMNWRITE;


/**
 * MMIO read handler.
 *
 * @returns nothing.
 * @param   offMmio                 Offset from the beginning of the registered range the read starts at
 *                                  (when used as the unassigned region callback this is the absolute address).
 * @param   cbRead                  Number of bytes to read.
 * @param   pvVal                   Where to store the read data.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMMMIOREAD)(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser);
/** MMIO read handler pointer. */
typedef FNPSPIOMMMIOREAD *PFNPSPIOMMMIOREAD;


/**
 * MMIO write handler.
 *
 * @returns nothing.
 * @param   offMmio                 Offset from the beginning of the registered range the write starts at
 *                                  (when used as the unassigned region callback this is the absolute address).
 * @param   cbWrite                 Number of bytes to write.
 * @param   pvVal                   The data to write.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMMMIOWRITE)(PSPADDR offMmio, size_t cbRead, const void *pvVal, void *pvUser);
/** MMIO write handler pointer. */
typedef FNPSPIOMMMIOWRITE *PFNPSPIOMMMIOWRITE;


/**
 * X86 MMIO read handler.
 *
 * @returns nothing.
 * @param   offX86Mmio              Offset from the beginning of the registered range the read starts at
 *                                  (when used as the unassigned region callback this is the absolute address).
 * @param   cbRead                  Number of bytes to read.
 * @param   pvVal                   Where to store the read data.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMX86MMIOREAD)(X86PADDR offX86Mmio, size_t cbRead, void *pvVal, void *pvUser);
/** X86 MMIO read handler pointer. */
typedef FNPSPIOMX86MMIOREAD *PFNPSPIOMX86MMIOREAD;


/**
 * X86 MMIO write handler.
 *
 * @returns nothing.
 * @param   offX86Mmio              Offset from the beginning of the registered range the write starts at
 *                                  (when used as the unassigned region callback this is the absolute address).
 * @param   cbWrite                 Number of bytes to write.
 * @param   pvVal                   The data to write.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMX86MMIOWRITE)(X86PADDR offX86Mmio, size_t cbRead, const void *pvVal, void *pvUser);
/** X86 MMIO write handler pointer. */
typedef FNPSPIOMX86MMIOWRITE *PFNPSPIOMX86MMIOWRITE;


/**
 * X86 memory fetch handler.
 *
 * @returns nothing.
 * @param   offX86Mem               Offset from the beginning of the registered range to start fetching from.
 * @param   cbFetch                 Number of bytes to fetch.
 * @param   pvVal                   Where to store the fetched data.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMX86MEMFETCH)(X86PADDR offX86Mem, size_t cbFetch, void *pvDst, void *pvUser);
/** X86 memory fetch handler pointer. */
typedef FNPSPIOMX86MEMFETCH *PFNPSPIOMX86MEMFETCH;


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
 * Sets callbacks for intercepting accesses to unassigned MMIO regions.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means reads don't get intercepted).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means writes don't get intercepted).
 * @param   pvUser                  Opaque user data passed in the callback.
 *
 * @note By default there is no callback registered and accesses to unassigned regions get logged, reads return all bits 0
 *       and writes get ignored otherwise.
 */
int PSPEmuIoMgrMmioUnassignedSet(PSPIOM hIoMgr, PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, void *pvUser);


/**
 * Sets callbacks for intercepting accesses to unassigned SMN regions.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means reads don't get intercepted).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means writes don't get intercepted).
 * @param   pvUser                  Opaque user data passed in the callback.
 *
 * @note By default there is no callback registered and accesses to unassigned regions get logged, reads return all bits 0
 *       and writes get ignored otherwise.
 */
int PSPEmuIoMgrSmnUnassignedSet(PSPIOM hIoMgr, PFNPSPIOMSMNREAD pfnRead, PFNPSPIOMSMNWRITE pfnWrite, void *pvUser);


/**
 * Sets callbacks for intercepting accesses to unassigned X86 address regions.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means reads don't get intercepted).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means writes don't get intercepted).
 * @param   pvUser                  Opaque user data passed in the callback.
 *
 * @note By default there is no callback registered and accesses to unassigned regions get logged, reads return all bits 0
 *       and writes get ignored otherwise.
 */
int PSPEmuIoMgrX86UnassignedSet(PSPIOM hIoMgr, PFNPSPIOMX86MMIOREAD pfnRead, PFNPSPIOMX86MMIOWRITE pfnWrite, void *pvUser);


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
 * Registers a X86 memory backed region.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PhysX86AddrMemStart     The X86 start address of the memory region to register.
 * @param   cbX86Mem                Size of the X86 memory region in bytes.
 * @param   fCanExec                Flag whether the memory should be made executable to the core.
 * @param   pfnFetch                Callback to call on a first read access to dynamically initialize the memory content,
 *                                  optional (NULL means reads return 0 on first access).
 * @param   pvUser                  Opaque user data passed in the fetch callback.
 * @param   phX86Mem                Where to store the handle to the X86 memory region on success.
 */
int PSPEmuIoMgrX86MemRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrMemStart, size_t cbX86Mem,
                              bool fCanExec, PFNPSPIOMX86MEMFETCH pfnFetch, void *pvUser,
                              PPSPIOMREGIONHANDLE phX86Mem);


/**
 * Reads data from the given X86 memory region.
 *
 * @returns Status code.
 * @param   hX86Mem                 The X86 memory region to read from.
 * @param   offX86Mem               The offset from the start of the region to read from.
 * @param   pvDst                   Where to store the result.
 * @param   cbRead                  Number of bytes to read.
 *
 * @note This might invoke the fetch handler if given during registration and the accessed area of the region
 *       was not initialized yet.
 */
int PSPEmuIoMgrX86MemRead(PSPIOMREGIONHANDLE hX86Mem, X86PADDR offX86Mem, void *pvDst, size_t cbRead);


/**
 * Writes data to the given X86 memory region.
 *
 * @returns Status code.
 * @param   hX86Mem                 The X86 memory region to write to.
 * @param   offX86Mem               The offset from the start of the region to write to.
 * @param   pvSrc                   The data to write.
 * @param   cbWrite                 Number of bytes to write.
 */
int PSPEmuIoMgrX86MemWrite(PSPIOMREGIONHANDLE hX86Mem, X86PADDR offX86Mem, const void *pvSrc, size_t cbWrite);


/**
 * Deregisters the region of the given handle (MMIO, SMN or X86 MMIO/Mem).
 *
 * @returns Status code.
 * @param   hRegion                 The region handle to deregister.
 */
int PSPEmuIoMgrDeregister(PSPIOMREGIONHANDLE hRegion);


/**
 * Reads from the given PSP physical address, honoring MMIO access handlers.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PspAddr                 The PSP physical address to start reading from.
 * @param   pvDst                   Where to store the read data.
 * @param   cbRead                  How many bytes to read.
 */
int PSPEmuIoMgrPspAddrRead(PSPIOM hIoMgr, PSPADDR PspAddr, void *pvDst, size_t cbRead);


/**
 * Writes to the given PSP physical address, honoring MMIO access handlers.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PspAddr                 The PSP physical address to start writing to.
 * @param   pvSrc                   The data to write.
 * @param   cbWrite                 How many bytes to write.
 */
int PSPEmuIoMgrPspAddrWrite(PSPIOM hIoMgr, PSPADDR PspAddr, const void *pvSrc, size_t cbWrite);


#endif /* __psp_iom_h */

