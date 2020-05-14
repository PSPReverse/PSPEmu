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

/** A I/O trace point handle. */
typedef struct PSPIOMTPINT *PSPIOMTP;
/** Pointer to a trace point handle. */
typedef PSPIOMTP *PPSPIOMTP;


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
 * SMN address access handler.
 *
 * @returns nothing.
 * @param   offSmnAbs               The abolsute SMN adress the access happens at.
 * @param   pszDevId                The device name if a device has registered the range or NULL
 *                                  if not assigned.
 * @param   offSmnDev               Offset from the beginning of the registered range if a device
 *                                  has claimed the range.
 * @param   cbAccess                Access size, (1, 2 or 4 bytes).
 * @param   pvVal                   On writes this contains the value written, for
 *                                  reads this contains the value read from the register if the trace is
 *                                  executed after the access.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMSMNTRACE)(SMNADDR offSmnAbs, const char *pszDevId, SMNADDR offSmnDev, size_t cbAccess,
                                const void *pvVal, uint32_t fFlags, void *pvUser);
/** SMN trace handler pointer. */
typedef FNPSPIOMSMNTRACE *PFNPSPIOMSMNTRACE;


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
 * SMN address access handler.
 *
 * @returns nothing.
 * @param   offMmioAbs              The abolsute MMIO adress the access happens at.
 * @param   pszDevId                The device name if a device has registered the range or NULL
 *                                  if not assigned.
 * @param   offMmioDev              Offset from the beginning of the registered range if a device
 *                                  has claimed the range.
 * @param   cbAccess                Access size, (1, 2 or 4 bytes).
 * @param   pvVal                   On writes this contains the value written, for
 *                                  reads this contains the value read from the register if the trace is
 *                                  executed after the access.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMMMIOTRACE)(PSPADDR offMmioAbs, const char *pszDevId, PSPADDR offMmioDev, size_t cbAccess,
                                 const void *pvVal, uint32_t fFlags, void *pvUser);
/** MMIO trace handler pointer. */
typedef FNPSPIOMMMIOTRACE *PFNPSPIOMMMIOTRACE;


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
 * X86 address read handler.
 *
 * @returns nothing.
 * @param   offX86Mmio              Offset from the beginning of the registered range the read starts at
 *                                  (when used as the unassigned region callback this is the absolute address).
 * @param   cbRead                  Number of bytes to read.
 * @param   pvVal                   Where to store the read data.
 * @param   fMmio                   Flag whether this address is accesses as MMIO.
 * @param   fCaching                Flags the ampping was created with.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMX86READ)(X86PADDR offX86Mmio, size_t cbRead, void *pvVal, bool fMmio, uint32_t fCaching, void *pvUser);
/** X86 MMIO read handler pointer. */
typedef FNPSPIOMX86READ *PFNPSPIOMX86READ;


/**
 * X86 MMIO write handler.
 *
 * @returns nothing.
 * @param   offX86Mmio              Offset from the beginning of the registered range the write starts at
 *                                  (when used as the unassigned region callback this is the absolute address).
 * @param   cbWrite                 Number of bytes to write.
 * @param   pvVal                   The data to write.
 * @param   fMmio                   Flag whether this address is accesses as MMIO.
 * @param   fCaching                Flags the ampping was created with.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMX86WRITE)(X86PADDR offX86Mmio, size_t cbRead, const void *pvVal, bool fMmio, uint32_t fCaching, void *pvUser);
/** X86 MMIO write handler pointer. */
typedef FNPSPIOMX86WRITE *PFNPSPIOMX86WRITE;


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
 * X86 address access handler.
 *
 * @returns nothing.
 * @param   offX86Abs               The abolsute x86 physical adress the access happens at.
 * @param   pszDevId                The device name if a device has registered the range or NULL
 *                                  if not assigned.
 * @param   offX86Dev               Offset from the beginning of the registered range if a device
 *                                  has claimed the range.
 * @param   cbAccess                Access size, (1, 2 or 4 bytes).
 * @param   pvVal                   On writes this contains the value written, for
 *                                  reads this contains the value read from the register if the trace is
 *                                  executed after the access.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef void (FNPSPIOMX86TRACE)(X86PADDR offX86Abs, const char *pszDevId, X86PADDR offX86Dev, size_t cbAccess,
                                const void *pvVal, uint32_t fFlags, void *pvUser);
/** X86 trace handler pointer. */
typedef FNPSPIOMX86TRACE *PFNPSPIOMX86TRACE;


/** The trace handler should hit on a read access. */
#define PSPEMU_IOM_TRACE_F_READ                 BIT(0)
/** The trace handler should hit on a write access. */
#define PSPEMU_IOM_TRACE_F_WRITE                BIT(1)
/** The trace handler should hit before the access is executed. */
#define PSPEMU_IOM_TRACE_F_BEFORE               BIT(2)
/** The trace handler should hit after the access was executed. */
#define PSPEMU_IOM_TRACE_F_AFTER                BIT(3)
/** Mask of all valid flags. */
#define PSPEMU_IOM_TRACE_F_VALID_MASK           0xf


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
 * Configures whether any I/O access is logged no matter whether it is to an unassigned
 * region or not.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   fEnable                 true to enable logging for all accesses, false to return to default behavior
 *                                  where only the access to unassigned regions is logged.
 *
 * @note This is a separate API and not a flag given during instantiation of the I/O manager
 *       so it can be changed easily during runtime.
 */
int PSPEmuIoMgrTraceAllAccessesSet(PSPIOM hIoMgr, bool fEnable);


/**
 * Sets callbacks for intercepting accesses to unassigned MMIO regions.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means reads don't get intercepted).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means writes don't get intercepted).
 * @param   pszDesc                 The description used for access logging.
 * @param   pvUser                  Opaque user data passed in the callback.
 *
 * @note By default there is no callback registered and accesses to unassigned regions get logged, reads return all bits 0
 *       and writes get ignored otherwise.
 */
int PSPEmuIoMgrMmioUnassignedSet(PSPIOM hIoMgr, PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, const char *pszDesc,
                                 void *pvUser);


/**
 * Sets callbacks for intercepting accesses to unassigned SMN regions.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means reads don't get intercepted).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means writes don't get intercepted).
 * @param   pszDesc                 The description used for access logging.
 * @param   pvUser                  Opaque user data passed in the callback.
 *
 * @note By default there is no callback registered and accesses to unassigned regions get logged, reads return all bits 0
 *       and writes get ignored otherwise.
 */
int PSPEmuIoMgrSmnUnassignedSet(PSPIOM hIoMgr, PFNPSPIOMSMNREAD pfnRead, PFNPSPIOMSMNWRITE pfnWrite, const char *pszDesc,
                                void *pvUser);


/**
 * Sets callbacks for intercepting accesses to unassigned X86 address regions.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   pfnRead                 Callback to call on a read access, optional (NULL means reads don't get intercepted).
 * @param   pfnWrite                Callback to call on a write access, optional (NULL means writes don't get intercepted).
 * @param   pszDesc                 The description used for access logging.
 * @param   pvUser                  Opaque user data passed in the callback.
 *
 * @note By default there is no callback registered and accesses to unassigned regions get logged, reads return all bits 0
 *       and writes get ignored otherwise.
 */
int PSPEmuIoMgrX86UnassignedSet(PSPIOM hIoMgr, PFNPSPIOMX86READ pfnRead, PFNPSPIOMX86WRITE pfnWrite, const char *pszDesc,
                                void *pvUser);


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
 * @param   pszDesc                 Description for this region which must be valid for the lifetime of this region, optional.
 * @param   phMmio                  Where to store the handle to the MMIO region on success.
 */
int PSPEmuIoMgrMmioRegister(PSPIOM hIoMgr, PSPADDR PspAddrMmioStart, size_t cbMmio,
                            PFNPSPIOMMMIOREAD pfnRead, PFNPSPIOMMMIOWRITE pfnWrite, void *pvUser,
                            const char *pszDesc, PPSPIOMREGIONHANDLE phMmio);


/**
 * Registers a new MMIO access tracing handler.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PspAddrMmioStart        The MMIO start address the trace handler should hit at.
 * @param   PspAddrMmioEnd          The last MMIO address the trace handler should hit at (inclusive).
 * @param   cbAccess                The access width the handler should hit at, 0 for all access sizes,
 *                                  1, 2 or 4 bytes otherwise.
 * @param   fFlags                  Combination of PSPEMU_IOM_TRACE_F_XXX controlling when the trace handler should
 *                                  hit.
 * @param   pfnTrace                The handler to call.
 * @param   pvUser                  Opaque user data to pass to the handler.
 * @param   phIoTp                  Where to store the I/O trace point handle on success.
 */
int PSPEmuIoMgrMmioTraceRegister(PSPIOM hIoMgr, PSPADDR PspAddrMmioStart, PSPADDR PspAddrMmioEnd,
                                 size_t cbAccess, uint32_t fFlags, PFNPSPIOMMMIOTRACE pfnTrace, void *pvUser,
                                 PPSPIOMTP phIoTp);


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
 * @param   pszDesc                 Description for this region which must be valid for the lifetime of this region, optional.
 * @param   phSmn                   Where to store the handle to the SMN region on success.
 */
int PSPEmuIoMgrSmnRegister(PSPIOM hIoMgr, SMNADDR SmnAddrStart, size_t cbSmn,
                           PFNPSPIOMSMNREAD pfnRead, PFNPSPIOMSMNWRITE pfnWrite, void *pvUser,
                           const char *pszDesc, PPSPIOMREGIONHANDLE phSmn);


/**
 * Registers a new MMIO access tracing handler.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   SmnAddrStart            The SMN start address the trace handler should hit at.
 * @param   SmnAddrEnd              The last SMN address the trace handler should hit at (inclusive).
 * @param   cbAccess                The access width the handler should hit at, 0 for all access sizes,
 *                                  1, 2 or 4 bytes otherwise.
 * @param   fFlags                  Combination of PSPEMU_IOM_TRACE_F_XXX controlling when the trace handler should
 *                                  hit.
 * @param   pfnTrace                The handler to call.
 * @param   pvUser                  Opaque user data to pass to the handler.
 * @param   phIoTp                  Where to store the I/O trace point handle on success.
 */
int PSPEmuIoMgrSmnTraceRegister(PSPIOM hIoMgr, SMNADDR SmnAddrStart, SMNADDR SmnAddrEnd,
                                size_t cbAccess, uint32_t fFlags, PFNPSPIOMSMNTRACE pfnTrace, void *pvUser,
                                PPSPIOMTP phIoTp);


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
 * @param   pszDesc                 Description for this region which must be valid for the lifetime of this region, optional.
 * @param   phX86Mmio               Where to store the handle to the X86 MMIO region on success.
 */
int PSPEmuIoMgrX86MmioRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrMmioStart, size_t cbX86Mmio,
                               PFNPSPIOMX86MMIOREAD pfnRead, PFNPSPIOMX86MMIOWRITE pfnWrite, void *pvUser,
                               const char *pszDesc, PPSPIOMREGIONHANDLE phX86Mmio);


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
 * @param   pszDesc                 Description for this region which must be valid for the lifetime of this region, optional.
 * @param   phX86Mem                Where to store the handle to the X86 memory region on success.
 */
int PSPEmuIoMgrX86MemRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrMemStart, size_t cbX86Mem,
                              bool fCanExec, PFNPSPIOMX86MEMFETCH pfnFetch, void *pvUser,
                              const char *pszDesc, PPSPIOMREGIONHANDLE phX86Mem);


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
 * Registers a new x86 address access tracing handler.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PhysX86AddrStart        The x86 physical start address the trace handler should hit at.
 * @param   PhysX86AddrEnd          The last x86 physical address the trace handler should hit at (inclusive).
 * @param   cbAccess                The access width the handler should hit at, 0 for all access sizes,
 *                                  1, 2 or 4 bytes otherwise.
 * @param   fFlags                  Combination of PSPEMU_IOM_TRACE_F_XXX controlling when the trace handler should
 *                                  hit.
 * @param   pfnTrace                The handler to call.
 * @param   pvUser                  Opaque user data to pass to the handler.
 * @param   phIoTp                  Where to store the I/O trace point handle on success.
 */
int PSPEmuIoMgrX86TraceRegister(PSPIOM hIoMgr, X86PADDR PhysX86AddrStart, X86PADDR PhysX86AddrEnd,
                                size_t cbAccess, uint32_t fFlags, PFNPSPIOMX86TRACE pfnTrace, void *pvUser,
                                PPSPIOMTP phIoTp);


/**
 * Deregisters the region of the given handle (MMIO, SMN or X86 MMIO/Mem).
 *
 * @returns Status code.
 * @param   hRegion                 The region handle to deregister.
 */
int PSPEmuIoMgrDeregister(PSPIOMREGIONHANDLE hRegion);


/**
 * Deregisters the given I/O trace point.
 *
 * @returns Status code.
 * @param   hIoTp                   The I/O trace point handle to deregister.
 */
int PSPEmuIoMgrTpDeregister(PSPIOMTP hIoTp);


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


/**
 * Reads from the given x86 physical address, honoring MMIO access handlers.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PhysX86Addr             The PSP physical address to start reading from.
 * @param   pvDst                   Where to store the read data.
 * @param   cbRead                  How many bytes to read.
 */
int PSPEmuIoMgrX86AddrRead(PSPIOM hIoMgr, X86PADDR PhysX86Addr, void *pvDst, size_t cbRead);


/**
 * Writes to the given x86 physical address, honoring MMIO access handlers.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   PhysX86Addr             The PSP physical address to start writing to.
 * @param   pvSrc                   The data to write.
 * @param   cbWrite                 How many bytes to write.
 */
int PSPEmuIoMgrX86AddrWrite(PSPIOM hIoMgr, X86PADDR PhysX86Addr, const void *pvSrc, size_t cbWrite);


/**
 * Dumps the state of the given x86 mapping slots to the trace log.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   idxSlotStart            The first slot to dump.
 * @param   idxSlotEnd              The last slot to dump.
 */
int PSPEmuIoMgrX86MapSlotDump(PSPIOM hIoMgr, uint32_t idxSlotStart, uint32_t idxSlotEnd);


/**
 * Dumps the state of the given SMN mapping slots to the trace log.
 *
 * @returns Status code.
 * @param   hIoMgr                  The I/O manager handle.
 * @param   idxSlotStart            The first slot to dump.
 * @param   idxSlotEnd              The last slot to dump.
 */
int PSPEmuIoMgrSmnMapSlotDump(PSPIOM hIoMgr, uint32_t idxSlotStart, uint32_t idxSlotEnd);


#endif /* __psp_iom_h */

