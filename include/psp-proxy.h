/** @file
 * PSP Emulator - API for proxying accesses to a real PSP.
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
#ifndef __psp_proxy_h
#define __psp_proxy_h

#include <common/types.h>

#include <psp-cfg.h>
#include <psp-ccd.h>


/** Opaque PSP proxy handle. */
typedef struct PSPPROXYINT *PSPPROXY;
/** Pointer to a PSP proxy handle. */
typedef PSPPROXY *PPSPPROXY;


/**
 * Bootloader stage.
 */
typedef enum PSPPROXYBLSTAGE
{
    /** Invalid bootloader stage. */
    PSPPROXYBLSTAGE_INVALID = 0,
    /** Unknown stage. */
    PSPPROXYBLSTAGE_UNKNOWN,
    /** on-chip BL stage. */
    PSPPROXYBLSTAGE_ON_CHIP,
    /** off-chip BL stage. */
    PSPPROXYBLSTAGE_OFF_CHIP,
    /** @todo ABL stages. */
    /** 32bit hack. */
    PSPPROXYBLSTAGE_32BIT_HACK = 0x7fffffff
} PSPPROXYBLSTAGE;


/**
 * Creates a new proxy instance.
 *
 * @returns Status code.
 * @param   phProxy                 Where to store the handle to the proxy instance on success.
 * @param   pCfg                    Pointer to the global emulator config.
 */
int PSPProxyCreate(PPSPPROXY phProxy, PPSPEMUCFG pCfg);


/**
 * Destroys the given proxy handle.
 *
 * @returns nothing.
 * @param   hProxy                  The proxy handle to destroy.
 */
void PSPProxyDestroy(PSPPROXY hProxy);


/**
 * Registers the given CCD handle for hardware access proxying.
 *
 * @returns Status code.
 * @param   hProxy                  The proxy handle.
 */
int PSPProxyCcdRegister(PSPPROXY hProxy, PSPCCD hCcd);


/**
 * Deregisters the given CCD handle with the given proxy.
 *
 * @returns Status code.
 * @param   hProxy                  The proxy handle.
 * @param   hCcd                    The CCD handle to deregister.
 */
int PSPProxyCcdDeregister(PSPPROXY hProxy, PSPCCD hCcd);


/**
 * Returns whether accessing the given MMIO address is allowed accessing through the proxy
 * for the given stage.
 *
 * @returns Status code.
 * @param   PspAddrMmio             The MMIO address being accessed.
 * @param   cbAcc                   Size of the access in bytes.
 * @param   fWrite                  Flag whether this is a read of write access.
 * @param   enmStage                The bootloader stage.
 * @param   pCfg                    The PSP emulator config.
 * @param   pvReadVal               Where to store the value to return for blocked reads.
 */
bool PSPProxyIsMmioAccessAllowed(PSPADDR PspAddrMmio, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                 PCPSPEMUCFG pCfg, void *pvReadVal);


/**
 * Returns whether accessing the given SMN address is allowed accessing through the proxy
 * for the given stage.
 *
 * @returns Status code.
 * @param   SmnAddr                 The SMN address being accessed.
 * @param   cbAcc                   Size of the access in bytes.
 * @param   fWrite                  Flag whether this is a read of write access.
 * @param   enmStage                The bootloader stage.
 * @param   pCfg                    The PSP emulator config.
 * @param   pvReadVal               Where to store the value to return for blocked reads.
 */
bool PSPProxyIsSmnAccessAllowed(SMNADDR SmnAddr, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                PCPSPEMUCFG pCfg, void *pvReadVal);


/**
 * Returns whether accessing the given SMN address is allowed accessing through the proxy
 * for the given stage.
 *
 * @returns Status code.
 * @param   PhysX86Addr             The physical x86 address being accessed.
 * @param   cbAcc                   Size of the access in bytes.
 * @param   fWrite                  Flag whether this is a read of write access.
 * @param   enmStage                The bootloader stage.
 * @param   pCfg                    The PSP emulator config.
 * @param   pvReadVal               Where to store the value to return for blocked reads.
 */
bool PSPProxyIsX86AccessAllowed(X86PADDR PhysX86Addr, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                PCPSPEMUCFG pCfg, void *pvReadVal);


#endif /* !__psp_proxy_h */
