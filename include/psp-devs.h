/** @file
 * PSP Emulator - Known MMIO devices
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
#ifndef __psp_devs_h
#define __psp_devs_h

#include <common/types.h>

#include <psp-dev.h>

extern const PSPDEVREG g_DevRegCcpV5;
extern const PSPDEVREG g_DevRegTimer;
extern const PSPDEVREG g_DevRegFuse;
extern const PSPDEVREG g_DevRegFlash;
extern const PSPDEVREG g_DevRegSmu;
extern const PSPDEVREG g_DevRegMp2;
extern const PSPDEVREG g_DevRegSts;
extern const PSPDEVREG g_DevRegMmioUnk;
extern const PSPDEVREG g_DevRegTest;
extern const PSPDEVREG g_DevRegAcpi;
extern const PSPDEVREG g_DevRegGpio;
extern const PSPDEVREG g_DevRegIoMux;

extern const PSPDEVREG g_DevRegSmnUnk;

extern const PSPDEVREG g_DevRegX86Unk;
extern const PSPDEVREG g_DevRegX86Uart;
extern const PSPDEVREG g_DevRegX86Mem;

#endif /* __psp_devs_h */

