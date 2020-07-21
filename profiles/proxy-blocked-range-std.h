/** @file
 * PSP Emulator - Generic proxy blocked address ranges.
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
#ifndef PSPEMU_PROFILES_proxy_blocke_range_std_h
#define PSPEMU_PROFILES_proxy_blocke_range_std_h


/**
 * Standard MMIO ranges being blocked in proxy mode.
 */
static const PSPPROXYADDRBLOCKEDDESC g_aProxyBlockedMmioStd[] =
{
    PSPPROXY_ADDR_BLOCKED_MMIO_INIT_WR("SomeReset?", 0x320001c, 4),
    PSPPROXY_ADDR_BLOCKED_MMIO_INIT_WR("SomeReset?", 0x3a0001c, 4)
};


/**
 * Standard SMN ranges being blocked in proxy mode.
 */
static const PSPPROXYADDRBLOCKEDDESC g_aProxyBlockedSmnStd[] =
{
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("Flash", 0x02dc4000, 32, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_SPI)
};


/**
 * Standard X86 ranges being blocked in proxy mode.
 */
static const PSPPROXYADDRBLOCKEDDESC g_aProxyBlockedX86Std[] =
{
    PSPPROXY_ADDR_BLOCKED_X86_INIT_ALL_FEAT("Uart", 0xfffdfc0003f8, 8, 0xff, PSPPROXY_ADDR_BLOCKED_FEAT_F_X86_UART)
};

#endif /* !PSPEMU_PROFILES_proxy_blocke_range_std_h */

