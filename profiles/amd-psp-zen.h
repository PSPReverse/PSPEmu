/** @file
 * PSP Emulator - Generic PSP profile for a Zen CPU.
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
#ifndef PSPEMU_PROFILES_psp_amd_zen_h
#define PSPEMU_PROFILES_psp_amd_zen_h


/**
 * Generic PSP profile for a standard Zen CPU.
 */
static const PSPPROFILE g_PspProfileZen =
{
    /** pszId */
    "zen-standard",
    /** pszDesc */
    "PSP profile for a standard Zen based CPU",
    /** enmMicroArch */
    PSPEMUMICROARCH_ZEN,
    /** u32PspOnChipBlVersion */
    0xbc090072,
    /** cbSram. */
    _256K,
    /** PspAddrBrsp */
    0x3f000,
    /** PspAddrMmioVersion */
    0x0320004c,
    /** PspAddrMmioSts */
    0x032000e8,
    /** SmnAddrFlashStart */
    0x0a000000,
    /** paAddrProxyBlockedMmio */
    &g_aProxyBlockedMmioStd[0],
    /** cAddrProxyBlockedMmio */
    ELEMENTS(g_aProxyBlockedMmioStd),
    /** paAddrProxyBlockedSmn */
    &g_aProxyBlockedSmnStd[0],
    /** cAddrProxyBlockedSmn */
    ELEMENTS(g_aProxyBlockedSmnStd),
    /** paAddrProxyBlockedX86 */
    &g_aProxyBlockedX86Std[0],
    /** cAddrProxyBlockedX86 */
    ELEMENTS(g_aProxyBlockedX86Std)
};

#endif /* !PSPEMU_PROFILES_psp_amd_zen_h */

