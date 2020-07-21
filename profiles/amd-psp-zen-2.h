/** @file
 * PSP Emulator - Generic PSP profile for a Zen 2 CPU.
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
#ifndef PSPEMU_PROFILES_psp_amd_zen_2_h
#define PSPEMU_PROFILES_psp_amd_zen_2_h


/**
 * Generic PSP profile for a standard Zen 2 CPU.
 */
static const PSPPROFILE g_PspProfileZen2 =
{
    /** pszId */
    "zen2-standard",
    /** pszDesc */
    "PSP profile for a standard Zen 2 based CPU",
    /** enmMicroArch */
    PSPEMUMICROARCH_ZEN2,
    /** cbSram. */
    320 * _1K,
    /** PspAddrBrsp */
    0x4f000,
    /** PspAddrMmioSts */
    0x032000d8,
    /** SmnAddrFlashStart */
    0x44000000,
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

#endif /* !PSPEMU_PROFILES_psp_amd_zen_2_h */

