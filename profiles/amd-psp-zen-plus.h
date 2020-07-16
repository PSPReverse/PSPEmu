/** @file
 * PSP Emulator - Generic PSP profile for a Zen+ CPU.
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
#ifndef PSPEMU_PROFILES_psp_amd_zen_plus_h
#define PSPEMU_PROFILES_psp_amd_zen_plus_h


/**
 * Generic PSP profile for a standard Zen+ CPU.
 */
static const PSPPROFILE g_PspProfileZenPlus =
{
    /** pszId */
    "zen+-standard",
    /** pszDesc */
    "PSP profile for a standard Zen+ based CPU",
    /** enmMicroArch */
    PSPEMUMICROARCH_ZEN_PLUS,
    /** cbSram. */
    _256K,
    /** PspAddrBrsp */
    0x3f000,
    /** PspAddrMmioSts */
    0x032000f0,
    /** SmnAddrFlashStart */
    0x0a000000
};

#endif /* !PSPEMU_PROFILES_psp_amd_zen_plus_h */

