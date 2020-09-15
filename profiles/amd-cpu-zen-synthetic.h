/** @file
 * PSP Emulator - CPU profile for an synthetic AMD CPU used as the default.
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
#ifndef PSPEMU_PROFILES_psp_amd_cpu_zen_synthetic_h
#define PSPEMU_PROFILES_psp_amd_cpu_zen_synthetic_h


/**
 * CPU profile for an AMD Zen based synthetic CPU.
 */
static const PSPAMDCPUPROFILE g_AmdCpu_Zen_Synthetic =
{
    /** pszId */
    "zen-synthetic",
    /** pszDesc */
    "AMD Zen based Synthetic",
    /** enmMicroArch */
    PSPEMUMICROARCH_ZEN,
    /** enmCpuSegment */
    PSPEMUAMDCPUSEGMENT_RYZEN,
    /** cCcdsPerSocket */
    1,
    /** cSocketsMax */
    1,
    /** cCoresPerCcx */
    1,
    /** cCcxs */
    1,
    /** cCoresPerCcd */
    1,
    /** pPspProfile. */
    &g_PspProfileZen,
    /** paAddrProxyBlockedSmn */
    NULL,
    /** cAddrProxyBlockedSmn */
    0
};

#endif /* !PSPEMU_PROFILES_psp_amd_cpu_zen_synthetic_h */

