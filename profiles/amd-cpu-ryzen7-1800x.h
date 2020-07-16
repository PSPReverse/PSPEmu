/** @file
 * PSP Emulator - CPU profile for an AMD Ryzen 7 1800X.
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
#ifndef PSPEMU_PROFILES_psp_amd_cpu_ryzen7_1800x_h
#define PSPEMU_PROFILES_psp_amd_cpu_ryzen7_1800x_h


/**
 * CPU profile for an AMD CPU Ryzen 7 1800X
 */
static const PSPAMDCPUPROFILE g_AmdCpu_Ryzen7_1800X =
{
    /** pszId */
    "ryzen7-1800x",
    /** pszDesc */
    "AMD Ryzen 7 1800X Eight Core CPU",
    /** enmMicroArch */
    PSPEMUMICROARCH_ZEN,
    /** enmCpuSegment */
    PSPEMUAMDCPUSEGMENT_RYZEN,
    /** cCcdsPerSocket */
    1,
    /** cSocketsMax */
    1,
    /** pPspProfile. */
    &g_PspProfileZen
};

#endif /* !PSPEMU_PROFILES_psp_amd_cpu_ryzen7_1800x_h */

