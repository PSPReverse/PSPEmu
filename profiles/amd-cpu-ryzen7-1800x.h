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
 * Standard SMN ranges being blocked in proxy mode.
 */
static const PSPPROXYADDRBLOCKEDDESC g_aProxyBlockedSmn_AmdCpu_Ryzen7_1800x[] =
{
    /*
     * The following monitor commands release the x86 cores on an Ryzen 1800x (1 CCD, 2CCX, 8 cores/16 threads):
     *
     *     monitor proxy.SmnWrite 0x18002ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18022ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18042ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18062ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18402ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18422ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18442ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18462ff0 4 0x80000000
     */
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("X86Ccx0Core0", 0x18002ff0, 4, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE),
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("X86Ccx0Core1", 0x18022ff0, 4, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE),
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("X86Ccx0Core2", 0x18042ff0, 4, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE),
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("X86Ccx0Core3", 0x18062ff0, 4, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE),
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("X86Ccx1Core0", 0x18402ff0, 4, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE),
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("X86Ccx1Core1", 0x18422ff0, 4, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE),
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("X86Ccx1Core2", 0x18442ff0, 4, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE),
    PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT("X86Ccx1Core3", 0x18462ff0, 4, 0, PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE)
};


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
    &g_PspProfileZen,
    /** paAddrProxyBlockedSmn */
    &g_aProxyBlockedSmn_AmdCpu_Ryzen7_1800x[0],
    /** cAddrProxyBlockedSmn */
    ELEMENTS(g_aProxyBlockedSmn_AmdCpu_Ryzen7_1800x)
};

#endif /* !PSPEMU_PROFILES_psp_amd_cpu_ryzen7_1800x_h */

