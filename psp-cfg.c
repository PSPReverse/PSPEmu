/** @file
 * PSP Emulator - Config API.
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

/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#include <stdio.h>

#include <common/types.h>
#include <common/cdefs.h>

#include <psp-cfg.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/


/**
 * Argument descriptor.
 */
typedef struct PSPCFGARG
{
    /** Long argument. */
    const char                  *pszArgLong;
    /** Short argument. */
    char                        chArgShort;
    /** Arguments. */
    const char                  *pszArg;
    /** Description of the argument for verbose mode. */
    const char                  *pszDesc;
} PSPCFGARG;
/** Pointer to an argument descriptor. */
typedef PSPCFGARG *PPSPCFGARG;
/** Pointer to a const argument descriptor. */
typedef const PSPCFGARG *PCPSPCFGARG;


/**
 * Argument group.
 */
typedef struct PSPCFGARGGRP
{
    /** Group name. */
    const char                      *pszName;
    /** Pointer to the array of arguments belonging to that group. */
    PCPSPCFGARG                     paArgs;
    /** Number of entries in the argument array. */
    uint32_t                        cArgs;
} PSPCFGARGGRP;
/** Pointer to an argument group descriptor. */
typedef PSPCFGARGGRP *PPSPCFGARGGRP;
/** Pointer to a const argument group descriptor. */
typedef const PSPCFGARGGRP *PCPSPCFGARGGRP;


/*********************************************************************************************************************************
*   Global Variables                                                                                                             *
*********************************************************************************************************************************/

/**
 * The arguments of the general settings group.
 */
static const PSPCFGARG g_aCfgArgsGeneral[] =
{
    {"emulation-mode",               'm', "[app|sys|on-chip-bl|trusted-os]",  "Selects the starting point in the bootstrapping phase"},
    {"psp-profile",                  'a', "<id>",                             "Selects the given PSP profile for emulation"},
    {"cpu-profile",                  'c', "<id>",                             "Selects the given CPU profile for emulation (optional)"},
    {"flash-rom",                    'f', "<path/to/flash/rom>",              "The flash image to use for emulation"},
    {"on-chip-bl",                   'o', "<path/to/on-chip-bl/binary>",      "The on-chip BL binary to use when starting emulation from the on-chip BL"},
    {"boot-rom-svc-page",            's', "<path/to/boot/rom/svc/page>",      "The boot ROM service page to load when starting with the off-chip BL or later"},
    {"boot-rom-svc-page-dont-alter", 'n', NULL,                               "Don't alter the boot ROM service page to match the emulated system"},
    {"bin-load",                     'b', "<path/to/binary/to/load>",         "Binary to load into SRAM for emulation, depends on the emulation mode"},
    {"bin-contains-hdr",             'p', NULL,                               "The binary has the 256byte header prepended. Leave out if the loaded binary doesn't has the header"},
    {"load-psp-dir",                 'l', NULL,                               "DO NOT USE (due for removal)"},
    {"psp-dbg-mode",                 'g', NULL,                               "Enables PSP debug mode where signature checks are disabled and some BLs print additional information"},
    {"sockets",                      'S', "<socket cound>",                   "Emulate the given number of sockets, must be in range of the selected CPU profile"},
    {"ccds-per-socket",              'C', "<CCD count per socket>",           "Emulate the given number of CCDs for each socket, overwrites the value in the CPU profile"},
    {"emulate-single-socket-id",     'O', "<id>",                             "Emulate a PSP for the given socket ID"},
    {"emulate-single-die-id",        'D', "<id>",                             "Emulate a PSP with the given die ID"},
    {"emulate-devices",              'E', "[<dev1>:<dev2>:...]",              "Select the devices for emulation, default is to emulate everything"},
    {"acpi-state",                   'i', "[s0|s1|s1|s2|s3|s4|s5]",           "Selects the ACPI system state to start emulation from, default is S5"},
    {"uart-remote-addr",             'u', "[<port>|<address:port>]",          "When the emulated UART is used connect either to given address/port pair or listen for incoming connections on the given port"},
    {"timer-real-time",              'r', NULL,                               "Emulated timers tick in host real-time"},
    {"memory-preload",               'M', "<addrspace>:<address>:<filename>", "Preloads a given address space address with data from the given file, can be given multiple times on the command line"},
    {"memory-create",                'R', "<addrspace>:<address>:<sz>",       "Creates a memory region for the given address space address, can be given multiple times on the command line"},
    {"help",                         'H', NULL,                               "Prints this help text"}
};


/**
 * The arguments of the debugger settings group.
 */
static const PSPCFGARG g_aCfgArgsDbg[] =
{
    {"dbg",                          'd', "<listening port>",                 "Enable the GDB debugger stub listening on the given port"},
    {"dbg-step-count",               'G', "<count>",                          "Number of instructions to step through in a single round, use at own RISK"},
    {"dbg-run-up-to",                'U', "<addr>",                           "Runs until the given address is hit and drops then into the debugger instead of right at the start"}
};


/**
 * The arguments of the proxy settings group.
 */
static const PSPCFGARG g_aCfgArgsProxy[] =
{
    {"psp-proxy-addr",               'x', "<path/to/proxy/device>",           "Enables proxy mode and tries to connect to the given device (see libpspproxy for more information)"},
    {"proxy-buffer-writes",          'P', NULL,                               "If proxy mode is enabled certain writes will be cached and sent in bursts to speed up certain access patterns"},
    {"proxy-trusted-os-handover",    'T', "<addr>",                           "If set, this is the address where the off chip BL jumps to the trusted OS and the emulator will do the same"},
    {"proxy-ccp",                    'X', NULL,                               "When proxy mode is enabled this will pass through certain CCP request to a real CCP (AES with keys from the protected LSB so far)"},
    {"proxy-x86-cores-no-release",   '8', NULL,                               "Do not release the x86 cores in proxy mode"},
    {"proxy-memory-wt",              'W', "<addrspace>:<address>:<sz>",       "Write through the indicated memory region to the real HW in proxy mode even if it is occupied by an emulated region, can be given multiple times on the command line"}
};


/**
 * The arguments of the tracing/logging settings group.
 */
static const PSPCFGARG g_aCfgArgsTraceLog[] =
{
    {"trace-log",                    't', "<path/to/trace/log>",              "Enable trace logging and sets the log destination"},
    {"intercept-svc-6",              '6', NULL,                               "Intercepts svc 6 debug log syscalls and prints the content to the trace log"},
    {"trace-svcs",                   'v', NULL,                               "Trace all syscalls being made along with the arguments"},
    {"spi-flash-trace",              'F', "<path/to/flash/trace>",            "Generates a trace compatible with psptrace when the emulated flash device is used" },
    {"coverage-trace",               'V', "<path/to/coverage/trace/file>",    "Create a coverage trace compatible to DrCov and dump it to the given file when the emulator exits"},
    {"iom-log-all-accesses",         'I', NULL,                               "I/O manager logs all device accesses not only the ones to unassigned regions"},
    {"io-log-write",                 'L', "<path/to/io/log>",                 "Writes a log of all I/O accesses for later replay"},
    {"io-log-replay",                'Y', "<path/to/io/log>",                 "Replays the given I/O log, mutually exclusive with proxy mode"},
    {"single-step-dump-core-state",  'A', NULL,                               "Single step execution, dumping the core state after each instruction"}
};


/**
 * The argument groups.
 */
static const PSPCFGARGGRP g_aCfgArgGroups[] =
{
    { "General settings",               &g_aCfgArgsGeneral[0],  ELEMENTS(g_aCfgArgsGeneral)  },
    { "Debugger related settings",      &g_aCfgArgsDbg[0],      ELEMENTS(g_aCfgArgsDbg)      },
    { "Proxy mode related settings",    &g_aCfgArgsProxy[0],    ELEMENTS(g_aCfgArgsProxy)    },
    { "Trace logging related settings", &g_aCfgArgsTraceLog[0], ELEMENTS(g_aCfgArgsTraceLog) },
};


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

/**
 * Dumps the given argument group.
 *
 * @returns nothing.
 * @param   pArgGroup               The argument group to dump.
 * @param   fVerbose                Flag whether to dump in verbose mode.
 */
static void pspCfgHelpArgGroup(PCPSPCFGARGGRP pArgGroup, bool fVerbose)
{
    if (fVerbose)
        printf("%s:\n", pArgGroup->pszName);

    for (uint32_t i = 0; i < pArgGroup->cArgs; i++)
    {
        PCPSPCFGARG pArg = &pArgGroup->paArgs[i];

        if (fVerbose)
        {
            if (pArg->pszArg)
                printf("    --%s, -%c %s\n"
                       "        %s\n",
                       pArg->pszArgLong, pArg->chArgShort, pArg->pszArg, pArg->pszDesc);
            else
                printf("    --%s, -%c\n"
                       "        %s\n",
                       pArg->pszArgLong, pArg->chArgShort, pArg->pszDesc);
        }
        else
        {
            if (pArg->pszArg)
                printf("    --%s, -%c %s\n", pArg->pszArgLong, pArg->chArgShort, pArg->pszArg);
            else
                printf("    --%s, -%c\n", pArg->pszArgLong, pArg->chArgShort);
        }
    }

    if (fVerbose)
        printf("\n");
}


void PSPCfgHelp(const char *pszBinary, bool fVerbose)
{
    printf("%s: AMD Platform Secure Processor emulator\n", pszBinary);

    /* Go through the individual groups and dump the help text. */
    for (uint32_t i = 0; i < ELEMENTS(g_aCfgArgGroups); i++)
        pspCfgHelpArgGroup(&g_aCfgArgGroups[i], fVerbose);
}


