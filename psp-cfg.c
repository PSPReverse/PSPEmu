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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <common/types.h>
#include <common/cdefs.h>
#include <common/status.h>

#include <os/file.h>

#include <psp-cfg.h>
#include <psp-profile.h>
#include <psp-trace.h>


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
 * Available options for PSPEmu.
 * @todo Merge with argument descriptors to avoid duplication.
 */
static struct option g_aOptions[] =
{
    {"emulation-mode",               required_argument, 0, 'm'},
    {"flash-rom",                    required_argument, 0, 'f'},
    {"on-chip-bl",                   required_argument, 0, 'o'},
    {"boot-rom-svc-page",            required_argument, 0, 's'},
    {"boot-rom-svc-page-dont-alter", no_argument,       0, 'n'},
    {"bin-load",                     required_argument, 0, 'b'},
    {"bin-contains-hdr",             no_argument,       0, 'p'},
    {"dbg",                          required_argument, 0, 'd'},
    {"load-psp-dir",                 no_argument,       0, 'l'},
    {"psp-dbg-mode",                 no_argument,       0, 'g'},
    {"psp-proxy-addr",               required_argument, 0, 'x'},
    {"trace-log",                    required_argument, 0, 't'},
    {"psp-profile",                  required_argument, 0, 'a'},
    {"cpu-profile",                  required_argument, 0, 'c'},
    {"intercept-svc-6",              no_argument,       0, '6'},
    {"trace-svcs",                   no_argument,       0, 'v'},
    {"trace-cfg",                    required_argument, 0, 'Q'},
    {"acpi-state",                   required_argument, 0, 'i'},
    {"uart-remote-addr",             required_argument, 0, 'u'},
    {"timer-real-time",              no_argument      , 0, 'r'},
    {"spi-flash-trace",              required_argument, 0, 'F'},
    {"coverage-trace",               required_argument, 0, 'V'},
    {"sockets",                      required_argument, 0, 'S'},
    {"ccds-per-socket",              required_argument, 0, 'C'},
    {"emulate-single-socket-id",     required_argument, 0, 'O'},
    {"emulate-single-die-id",        required_argument, 0, 'D'},
    {"emulate-devices",              required_argument, 0, 'E'},
    {"iom-log-all-accesses",         no_argument      , 0, 'I'},
    {"io-log-write",                 required_argument, 0, 'L'},
    {"io-log-replay",                required_argument, 0, 'Y'},
    {"proxy-buffer-writes",          no_argument      , 0, 'P'},
    {"dbg-step-count",               required_argument, 0, 'G'},
    {"dbg-run-up-to",                required_argument, 0, 'U'},
    {"proxy-trusted-os-handover",    required_argument, 0, 'T'},
    {"proxy-ccp",                    no_argument,       0, 'X'},
    {"proxy-x86-cores-no-release",   no_argument,       0, '8'},
    {"memory-preload",               required_argument, 0, 'M'},
    {"memory-create",                required_argument, 0, 'R'},
    {"proxy-memory-wt",              required_argument, 0, 'W'},
    {"single-step-dump-core-state",  no_argument,       0, 'A'},

    {"help",                         no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


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
    {"trace-cfg",                    'Q', "[origin=severity:...]",            "Sets the minimum severity for the given origin in order to appear in the trace log"},
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
 * Parses the given emulated device string and returns an array with individual entries.
 *
 * @returns Pointer to the Array of individual device entries on success.
 * @param   pszDevString            The device string form the command line to parse.
 */
static const char **pspCfgParseDevices(const char *pszDevString)
{
    /* Count the number of : separators first. */
    uint32_t cDevs = 1; /* Account for the NULL entry in the table. */
    const char *pszCur = pszDevString;
    while (*pszCur != '\0')
    {
        char *pszSep = strchr(pszCur, ':');
        if (!pszSep) /* Last device? */
            pszSep = strchr(pszCur, '\0');
        if (!pszSep)
            break;

        cDevs++;
        if (*pszSep != '\0')
            pszCur = pszSep + 1;
        else
            pszCur = pszSep;
    }

    const char **papszDevs = (const char **)calloc(cDevs, sizeof(const char *));
    if (papszDevs)
    {
        uint32_t idxDev = 0;

        pszCur = pszDevString;
        while (*pszCur != '\0')
        {
            char *pszSep = strchr(pszCur, ':');
            if (!pszSep)
                pszSep = strchr(pszCur, '\0');
            if (!pszSep)
                break;

            papszDevs[idxDev] = strndup(pszCur, pszSep - pszCur);
            if (   !papszDevs[idxDev]
                && idxDev > 0)
            {
                /* Rollback. */
                while (idxDev)
                {
                    free((void *)papszDevs[idxDev - 1]);
                    idxDev--;
                }

                free(papszDevs);
                papszDevs = NULL;
                break;
            }

            idxDev++;
            if (*pszSep != '\0')
                pszCur = pszSep + 1;
            else
                pszCur = pszSep;
        }
    }

    return papszDevs;
}


/**
 * Parses the give ntrace config.
 *
 * @returns Status code.
 * @param   pCfg                    The config to add the config to upon success.
 * @param   pszTraceCfg             The trace config to parse.
 */
static int pspCfgParseTraceCfg(PPSPEMUCFG pCfg, const char *pszTraceCfg)
{
    /* Count the number of : separators first. */
    uint32_t cDescs = 1; /* Account for the NULL entry in the table. */
    const char *pszCur = pszTraceCfg;
    while (*pszCur != '\0')
    {
        char *pszSep = strchr(pszCur, ':');
        if (!pszSep) /* Last device? */
            pszSep = strchr(pszCur, '\0');
        if (!pszSep)
            break;

        cDescs++;
        if (*pszSep != '\0')
            pszCur = pszSep + 1;
        else
            pszCur = pszSep;
    }

    int rc = STS_INF_SUCCESS;
    PPSPEMUCFGTRACECFGDESC paTraceCfg = (PPSPEMUCFGTRACECFGDESC)calloc(cDescs, sizeof(*paTraceCfg));
    if (paTraceCfg)
    {
        uint32_t idxDesc = 0;

        pszCur = pszTraceCfg;
        while (*pszCur != '\0')
        {
            char *pszSep = strchr(pszCur, ':');
            if (!pszSep)
                pszSep = strchr(pszCur, '\0');
            if (!pszSep)
            {
                rc = STS_ERR_INVALID_PARAMETER;
                break;
            }

            size_t cchDesc = pszSep - pszCur;
            char szDesc[512]; /** @todo Lazy approach but should be more than enough. */
            if (cchDesc >= sizeof(szDesc))
            {
                rc = STS_ERR_INVALID_PARAMETER;
                break;
            }
            memcpy(&szDesc[0], pszCur, cchDesc);
            szDesc[cchDesc] = '\0';

            /* A valid config descriptor should have a = in it. */
            char *pszSeverityStart = strchr(&szDesc[0], '=');
            if (!pszSeverityStart)
            {
                rc = STS_ERR_INVALID_PARAMETER;
                break;
            }

            *pszSeverityStart++ = '\0'; /* Terminate the origin, severity is already terminated. */

            /* Translate to the proper enums. */
            rc = PSPEmuTraceSeverityStringQueryEnum(pszSeverityStart, &paTraceCfg[idxDesc].enmSeverity);
            if (STS_SUCCESS(rc))
                rc = PSPEmuTraceOriginStringQueryEnum(&szDesc[0],&paTraceCfg[idxDesc].enmOrigin);
            if (STS_FAILURE(rc))
                break;

            idxDesc++;
            if (*pszSep != '\0')
                pszCur = pszSep + 1;
            else
                pszCur = pszSep;
        }

        if (STS_SUCCESS(rc))
            pCfg->paTraceCfg = paTraceCfg;
        else
            free(paTraceCfg);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


/**
 * Parses a signle given preload descriptor string and adds it to the given config.
 *
 * @returns Status code.
 * @param   pCfg                    The config to add the descriptor to upon success.
 * @param   pszPreload              The preload descriptor string to parse.
 */
static int pspCfgMemPreloadParse(PPSPEMUCFG pCfg, const char *pszPreload)
{
    int rc = STS_INF_SUCCESS;
    PSPEMUCFGMEMPRELOAD MemPreload;
    const char *pszCur = pszPreload;

    char *pszSep = strchr(pszCur, ':');
    if (pszSep)
    {
        if (!strncmp(pszCur, "psp", pszSep - pszCur))
            MemPreload.enmAddrSpace = PSPADDRSPACE_PSP;
        else if (!strncmp(pszCur, "smn", pszSep - pszCur))
            MemPreload.enmAddrSpace = PSPADDRSPACE_SMN;
        else if (!strncmp(pszCur, "x86", pszSep - pszCur))
            MemPreload.enmAddrSpace = PSPADDRSPACE_X86;
        else
            rc = STS_ERR_INVALID_PARAMETER;

        if (STS_SUCCESS(rc))
        {
            pszCur = pszSep + 1;
            pszSep = strchr(pszCur, ':');

            if (pszSep)
            {
                char *pszEndPtr;

                errno = 0;
                uint64_t uAddr = strtoull(pszCur, &pszEndPtr, 0);
                if (   !errno
                    && pszEndPtr == pszSep)
                {
                    switch (MemPreload.enmAddrSpace)
                    {
                        case PSPADDRSPACE_PSP:
                        {
                            if (uAddr == (PSPPADDR)uAddr)
                                MemPreload.u.PspAddr = (PSPPADDR)uAddr;
                            else
                                rc = STS_ERR_BUFFER_OVERFLOW;
                            break;
                        }
                        case PSPADDRSPACE_SMN:
                        {
                            if (uAddr == (SMNADDR)uAddr)
                                MemPreload.u.SmnAddr = (SMNADDR)uAddr;
                            else
                                rc = STS_ERR_BUFFER_OVERFLOW;
                            break;
                        }
                        case PSPADDRSPACE_X86:
                        {
                            MemPreload.u.PhysX86Addr = uAddr;
                            break;
                        }
                        default:
                            rc = STS_ERR_INVALID_PARAMETER;
                    }

                    if (STS_SUCCESS(rc))
                    {
                        MemPreload.pszFilePreload = pszSep + 1;

                        /* Add the descriptor the array. */
                        uint32_t cMemPreloadNew = pCfg->cMemPreload + 1;
                        PCPSPEMUCFGMEMPRELOAD paMemPreloadNew = (PCPSPEMUCFGMEMPRELOAD)realloc((void *)pCfg->paMemPreload,
                                                                                               cMemPreloadNew * sizeof(MemPreload));
                        if (paMemPreloadNew)
                        {
                            pCfg->paMemPreload = paMemPreloadNew;
                            pCfg->cMemPreload  = cMemPreloadNew;
                            memcpy((void *)&pCfg->paMemPreload[cMemPreloadNew - 1], &MemPreload, sizeof(MemPreload));
                        }
                        else
                            rc = STS_ERR_NO_MEMORY;
                    }
                }
                else
                    rc = STS_ERR_INVALID_PARAMETER;
            }
            else
                rc = STS_ERR_INVALID_PARAMETER;
        }
    }
    else
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


/**
 * Parses a signle given preload descriptor string and adds it to the given config.
 *
 * @returns Status code.
 * @param   pCfg                    The config to add the descriptor to upon success.
 * @param   pszRegion               The region descriptor string to parse.
 */
static int pspCfgMemRegionParse(PPSPEMUCFG pCfg, const char *pszRegion)
{
    int rc = STS_INF_SUCCESS;
    PSPEMUCFGMEMREGIONCREATE MemRegion;
    const char *pszCur = pszRegion;

    char *pszSep = strchr(pszCur, ':');
    if (pszSep)
    {
        if (!strncmp(pszCur, "psp", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_PSP;
        else if (!strncmp(pszCur, "smn", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_SMN;
        else if (!strncmp(pszCur, "x86", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_X86;
        else
            rc = STS_ERR_INVALID_PARAMETER;

        if (STS_SUCCESS(rc))
        {
            pszCur = pszSep + 1;
            pszSep = strchr(pszCur, ':');

            if (pszSep)
            {
                char *pszEndPtr;

                errno = 0;
                uint64_t uAddr = strtoull(pszCur, &pszEndPtr, 0);
                if (   !errno
                    && pszEndPtr == pszSep)
                {
                    switch (MemRegion.enmAddrSpace)
                    {
                        case PSPADDRSPACE_PSP:
                        {
                            if (uAddr == (PSPPADDR)uAddr)
                                MemRegion.u.PspAddr = (PSPPADDR)uAddr;
                            else
                                rc = STS_ERR_BUFFER_OVERFLOW;
                            break;
                        }
                        case PSPADDRSPACE_SMN:
                        {
                            if (uAddr == (SMNADDR)uAddr)
                                MemRegion.u.SmnAddr = (SMNADDR)uAddr;
                            else
                                rc = STS_ERR_BUFFER_OVERFLOW;
                            break;
                        }
                        case PSPADDRSPACE_X86:
                        {
                            MemRegion.u.PhysX86Addr = uAddr;
                            break;
                        }
                        default:
                            rc = STS_ERR_INVALID_PARAMETER;
                    }

                    if (STS_SUCCESS(rc))
                    {
                        MemRegion.cbRegion = strtoull(pszSep + 1, &pszEndPtr, 0);
                        if (*pszEndPtr == '\0')
                        {
                            /* Add the descriptor the array. */
                            uint32_t cMemCreateNew = pCfg->cMemCreate + 1;
                            PCPSPEMUCFGMEMREGIONCREATE paMemCreateNew = (PCPSPEMUCFGMEMREGIONCREATE)realloc((void *)pCfg->paMemCreate,
                                                                                                            cMemCreateNew * sizeof(MemRegion));
                            if (paMemCreateNew)
                            {
                                pCfg->paMemCreate = paMemCreateNew;
                                pCfg->cMemCreate  = cMemCreateNew;
                                memcpy((void *)&pCfg->paMemCreate[cMemCreateNew - 1], &MemRegion, sizeof(MemRegion));
                            }
                            else
                                rc = STS_ERR_NO_MEMORY;
                        }
                        else
                            rc = STS_ERR_INVALID_PARAMETER;
                    }
                }
                else
                    rc = STS_ERR_INVALID_PARAMETER;
            }
            else
                rc = STS_ERR_INVALID_PARAMETER;
        }
    }
    else
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


/**
 * Parses a single given proxy memory region write through descriptor string and adds it to the given config.
 *
 * @returns Status code.
 * @param   pCfg                    The config to add the descriptor to upon success.
 * @param   pszRegion               The region descriptor string to parse.
 */
static int pspCfgProxyMemRegionWtParse(PPSPEMUCFG pCfg, const char *pszRegion)
{
    int rc = STS_INF_SUCCESS;
    PSPEMUCFGPROXYMEMWT MemRegion;
    const char *pszCur = pszRegion;

    char *pszSep = strchr(pszCur, ':');
    if (pszSep)
    {
        if (!strncmp(pszCur, "psp", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_PSP;
        else if (!strncmp(pszCur, "psp-mem", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_PSP_MEM;
        else if (!strncmp(pszCur, "psp-mmio", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_PSP_MMIO;
        else if (!strncmp(pszCur, "smn", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_SMN;
        else if (!strncmp(pszCur, "x86", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_X86;
        else if (!strncmp(pszCur, "x86-mem", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_X86_MEM;
        else if (!strncmp(pszCur, "x86-mmio", pszSep - pszCur))
            MemRegion.enmAddrSpace = PSPADDRSPACE_X86_MMIO;
        else
            rc = STS_ERR_INVALID_PARAMETER;

        if (STS_SUCCESS(rc))
        {
            pszCur = pszSep + 1;
            pszSep = strchr(pszCur, ':');

            if (pszSep)
            {
                char *pszEndPtr;

                errno = 0;
                uint64_t uAddr = strtoull(pszCur, &pszEndPtr, 0);
                if (   !errno
                    && pszEndPtr == pszSep)
                {
                    switch (MemRegion.enmAddrSpace)
                    {
                        case PSPADDRSPACE_PSP:
                        {
                            if (uAddr == (PSPPADDR)uAddr)
                                MemRegion.u.PspAddr = (PSPPADDR)uAddr;
                            else
                                rc = STS_ERR_BUFFER_OVERFLOW;
                            break;
                        }
                        case PSPADDRSPACE_SMN:
                        {
                            if (uAddr == (SMNADDR)uAddr)
                                MemRegion.u.SmnAddr = (SMNADDR)uAddr;
                            else
                                rc = STS_ERR_BUFFER_OVERFLOW;
                            break;
                        }
                        case PSPADDRSPACE_X86:
                        {
                            MemRegion.u.PhysX86Addr = uAddr;
                            break;
                        }
                        default:
                            rc = STS_ERR_INVALID_PARAMETER;
                    }

                    if (STS_SUCCESS(rc))
                    {
                        MemRegion.cbRegion = strtoull(pszSep + 1, &pszEndPtr, 0);
                        if (*pszEndPtr == '\0')
                        {
                            /* Add the descriptor the array. */
                            uint32_t cProxyMemWtNew = pCfg->cProxyMemWt + 1;
                            PCPSPEMUCFGPROXYMEMWT paMemWtNew = (PCPSPEMUCFGPROXYMEMWT)realloc((void *)pCfg->paMemCreate,
                                                                                              cProxyMemWtNew * sizeof(MemRegion));
                            if (paMemWtNew)
                            {
                                pCfg->paProxyMemWt = paMemWtNew;
                                pCfg->cProxyMemWt  = cProxyMemWtNew;
                                memcpy((void *)&pCfg->paProxyMemWt[cProxyMemWtNew - 1], &MemRegion, sizeof(MemRegion));
                            }
                            else
                                rc = STS_ERR_NO_MEMORY;
                        }
                        else
                            rc = STS_ERR_INVALID_PARAMETER;
                    }
                }
                else
                    rc = STS_ERR_INVALID_PARAMETER;
            }
            else
                rc = STS_ERR_INVALID_PARAMETER;
        }
    }
    else
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


/**
 * Verifies the given config for some basic sanity.
 *
 * @returns status code.
 * @param   pCfg                    The config to verify.
 */
static int pspCfgVerify(PCPSPEMUCFG pCfg)
{
    if (pCfg->enmMode == PSPEMUMODE_INVALID)
    {
        fprintf(stderr, "--emulation-mode is mandatory\n");
        return STS_ERR_GENERAL_ERROR;
    }

    if (   pCfg->cSockets < 1
        || pCfg->cSockets > 2)
    {
        fprintf(stderr, "--sockets argument must be in range [1..2]\n");
        return STS_ERR_GENERAL_ERROR;
    }

    if (   pCfg->cCcdsPerSocket < 1
        || pCfg->cCcdsPerSocket > 4)
    {
        fprintf(stderr, "--ccds-per-socket argument must be in range [1..4]\n");
        return STS_ERR_GENERAL_ERROR;
    }

    /* Do some sanity checks of the config here. */
    if (!pCfg->pszPathFlashRom)
    {
        fprintf(stderr, "Flash ROM path is required\n");
        return STS_ERR_GENERAL_ERROR;
    }

    if (   !pCfg->pszPathOnChipBl
        && pCfg->enmMode == PSPEMUMODE_SYSTEM_ON_CHIP_BL)
    {
        fprintf(stderr, "The on chip bootloader binary is required for the selected emulation mode\n");
        return STS_ERR_GENERAL_ERROR;
    }

    if (   pCfg->enmMode != PSPEMUMODE_SYSTEM_ON_CHIP_BL
        && !pCfg->pszPathBinLoad)
    {
        fprintf(stderr, "Loading the designated binary from the flash image is not implemented yet, please load the binary explicitely using --bin-load\n");
        return STS_ERR_GENERAL_ERROR;
    }

    if (   pCfg->fIncptSvc6
        && pCfg->enmMode == PSPEMUMODE_APP)
    {
        fprintf(stderr, "Application mode and explicit SVC 6 interception are mutually exclusive (svc 6 is always intercepted in app mode)\n");
        return STS_ERR_GENERAL_ERROR;
    }

    if (   pCfg->fTraceSvcs
        && pCfg->enmMode == PSPEMUMODE_APP)
    {
        fprintf(stderr, "Application mode and SVC tracing are mutually exclusive (svcs are always traced in app mode)\n");
        return STS_ERR_GENERAL_ERROR;
    }

    if (   pCfg->pszIoLogReplay
        && pCfg->pszPspProxyAddr)
    {
        fprintf(stderr, "Proxy mode and I/O log replay are mutually exclusive\n");
        return STS_ERR_GENERAL_ERROR;
    }

    return STS_INF_SUCCESS;
}


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


void PSPCfgInit(PPSPEMUCFG pCfg)
{
    pCfg->enmMode               = PSPEMUMODE_INVALID;
    pCfg->pszPathFlashRom       = NULL;
    pCfg->pszPathOnChipBl       = NULL;
    pCfg->pszPathBinLoad        = NULL;
    pCfg->pszPathBootRomSvcPage = NULL;
    pCfg->fBinContainsHdr       = false;
    pCfg->uDbgPort              = 0;
    pCfg->cDbgInsnStep          = 0;
    pCfg->PspAddrDbgRunUpTo     = UINT32_MAX;
    pCfg->fLoadPspDir           = false;
    pCfg->fIncptSvc6            = false;
    pCfg->fTraceSvcs            = false;
    pCfg->fTimerRealtime        = false;
    pCfg->fBootRomSvcPageModify = true;
    pCfg->fIomLogAllAccesses    = false;
    pCfg->fProxyWrBuffer        = false;
    pCfg->fCcpProxy             = false;
    pCfg->fProxyBlockX86CoreRelease = false;
    pCfg->pvFlashRom            = NULL;
    pCfg->cbFlashRom            = 0;
    pCfg->pvOnChipBl            = NULL;
    pCfg->cbOnChipBl            = 0;
    pCfg->pvBinLoad             = NULL;
    pCfg->cbBinLoad             = 0;
    pCfg->pszPspProxyAddr       = NULL;
    pCfg->PspAddrProxyTrustedOsHandover = 0;
    pCfg->pszTraceLog           = NULL;
    pCfg->pCpuProfile           = NULL;
    pCfg->pPspProfile           = NULL;
    pCfg->enmAcpiState          = PSPEMUACPISTATE_S5;
    pCfg->pszUartRemoteAddr     = NULL;
    pCfg->pszSpiFlashTrace      = NULL;
    pCfg->pszIoLog              = NULL;
    pCfg->pszIoLogReplay        = NULL;
    pCfg->pszCovTrace           = NULL;
    pCfg->cSockets              = 1;
    pCfg->cCcdsPerSocket        = 1;
    pCfg->idSocketSingle        = UINT32_MAX;
    pCfg->idCcdSingle           = UINT32_MAX;
    pCfg->paMemCreate           = NULL;
    pCfg->cMemCreate            = 0;
    pCfg->paMemPreload          = NULL;
    pCfg->cMemPreload           = 0;
    pCfg->paProxyMemWt          = NULL;
    pCfg->cProxyMemWt           = 0;
    pCfg->papszDevs             = NULL;
    pCfg->pCcpProxyIf           = NULL;
    pCfg->hDbgHlp               = NULL;
    pCfg->fSingleStepDumpCoreState = false;
    pCfg->paTraceCfg               = NULL;
}


void PSPCfgFree(PPSPEMUCFG pCfg)
{
    if (pCfg->hDbgHlp)
        PSPEmuDbgHlpRelease(pCfg->hDbgHlp);

    if (   pCfg->pvOnChipBl
        && pCfg->cbOnChipBl)
        OSFileLoadAllFree(pCfg->pvOnChipBl, pCfg->cbOnChipBl);

    if (   pCfg->pvFlashRom
        && pCfg->cbFlashRom)
        OSFileLoadAllFree(pCfg->pvFlashRom, pCfg->cbFlashRom);

    if (   pCfg->pvBinLoad
        && pCfg->cbBinLoad)
        OSFileLoadAllFree(pCfg->pvBinLoad, pCfg->cbBinLoad);

    if (pCfg->papszDevs)
    {
        uint32_t idx = 0;
        while (pCfg->papszDevs[idx])
        {
            free((void *)pCfg->papszDevs[idx]);
            idx++;
        }

        free(pCfg->papszDevs);
    }

    if (pCfg->paMemCreate)
        free((void *)pCfg->paMemCreate);

    if (pCfg->paMemPreload)
        free((void *)pCfg->paMemPreload);

    if (pCfg->paProxyMemWt)
        free((void *)pCfg->paProxyMemWt);

    if (pCfg->paTraceCfg)
        free(pCfg->paTraceCfg);
}


int PSPCfgParse(PPSPEMUCFG pCfg, int cArgs, const char * const *papszArgs)
{
    int ch = 0;
    int idxOption = 0;

    PSPCfgInit(pCfg);

    while ((ch = getopt_long (cArgs, (char * const *)papszArgs, "hpbr8N:m:f:o:d:s:x:a:c:u:S:C:O:D:E:V:U:P:T:M:R:L:Y:W:IA", &g_aOptions[0], &idxOption)) != -1)
    {
        switch (ch)
        {
            case 'h':
            case 'H':
                PSPCfgHelp(papszArgs[0], true /*fVerbose*/);
                exit(0);
                break;

            case 'm':
                if (!strcmp(optarg, "app"))
                    pCfg->enmMode = PSPEMUMODE_APP;
                else if (!strcmp(optarg, "sys"))
                    pCfg->enmMode = PSPEMUMODE_SYSTEM;
                else if (!strcmp(optarg, "on-chip-bl"))
                    pCfg->enmMode = PSPEMUMODE_SYSTEM_ON_CHIP_BL;
                else if (!strcmp(optarg, "trusted-os"))
                    pCfg->enmMode = PSPEMUMODE_TRUSTED_OS;
                else
                {
                    fprintf(stderr, "--emulation-mode takes only one of [app|sys|on-chip-bl|trusted-os] as the emulation mode\n");
                    return -1;
                }
                break;
            case 'f':
                pCfg->pszPathFlashRom = optarg;
                break;
            case 's':
                pCfg->pszPathBootRomSvcPage = optarg;
                break;
            case 'n':
                pCfg->fBootRomSvcPageModify = false;
                break;
            case 'o':
                pCfg->pszPathOnChipBl = optarg;
                break;
            case 'p':
                pCfg->fBinContainsHdr = true;
                break;
            case 'b':
                pCfg->pszPathBinLoad = optarg;
                break;
            case 'd':
                pCfg->uDbgPort = strtoul(optarg, NULL, 10);
                break;
            case 'l':
                pCfg->fLoadPspDir = true;
                break;
            case 'g':
                pCfg->fPspDbgMode = true;
                break;
            case 'x':
                pCfg->pszPspProxyAddr = optarg;
                break;
            case 't':
                pCfg->pszTraceLog = optarg;
                break;
            case 'a':
            {
                pCfg->pPspProfile = PSPProfilePspGetById(optarg);
                if (!pCfg->pPspProfile)
                {
                    fprintf(stderr, "The PSP profile \"%s\" could not be found\n", optarg);
                    return -1;
                }
                break;
            }
            case 'c':
            {
                pCfg->pCpuProfile = PSPProfileAmdCpuGetById(optarg);
                if (!pCfg->pCpuProfile)
                {
                    fprintf(stderr, "The CPU profile \"%s\" could not be found\n", optarg);
                    return -1;
                }

                if (!pCfg->pPspProfile) /* Can be overwritten with a dedicated PSP profile argument. */
                    pCfg->pPspProfile = pCfg->pCpuProfile->pPspProfile;
                break;
            }
            case 'i':
            {
                if (!strcasecmp(optarg, "s0"))
                    pCfg->enmAcpiState = PSPEMUACPISTATE_S0;
                else if (!strcasecmp(optarg, "s1"))
                    pCfg->enmAcpiState = PSPEMUACPISTATE_S1;
                else if (!strcasecmp(optarg, "s2"))
                    pCfg->enmAcpiState = PSPEMUACPISTATE_S2;
                else if (!strcasecmp(optarg, "s3"))
                    pCfg->enmAcpiState = PSPEMUACPISTATE_S3;
                else if (!strcasecmp(optarg, "s4"))
                    pCfg->enmAcpiState = PSPEMUACPISTATE_S4;
                else if (!strcasecmp(optarg, "s5"))
                    pCfg->enmAcpiState = PSPEMUACPISTATE_S5;
                else
                {
                    fprintf(stderr, "Unrecognised ACPI state: %s\n", optarg);
                    return -1;
                }
                break;
            }
            case '6':
                pCfg->fIncptSvc6 = true;
                break;
            case 'v':
                pCfg->fTraceSvcs = true;
                break;
            case 'u':
                pCfg->pszUartRemoteAddr = optarg;
                break;
            case 'r':
                pCfg->fTimerRealtime = true;
                break;
            case 'S':
                pCfg->cSockets = strtoul(optarg, NULL, 10);
                break;
            case 'C':
                pCfg->cCcdsPerSocket = strtoul(optarg, NULL, 10);
                break;
            case 'O':
                pCfg->idSocketSingle = strtoul(optarg, NULL, 10);
                break;
            case 'D':
                pCfg->idCcdSingle = strtoul(optarg, NULL, 10);
                break;
            case 'E':
                pCfg->papszDevs = pspCfgParseDevices(optarg);
                break;
            case 'F':
                pCfg->pszSpiFlashTrace = optarg;
                break;
            case 'V':
                pCfg->pszCovTrace = optarg;
                break;
            case 'I':
                pCfg->fIomLogAllAccesses = true;
                break;
            case 'L':
                pCfg->pszIoLog = optarg;
                break;
            case 'Y':
                pCfg->pszIoLogReplay = optarg;
                break;
            case 'P':
                pCfg->fProxyWrBuffer = true;
                break;
            case 'G':
                pCfg->cDbgInsnStep = strtoul(optarg, NULL, 10);
                break;
            case 'U':
                pCfg->PspAddrDbgRunUpTo = strtoul(optarg, NULL, 0);
                break;
            case 'T':
                pCfg->PspAddrProxyTrustedOsHandover = strtoul(optarg, NULL, 0);
                break;
            case 'X':
                pCfg->fCcpProxy = true;
                break;
            case 'M':
            {
                int rc = pspCfgMemPreloadParse(pCfg, optarg);
                if (STS_FAILURE(rc))
                    return rc;
                break;
            }
            case 'R':
            {
                int rc = pspCfgMemRegionParse(pCfg, optarg);
                if (STS_FAILURE(rc))
                    return rc;
                break;
            }
            case 'W':
            {
                int rc = pspCfgProxyMemRegionWtParse(pCfg, optarg);
                if (STS_FAILURE(rc))
                    return rc;
                break;
            }
            case 'A':
                pCfg->fSingleStepDumpCoreState = true;
                break;
            case '8':
                pCfg->fProxyBlockX86CoreRelease = true;
                break;
            case 'Q':
            {
                int rc = pspCfgParseTraceCfg(pCfg, optarg);
                if (STS_FAILURE(rc))
                    return rc;
                break;
            }
            default:
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                return -1;
        }
    }

    int rc = pspCfgVerify(pCfg);
    if (   STS_SUCCESS(rc)
        && pCfg->pszPathOnChipBl)
    {
        rc = OSFileLoadAll(pCfg->pszPathOnChipBl, &pCfg->pvOnChipBl, &pCfg->cbOnChipBl);
        if (rc)
            fprintf(stderr, "Loading the on chip bootloader ROM failed with %d\n", rc);
    }

    if (STS_SUCCESS(rc))
    {
        rc = OSFileLoadAll(pCfg->pszPathFlashRom, &pCfg->pvFlashRom, &pCfg->cbFlashRom);
        if (rc)
            fprintf(stderr, "Loading the flash ROM failed with %d\n", rc);
    }

    if (   STS_SUCCESS(rc)
        && pCfg->pszPathBinLoad)
    {
        rc = OSFileLoadAll(pCfg->pszPathBinLoad, &pCfg->pvBinLoad, &pCfg->cbBinLoad);
        if (rc)
            fprintf(stderr, "Loading the binary \"%s\" failed with %d\n", pCfg->pszPathBinLoad, rc);
    }

    if (STS_FAILURE(rc))
        PSPCfgFree(pCfg);

    return rc;
}

