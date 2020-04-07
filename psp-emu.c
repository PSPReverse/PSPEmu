/** @file
 * PSP Emulator - Entry point.
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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpspproxy.h>

#include <common/cdefs.h>
#include <psp-fw/boot-rom-svc-page.h>

#include <psp-core.h>
#include <psp-dbg.h>
#include <psp-flash.h>
#include <psp-iom.h>
#include <psp-devs.h>
#include <psp-cfg.h>
#include <psp-svc.h>
#include <psp-trace.h>


/**
 * Available options for PSPEmu.
 */
static struct option g_aOptions[] =
{
    {"emulation-mode",       required_argument, 0, 'm'},
    {"flash-rom",            required_argument, 0, 'f'},
    {"on-chip-bl",           required_argument, 0, 'o'},
    {"boot-rom-svc-page",    required_argument, 0, 's'},
    {"bin-load",             required_argument, 0, 'b'},
    {"bin-contains-hdr",     no_argument,       0, 'p'},
    {"dbg",                  required_argument, 0, 'd'},
    {"load-psp-dir",         no_argument,       0, 'l'},
    {"psp-dbg-mode",         no_argument,       0, 'g'},
    {"psp-proxy-addr",       required_argument, 0, 'x'},
    {"trace-log",            required_argument, 0, 't'},
    {"micro-arch",           required_argument, 0, 'a'},
    {"cpu-segment",          required_argument, 0, 'c'},
    {"intercept-svc-6",      no_argument,       0, '6'},
    {"trace-svcs",           no_argument,       0, 'v'},
    {"acpi-state",           required_argument, 0, 'i'},
    {"uart-remote-addr",     required_argument, 0, 'u'},
    {"timer-real-time",      no_argument      , 0, 'r'},
    {"preload-app",          required_argument, 0, 'j'},
    {"em100-emu-port",       required_argument, 0, 'e'},

    {"help",                 no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


/**
 * Parses the command line arguments and creates the emulator config.
 *
 * @returns Status code.
 * @param   argc        Argument count as passed from main.
 * @param   argv        Argument vector as passed from main.
 * @param   pCfg        The config structure to initialize.
 */
static int pspEmuCfgParse(int argc, char *argv[], PPSPEMUCFG pCfg)
{
    int ch = 0;
    int idxOption = 0;

    pCfg->enmMode               = PSPEMUMODE_INVALID;
    pCfg->pszPathFlashRom       = NULL;
    pCfg->pszPathOnChipBl       = NULL;
    pCfg->pszPathBinLoad        = NULL;
    pCfg->pszPathBootRomSvcPage = NULL;
    pCfg->fBinContainsHdr       = false;
    pCfg->uDbgPort              = 0;
    pCfg->fLoadPspDir           = false;
    pCfg->fIncptSvc6            = false;
    pCfg->fTraceSvcs            = false;
    pCfg->fTimerRealtime        = false;
    pCfg->pszPspProxyAddr       = NULL;
    pCfg->pszTraceLog           = NULL;
    pCfg->enmMicroArch          = PSPEMUMICROARCH_INVALID;
    pCfg->enmCpuSegment         = PSPEMUAMDCPUSEGMENT_INVALID;
    pCfg->enmAcpiState          = PSPEMUACPISTATE_S5;
    pCfg->pszUartRemoteAddr     = NULL;
    pCfg->pszAppPreload         = NULL;
    pCfg->uEm100FlashEmuPort    = 0;
    pCfg->cSockets              = 1;
    pCfg->cCcdsPerSocket        = 1;
    pCfg->papszDevs             = NULL;

    while ((ch = getopt_long (argc, argv, "hpbr:m:f:o:d:s:x:a:c:u:j:e:", &g_aOptions[0], &idxOption)) != -1)
    {
        switch (ch)
        {
            case 'h':
            case 'H':
                printf("%s: AMD Platform Secure Processor emulator\n"
                       "    --emulation-mode [app|sys|on-chip-bl]\n"
                       "    --flash-rom <path/to/flash/rom>\n"
                       "    --boot-rom-svc-page <path/to/boot/rom/svc/page>\n"
                       "    --bin-contains-hdr The binaries contain the 256 byte header, omit if raw binaries\n"
                       "    --bin-load <path/to/binary/to/load>\n"
                       "    --on-chip-bl <path/to/on-chip-bl/binary>\n"
                       "    --dbg <listening port>\n"
                       "    --psp-proxy-addr <path/to/proxy/device>\n"
                       "    --load-psp-dir\n"
                       "    --psp-dbg-mode\n"
                       "    --trace-log <path/to/trace/log>\n"
                       "    --micro-arch <zen|zen+|zen2>\n"
                       "    --cpu-segment <ryzen|ryzen-pro|threadripper|epyc>\n"
                       "    --acpi-state <s0|s1|s1|s2|s3|s4|s5>\n"
                       "    --intercept-svc-6\n"
                       "    --trace-svcs\n"
                       "    --uart-remote-addr [<port>|<address:port>]\n"
                       "    --timer-real-time The timer clocks tick in realtime rather than emulated\n"
                       "    --preload-app <path/to/app/binary/with/hdr>\n"
                       "    --em100-emu-port <port for the EM100 network emulation>\n",
                       argv[0]);
                exit(0);
                break;

            case 'm':
                if (!strcmp(optarg, "app"))
                    pCfg->enmMode = PSPEMUMODE_APP;
                else if (!strcmp(optarg, "sys"))
                    pCfg->enmMode = PSPEMUMODE_SYSTEM;
                else if (!strcmp(optarg, "on-chip-bl"))
                    pCfg->enmMode = PSPEMUMODE_SYSTEM_ON_CHIP_BL;
                else
                {
                    fprintf(stderr, "--emulation-mode takes only one of [app|sys|on-chip-bl] as the emulation mode\n");
                    return -1;
                }
                break;
            case 'f':
                pCfg->pszPathFlashRom = optarg;
                break;
            case 's':
                pCfg->pszPathBootRomSvcPage = optarg;
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
                if (!strcasecmp(optarg, "zen"))
                    pCfg->enmMicroArch = PSPEMUMICROARCH_ZEN;
                else if (!strcasecmp(optarg, "zen+"))
                    pCfg->enmMicroArch = PSPEMUMICROARCH_ZEN_PLUS;
                else if (!strcasecmp(optarg, "zen2"))
                    pCfg->enmMicroArch = PSPEMUMICROARCH_ZEN2;
                else
                {
                    fprintf(stderr, "Unrecognised micro architecure: %s\n", optarg);
                    return -1;
                }
                break;
            }
            case 'c':
            {
                if (!strcasecmp(optarg, "ryzen"))
                    pCfg->enmCpuSegment = PSPEMUAMDCPUSEGMENT_RYZEN;
                else if (!strcasecmp(optarg, "ryzen-pro"))
                    pCfg->enmCpuSegment = PSPEMUAMDCPUSEGMENT_RYZEN_PRO;
                else if (!strcasecmp(optarg, "threadripper"))
                    pCfg->enmCpuSegment = PSPEMUAMDCPUSEGMENT_THREADRIPPER;
                else if (!strcasecmp(optarg, "epyc"))
                    pCfg->enmCpuSegment = PSPEMUAMDCPUSEGMENT_EPYC;
                else
                {
                    fprintf(stderr, "Unrecognised CPU segment: %s\n", optarg);
                    return -1;
                }
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
            case 'j':
                pCfg->pszAppPreload = optarg;
                break;
            case 'e':
                pCfg->uEm100FlashEmuPort = strtoul(optarg, NULL, 10);
                break;
            default:
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                return -1;
        }
    }

    /* Do some sanity checks of the config here. */
    if (!pCfg->pszPathFlashRom)
    {
        fprintf(stderr, "Flash ROM path is required\n");
        return -1;
    }

    if (   !pCfg->pszPathOnChipBl
        && pCfg->enmMode == PSPEMUMODE_SYSTEM_ON_CHIP_BL)
    {
        fprintf(stderr, "The on chip bootloader binary is required for the selected emulation mode\n");
        return -1;
    }

    if (   pCfg->enmMode != PSPEMUMODE_SYSTEM_ON_CHIP_BL
        && !pCfg->pszPathBinLoad)
    {
        fprintf(stderr, "Loading the designated binary from the flash image is not implemented yet, please load the binary explicitely using --bin-load\n");
        return -1;
    }

    if (   pCfg->fIncptSvc6
        && pCfg->enmMode == PSPEMUMODE_APP)
    {
        fprintf(stderr, "Application mode and explicit SVC 6 interception are mutually exclusive (svc 6 is always intercepted in app mode)\n");
        return -1;
    }

    if (   pCfg->fTraceSvcs
        && pCfg->enmMode == PSPEMUMODE_APP)
    {
        fprintf(stderr, "Application mode and SVC tracing are mutually exclusive (svcs are always traced in app mode)\n");
        return -1;
    }

    return 0;
}


extern int pspEmuMainLegacy(PPSPEMUCFG pCfg);

int main(int argc, char *argv[])
{
    PSPEMUCFG Cfg;

    /* Parse the config first. */
    int rc = pspEmuCfgParse(argc, argv, &Cfg);
    if (!rc)
        return pspEmuMainLegacy(&Cfg);
    else
        fprintf(stderr, "Parsing arguments failed with %d\n", rc);

    return 0;
}

