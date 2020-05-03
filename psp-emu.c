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

#include <psp-ccd.h>
#include <psp-dbg.h>
#include <psp-flash.h>
#include <psp-proxy.h>


static uint32_t g_idSocketSingle = UINT32_MAX;
static uint32_t g_idCcdSingle = UINT32_MAX;


/**
 * Available options for PSPEmu.
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
    {"micro-arch",                   required_argument, 0, 'a'},
    {"cpu-segment",                  required_argument, 0, 'c'},
    {"intercept-svc-6",              no_argument,       0, '6'},
    {"trace-svcs",                   no_argument,       0, 'v'},
    {"acpi-state",                   required_argument, 0, 'i'},
    {"uart-remote-addr",             required_argument, 0, 'u'},
    {"timer-real-time",              no_argument      , 0, 'r'},
    {"preload-app",                  required_argument, 0, 'j'},
    {"em100-emu-port",               required_argument, 0, 'e'},
    {"spi-flash-trace",              required_argument, 0, 'F'},
    {"coverage-trace",               required_argument, 0, 'V'},
    {"sockets",                      required_argument, 0, 'S'},
    {"ccds-per-socket",              required_argument, 0, 'C'},
    {"emulate-single-socket-id",     required_argument, 0, 'O'},
    {"emulate-single-die-id",        required_argument, 0, 'D'},
    {"emulate-devices",              required_argument, 0, 'E'},
    {"iom-log-all-accesses",         no_argument      , 0, 'I'},
    {"proxy-buffer-writes",          no_argument      , 0, 'P'},
    {"dbg-step-count",               required_argument, 0, 'G'},
    {"dbg-run-up-to",                required_argument, 0, 'U'},

    {"help",                         no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


/**
 * Frees all allocated resources for the given config.
 *
 * @returns nothing.
 * @param   pCfg                    The config to free all resources from.
 */
static void pspEmuCfgFree(PPSPEMUCFG pCfg)
{
    if (   pCfg->pvOnChipBl
        && pCfg->cbOnChipBl)
        PSPEmuFlashFree(pCfg->pvOnChipBl, pCfg->cbOnChipBl);

    if (   pCfg->pvFlashRom
        && pCfg->cbFlashRom)
        PSPEmuFlashFree(pCfg->pvFlashRom, pCfg->cbFlashRom);

    if (   pCfg->pvBinLoad
        && pCfg->cbBinLoad)
        PSPEmuFlashFree(pCfg->pvBinLoad, pCfg->cbBinLoad);

    if (   pCfg->pvAppPreload
        && pCfg->cbAppPreload)
        PSPEmuFlashFree(pCfg->pvAppPreload, pCfg->cbAppPreload);

    if (   pCfg->pvBootRomSvcPage
        && pCfg->cbBootRomSvcPage)
        PSPEmuFlashFree(pCfg->pvBootRomSvcPage, pCfg->cbBootRomSvcPage);

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
}


/**
 * Parses the given emulated device string and returns an array with individual entries.
 *
 * @returns Pointer to the Array of individual device entries on success.
 * @param   pszDevString            The device string form the command line to parse.
 */
static const char **pspEmuCfgParseDevices(const char *pszDevString)
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
    pCfg->cDbgInsnStep          = 0;
    pCfg->PspAddrDbgRunUpTo     = UINT32_MAX;
    pCfg->fLoadPspDir           = false;
    pCfg->fIncptSvc6            = false;
    pCfg->fTraceSvcs            = false;
    pCfg->fTimerRealtime        = false;
    pCfg->fBootRomSvcPageModify = true;
    pCfg->fIomLogAllAccesses    = false;
    pCfg->fProxyWrBuffer        = false;
    pCfg->pvFlashRom            = NULL;
    pCfg->cbFlashRom            = 0;
    pCfg->pvOnChipBl            = NULL;
    pCfg->cbOnChipBl            = 0;
    pCfg->pvBinLoad             = NULL;
    pCfg->cbBinLoad             = 0;
    pCfg->pvAppPreload          = NULL;
    pCfg->cbAppPreload          = 0;
    pCfg->pvBootRomSvcPage      = NULL;
    pCfg->cbBootRomSvcPage      = 0;
    pCfg->pszPspProxyAddr       = NULL;
    pCfg->pszTraceLog           = NULL;
    pCfg->enmMicroArch          = PSPEMUMICROARCH_INVALID;
    pCfg->enmCpuSegment         = PSPEMUAMDCPUSEGMENT_INVALID;
    pCfg->enmAcpiState          = PSPEMUACPISTATE_S5;
    pCfg->pszUartRemoteAddr     = NULL;
    pCfg->pszAppPreload         = NULL;
    pCfg->uEm100FlashEmuPort    = 0;
    pCfg->pszSpiFlashTrace      = NULL;
    pCfg->pszCovTrace           = NULL;
    pCfg->cSockets              = 1;
    pCfg->cCcdsPerSocket        = 1;
    pCfg->papszDevs             = NULL;

    while ((ch = getopt_long (argc, argv, "hpbrN:m:f:o:d:s:x:a:c:u:j:e:S:C:O:D:E:V:U:P:", &g_aOptions[0], &idxOption)) != -1)
    {
        switch (ch)
        {
            case 'h':
            case 'H':
                printf("%s: AMD Platform Secure Processor emulator\n"
                       "    --emulation-mode [app|sys|on-chip-bl|trusted-os]\n"
                       "    --flash-rom <path/to/flash/rom>\n"
                       "    --boot-rom-svc-page <path/to/boot/rom/svc/page>\n"
                       "    --boot-rom-svc-page-dont-alter Do not alter the boot ROM service page for the emulated CCD (IDs etc.)\n"
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
                       "    --em100-emu-port <port for the EM100 network emulation>\n"
                       "    --spi-flash-trace <path/to/psptrace/compatible/flash/trace>\n"
                       "    --coverage-trace <path/to/coverage/trace/file>\n"
                       "    --sockets <number of sockets to emulate>\n"
                       "    --ccds-per-sockets <number of CCDS per socket to emulate>\n"
                       "    --emulate-single-socket-id <id> Emulate only a single PSP with the given socket ID\n"
                       "    --emulate-single-die-id <id> Emulate only a single PSP with the given die ID\n"
                       "    --emulate-devices [<dev1>:<dev2>:...] Enables only the specified devices for emulation\n"
                       "    --iom-log-all-accesses I/O manager logs all device accesses not only the ones to unassigned regions\n"
                       "    --proxy-buffer-writes If proxy mode is enabled certain writes will be cached and sent in bursts to speed up certain access patterns\n"
                       "    --dbg-run-up-to <addr> Runs until the given address is hit and drops then into the debugger instead of right at the start\n"
                       "    --dbg-step-count <count> Number of instructions to step through in a single round, use at own RISK\n",
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
            case 'S':
                pCfg->cSockets = strtoul(optarg, NULL, 10);
                break;
            case 'C':
                pCfg->cCcdsPerSocket = strtoul(optarg, NULL, 10);
                break;
            case 'O':
                g_idSocketSingle = strtoul(optarg, NULL, 10);
                break;
            case 'D':
                g_idCcdSingle = strtoul(optarg, NULL, 10);
                break;
            case 'E':
                pCfg->papszDevs = pspEmuCfgParseDevices(optarg);
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
            case 'P':
                pCfg->fProxyWrBuffer = true;
                break;
            case 'G':
                pCfg->cDbgInsnStep = strtoul(optarg, NULL, 10);
                break;
            case 'U':
                pCfg->PspAddrDbgRunUpTo = strtoul(optarg, NULL, 0);
                break;
            default:
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                return -1;
        }
    }

    if (pCfg->enmMode == PSPEMUMODE_INVALID)
    {
        fprintf(stderr, "--emulation-mode is mandatory\n");
        return -1;
    }

    if (   pCfg->cSockets < 1
        || pCfg->cSockets > 2)
    {
        fprintf(stderr, "--sockets argument must be in range [1..2]\n");
        return -1;
    }

    if (   pCfg->cCcdsPerSocket < 1
        || pCfg->cCcdsPerSocket > 4)
    {
        fprintf(stderr, "--ccds-per-socket argument must be in range [1..4]\n");
        return -1;
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

    int rc = 0;
    if (pCfg->pszPathOnChipBl)
    {
        rc = PSPEmuFlashLoadFromFile(pCfg->pszPathOnChipBl, &pCfg->pvOnChipBl, &pCfg->cbOnChipBl);
        if (rc)
            fprintf(stderr, "Loading the on chip bootloader ROM failed with %d\n", rc);
    }

    if (!rc)
    {
        rc = PSPEmuFlashLoadFromFile(pCfg->pszPathFlashRom, &pCfg->pvFlashRom, &pCfg->cbFlashRom);
        if (rc)
            fprintf(stderr, "Loading the flash ROM failed with %d\n", rc);
    }

    if (   !rc
        && pCfg->pszPathBinLoad)
    {
        rc = PSPEmuFlashLoadFromFile(pCfg->pszPathBinLoad, &pCfg->pvBinLoad, &pCfg->cbBinLoad);
        if (rc)
            fprintf(stderr, "Loading the binary \"%s\" failed with %d\n", pCfg->pszPathBinLoad, rc);
    }

    if (   !rc
        && pCfg->pszAppPreload)
    {
        rc = PSPEmuFlashLoadFromFile(pCfg->pszAppPreload, &pCfg->pvAppPreload, &pCfg->cbAppPreload);
        if (rc)
            fprintf(stderr, "Loading the app binary failed with %d\n", rc);
    }

    if (   !rc
        && pCfg->pszPathBootRomSvcPage)
    {
        rc = PSPEmuFlashLoadFromFile(pCfg->pszPathBootRomSvcPage, &pCfg->pvBootRomSvcPage, &pCfg->cbBootRomSvcPage);
        if (rc)
            fprintf(stderr, "Loading the boot ROM service page from the given file failed with %d\n", rc);
    }

    if (rc)
        pspEmuCfgFree(pCfg);

    return rc;
}


/**
 * Executes the given CCD under debugger control.
 *
 * @returns Status code.
 * @param   hCcd                    The CCD instance to run in a debugger.
 * @param   pCfg                    The configuration.
 */
static int pspEmuDbgRun(PSPCCD hCcd, PCPSPEMUCFG pCfg)
{
    PSPCORE hPspCore = NULL;

    int rc = PSPEmuCcdQueryCore(hCcd, &hPspCore);
    if (!rc)
    {
        /*
         * Execute one instruction to initialize the CPU state properly
         * so the debugger has valid values to work with.
         */
        int rc = PSPEmuCoreExecRun(hPspCore, 1, PSPEMU_CORE_EXEC_INDEFINITE);
        if (!rc)
        {
            PSPDBG hDbg = NULL;

            rc = PSPEmuDbgCreate(&hDbg, pCfg->uDbgPort, pCfg->cDbgInsnStep, pCfg->PspAddrDbgRunUpTo,
                                 &hCcd, 1);
            if (!rc)
            {
                printf("Debugger is listening on port %u...\n", pCfg->uDbgPort);
                rc = PSPEmuDbgRunloop(hDbg);
            }
        }
    }

    return rc;
}


int main(int argc, char *argv[])
{
    PSPEMUCFG Cfg;

    /* Parse the config first. */
    int rc = pspEmuCfgParse(argc, argv, &Cfg);
    if (!rc)
    {
        PSPCCD hCcd = NULL;
        if (   g_idSocketSingle != UINT32_MAX
            && g_idCcdSingle != UINT32_MAX)
            rc = PSPEmuCcdCreate(&hCcd, g_idSocketSingle, g_idCcdSingle, &Cfg);
        else
            rc = PSPEmuCcdCreate(&hCcd, 0, 0, &Cfg);

        if (!rc)
        {
            PSPPROXY hProxy = NULL;

            /* Setup the proxy if configured. */
            if (Cfg.pszPspProxyAddr)
            {
                rc = PSPProxyCreate(&hProxy, &Cfg);
                if (!rc)
                    rc = PSPProxyCcdRegister(hProxy, hCcd);
            }

            if (!rc)
            {
                if (Cfg.uDbgPort)
                    rc = pspEmuDbgRun(hCcd, &Cfg);
                else
                    rc = PSPEmuCcdRun(hCcd);
            }

            if (hProxy)
                PSPProxyCcdDeregister(hProxy, hCcd);

            PSPEmuCcdDestroy(hCcd);
        }

        pspEmuCfgFree(&Cfg);
    }
    else
        fprintf(stderr, "Parsing arguments failed with %d\n", rc);

    return 0;
}

