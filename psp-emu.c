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


static bool pspEmuSvcTrace(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcDbgLog(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);

#define PSPEMU_CORE_SVC_INIT_NULL                   { NULL, NULL, 0 }
#define PSPEMU_CORE_SVC_INIT_DEF(a_Name, a_Handler) { a_Name, a_Handler, PSPEMU_CORE_SVC_F_BEFORE }

/**
 * The SVC descriptors table.
 */
static PSPCORESVCDESC g_aSvcDescs[] =
{
    PSPEMU_CORE_SVC_INIT_NULL,
    PSPEMU_CORE_SVC_INIT_NULL,
    PSPEMU_CORE_SVC_INIT_NULL,
    PSPEMU_CORE_SVC_INIT_NULL,
    PSPEMU_CORE_SVC_INIT_NULL,
    PSPEMU_CORE_SVC_INIT_NULL,
    PSPEMU_CORE_SVC_INIT_DEF("SvcDbgLog", pspEmuSvcDbgLog),
};


/**
 * SVC injection registration record.
 */
static const PSPCORESVCREG g_Svc6Reg =
{
    /** GlobalSvc */
    {
        /** pszName */
        "Trace",
        /** pfnSvcHnd */
        pspEmuSvcTrace,
        /** fFlags */
        PSPEMU_CORE_SVC_F_BEFORE | PSPEMU_CORE_SVC_F_AFTER
    },
    /** cSvcDescs */
    ELEMENTS(g_aSvcDescs),
    /** paSvcDescs */
    &g_aSvcDescs[0]
};

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

    {"help",                 no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


static void pspEmuTraceState(PSPCORE hCore, PSPADDR uPspAddr, uint32_t cbInsn, void *pvUser)
{
    printf(">>> Tracing instruction at %#x, instruction size = 0x%x\n", uPspAddr, cbInsn);
    PSPEmuCoreStateDump(hCore);
}


static void pspEmuProxyPspMmioUnassignedRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspMmioRead(hPspProxyCtx, offMmio, cbRead, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspMmioUnassignedRead: Failed with %d\n", rc);
}


static void pspEmuProxyPspMmioUnassignedWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspMmioWrite(hPspProxyCtx, offMmio, cbWrite, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspMmioUnassignedWrite: Failed with %d\n", rc);
}


static void pspEmuProxyPspSmnUnassignedRead(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspSmnRead(hPspProxyCtx, 0 /*idCcdTgt*/, offSmn, cbRead, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspSmnUnassignedRead: Failed with %d\n", rc);
}


static void pspEmuProxyPspSmnUnassignedWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspSmnWrite(hPspProxyCtx, 0 /*idCcdTgt*/, offSmn, cbWrite, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspSmnUnassignedWrite: Failed with %d\n", rc);
}


static void pspEmuProxyX86UnassignedRead(X86PADDR offX86Phys, size_t cbRead, void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspX86MmioRead(hPspProxyCtx, offX86Phys, cbRead, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspX86UnassignedRead: Failed with %d\n", rc);
}


static void pspEmuProxyX86UnassignedWrite(X86PADDR offX86Phys, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspX86MmioWrite(hPspProxyCtx, offX86Phys, cbWrite, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspX86UnassignedWrite: Failed with %d\n", rc);
}


/**
 * Syscall tracer callback.
 */
static bool pspEmuSvcTrace(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPEMUCFG pCfg = (PPSPEMUCFG)pvUser;

    if (pCfg->fTraceSvcs)
        PSPEmuTraceEvtAddSvc(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_SVC, idxSyscall,
                               (fFlags & PSPEMU_CORE_SVC_F_BEFORE)
                             ? true
                             : false /* fEntry*/,
                             NULL /*pszMsg*/);
    return false;
}


/**
 * SVC 0x6 (DbgLog) syscall interception handler.
 */
static bool pspEmuSvcDbgLog(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser)
{
    PPSPEMUCFG pCfg = (PPSPEMUCFG)pvUser;

    if (!pCfg->fIncptSvc6)
        return false;

    /* Log the string. */
    PSPADDR PspAddrStr = 0;
    int rc = PSPEmuCoreQueryReg(hCore, PSPCOREREG_R0, &PspAddrStr);
    if (!rc)
    {
        char achStr[512];
        PSPEmuCoreMemRead(hCore, PspAddrStr, &achStr[0], 512);
        achStr[512 - 1] = '\0'; /* Ensure termination. */
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_SVC, &achStr[0]);
    }

    return true;
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

    pCfg->enmMode               = PSPCOREMODE_INVALID;
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

    while ((ch = getopt_long (argc, argv, "hpbr:m:f:o:d:s:x:a:c:u:", &g_aOptions[0], &idxOption)) != -1)
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
                       "    --timer-real-time The timer clocks tick in realtime rather than emulated\n",
                       argv[0]);
                exit(0);
                break;

            case 'm':
                if (!strcmp(optarg, "app"))
                    pCfg->enmMode = PSPCOREMODE_APP;
                else if (!strcmp(optarg, "sys"))
                    pCfg->enmMode = PSPCOREMODE_SYSTEM;
                else if (!strcmp(optarg, "on-chip-bl"))
                    pCfg->enmMode = PSPCOREMODE_SYSTEM_ON_CHIP_BL;
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
        && pCfg->enmMode == PSPCOREMODE_SYSTEM_ON_CHIP_BL)
    {
        fprintf(stderr, "The on chip bootloader binary is required for the selected emulation mode\n");
        return -1;
    }

    if (   pCfg->enmMode != PSPCOREMODE_SYSTEM_ON_CHIP_BL
        && !pCfg->pszPathBinLoad)
    {
        fprintf(stderr, "Loading the designated binary from the flash image is not implemented yet, please load the binary explicitely using --bin-load\n");
        return -1;
    }

    if (   pCfg->fIncptSvc6
        && pCfg->enmMode == PSPCOREMODE_APP)
    {
        fprintf(stderr, "Application mode and explicit SVC 6 interception are mutually exclusive (svc 6 is always intercepted in app mode)\n");
        return -1;
    }

    if (   pCfg->fTraceSvcs
        && pCfg->enmMode == PSPCOREMODE_APP)
    {
        fprintf(stderr, "Application mode and SVC tracing are mutually exclusive (svcs are always traced in app mode)\n");
        return -1;
    }

    return 0;
}


int main(int argc, char *argv[])
{
    PSPEMUCFG Cfg;

    /* Parse the config first. */
    int rc = pspEmuCfgParse(argc, argv, &Cfg);
    if (!rc)
    {
        void *pv = NULL;
        size_t cb = 0;

        rc = PSPEmuFlashLoadFromFile(Cfg.pszPathFlashRom, &pv, &cb);
        if (!rc)
        {
            PSPCORE hCore;

            Cfg.pvFlashRom = pv;
            Cfg.cbFlashRom = cb;

            rc = PSPEmuCoreCreate(&hCore, Cfg.enmMode, Cfg.enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 320 * _1K : _256K);
            if (!rc)
            {
                PSPIOM hIoMgr;

                rc = PSPEmuIoMgrCreate(&hIoMgr, hCore);
                if (!rc)
                {
                    if (Cfg.pszPathOnChipBl)
                    {
                        void *pvOnChipBl = NULL;
                        size_t cbOnChipBl = 0;

                        rc = PSPEmuFlashLoadFromFile(Cfg.pszPathOnChipBl, &pvOnChipBl, &cbOnChipBl);
                        if (!rc)
                        {
                            rc = PSPEmuCoreSetOnChipBl(hCore, pvOnChipBl, cbOnChipBl);
                            if (rc)
                                fprintf(stderr, "Setting the on chip bootloader ROM for the PSP core failed with %d\n", rc);
                        }
                        else
                            fprintf(stderr, "Loading the on chip bootloader ROM failed with %d\n", rc);
                    }

                    if (Cfg.pszPathBootRomSvcPage)
                    {
                        PPSPROMSVCPG pBootRomSvcPage = NULL;
                        size_t cbBootRomSvcPage = 0;

                        rc = PSPEmuFlashLoadFromFile(Cfg.pszPathBootRomSvcPage, (void **)&pBootRomSvcPage, &cbBootRomSvcPage);
                        if (!rc)
                        {
                            if (Cfg.fPspDbgMode)
                            {
                                printf("Activating PSP firmware debug mode\n");
                                pBootRomSvcPage->Fields.u32BootMode = 1;
                            }

                            if (Cfg.fLoadPspDir)
                            {
                                printf("Loading PSP 1st level directory from flash image into boot ROM service page\n");
                                uint8_t *pbFlashRom = (uint8_t *)Cfg.pvFlashRom;
                                memcpy(&pBootRomSvcPage->Fields.abFfsDir[0], &pbFlashRom[0x77000], sizeof(pBootRomSvcPage->Fields.abFfsDir)); /** @todo */
                            }

                            rc = PSPEmuCoreMemWrite(hCore, 0x3f000, pBootRomSvcPage, cbBootRomSvcPage);
                            if (rc)
                                fprintf(stderr, "Initializing the boot ROM service page from the given file failed with %d\n", rc);
                        }
                        else
                            fprintf(stderr, "Loading the boot ROM service page from the given file failed with %d\n", rc);
                    }
                    /** @todo else: Set one up based on the system information given in the arguments. */

                    if (Cfg.pszPathBinLoad)
                    {
                        void *pvBin = NULL;
                        size_t cbBin = 0;

                        rc = PSPEmuFlashLoadFromFile(Cfg.pszPathBinLoad, &pvBin, &cbBin);
                        if (!rc)
                        {
                            PSPADDR PspAddrWrite = 0;

                            switch (Cfg.enmMode)
                            {
                                case PSPCOREMODE_SYSTEM:
                                    PspAddrWrite = 0x0;
                                    break;
                                case PSPCOREMODE_APP:
                                    PspAddrWrite = 0x15000;
                                    break;
                                default:
                                    fprintf(stderr, "Invalid emulation mode selected for the loaded binary\n");
                                    return -1;
                            }

                            if (!Cfg.fBinContainsHdr)
                                PspAddrWrite += 256; /* Skip the header part. */

                            rc = PSPEmuCoreMemWrite(hCore, PspAddrWrite, pvBin, cbBin);
                            if (rc)
                                fprintf(stderr, "Writing the binary to PSP memory failed with %d\n", rc);

                            PSPEmuFlashFree(pvBin, cbBin);
                        }
                        else
                            fprintf(stderr, "Loading the binary failed with %d\n", rc);
                    }

                    if (!rc)
                    {
                        /** @todo Proper initialization,instantiation of attached devices. */
                        PPSPDEV pDev = NULL;
                        PSPSVC hSvc = NULL;
                        PSPPROXYCTX hPspProxyCtx = NULL;

                        if (Cfg.pszPspProxyAddr)
                        {
                            printf("PSP proxy: Connecting to %s\n", Cfg.pszPspProxyAddr);
                            rc = PSPProxyCtxCreate(&hPspProxyCtx, Cfg.pszPspProxyAddr);
                            if (!rc)
                            {
                                printf("PSP proxy: Connected to %s\n", Cfg.pszPspProxyAddr);

                                /* Register the unassigned handlers for the various regions. */
                                rc = PSPEmuIoMgrMmioUnassignedSet(hIoMgr, pspEmuProxyPspMmioUnassignedRead, pspEmuProxyPspMmioUnassignedWrite, hPspProxyCtx);
                                if (!rc)
                                    rc = PSPEmuIoMgrSmnUnassignedSet(hIoMgr, pspEmuProxyPspSmnUnassignedRead, pspEmuProxyPspSmnUnassignedWrite, hPspProxyCtx);
                                if (!rc)
                                    rc = PSPEmuIoMgrX86UnassignedSet(hIoMgr, pspEmuProxyX86UnassignedRead, pspEmuProxyX86UnassignedWrite, hPspProxyCtx);
                            }
                            else
                                fprintf(stderr, "Connecting to the PSP proxy failed with %d\n", rc);
                        }

                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegCcpV5, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegTimer, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegMmioUnk, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegSmnUnk, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegX86Unk, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegFuse, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegFlash, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegSmu, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegMp2, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegSts, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegTest, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegX86Uart, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegAcpi, &Cfg, &pDev);
                        if (!rc)
                            rc = PSPEmuDevCreate(hIoMgr, &g_DevRegX86Mem, &Cfg, &pDev);
                        if (rc)
                            printf("Error creating one of the devices: %d\n", rc);

                        PSPADDR PspAddrStartExec = 0x0;
                        switch (Cfg.enmMode)
                        {
                            case PSPCOREMODE_SYSTEM_ON_CHIP_BL:
                            {
                                //PSPEmuCoreTraceRegister(hCore, 0xffff0000, 0xffffffff, PSPEMU_CORE_TRACE_F_EXEC, pspEmuTraceState, NULL);
                                PspAddrStartExec = 0xffff0000;
                                break;
                            }
                            case PSPCOREMODE_APP:
                            {
                                PspAddrStartExec = 0x15100;
                                rc = PSPEmuSvcStateCreate(&hSvc, hCore, hIoMgr, hPspProxyCtx);
                                break;
                            }
                            case PSPCOREMODE_SYSTEM:
                            {
                                //PSPEmuCoreTraceRegister(hCore, 0x100, 0x20000, PSPEMU_CORE_TRACE_F_EXEC, pspEmuTraceState, NULL);
                                PspAddrStartExec = 0x100;
                                break;
                            }
                            default:
                                fprintf(stderr, "Invalid emulation mode selected %d\n", Cfg.enmMode);
                                rc = -1;
                        }

                        if (   !rc
                            && (   Cfg.fIncptSvc6
                                || Cfg.fTraceSvcs))
                            rc = PSPEmuCoreSvcInjectSet(hCore, &g_Svc6Reg, &Cfg);
                        if (!rc)
                            rc = PSPEmuCoreExecSetStartAddr(hCore, PspAddrStartExec);
                        if (!rc)
                        {
                            PSPTRACE hTrace = NULL;

                            if (Cfg.pszTraceLog)
                            {
                                /* Set up a tracer. */
                                rc = PSPEmuTraceCreateForFile(&hTrace, PSPEMU_TRACE_F_DEFAULT, hCore,
                                                              0, Cfg.pszTraceLog);
                                if (!rc)
                                    rc = PSPEmuTraceSetDefault(hTrace);
                            }

                            if (!rc)
                            {
                                if (Cfg.uDbgPort)
                                {
                                    /*
                                     * Execute one instruction to initialize the unicorn CPU state properly
                                     * so the debugger has valid values to work with.
                                     */
                                    rc = PSPEmuCoreExecRun(hCore, 1, PSPEMU_CORE_EXEC_INDEFINITE);
                                    if (!rc)
                                    {
                                        PSPDBG hDbg = NULL;

                                        rc = PSPEmuDbgCreate(&hDbg, hCore, Cfg.uDbgPort);
                                        if (!rc)
                                        {
                                            printf("Debugger is listening on port %u...\n", Cfg.uDbgPort);
                                            rc = PSPEmuDbgRunloop(hDbg);
                                            if (rc)
                                            {
                                                printf("Debugger runloop failed with %d\n", rc);
                                                PSPEmuCoreStateDump(hCore);
                                            }
                                        }
                                        else
                                            fprintf(stderr, "Failed to create debugger instance with %d\n", rc);
                                    }
                                }
                                else
                                {
                                    rc = PSPEmuCoreExecRun(hCore, 0, PSPEMU_CORE_EXEC_INDEFINITE);
                                    if (rc)
                                    {
                                        fprintf(stderr, "Emulation runloop failed with %d\n", rc);
                                        PSPEmuCoreStateDump(hCore);
                                    }
                                    else
                                        PSPEmuCoreStateDump(hCore);
                                }
                            }
                        }
                        else
                            fprintf(stderr, "Setting the execution start address failed with %d\n", rc);
                    }
                }
            }
            else
                fprintf(stderr, "Creating the emulation core failed with %d\n", rc);
        }
        else
            fprintf(stderr, "Loading the flash ROM failed with %d\n", rc);
    }
    else
        fprintf(stderr, "Parsing arguments failed with %d\n", rc);

    return 0;
}

