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

#include <common/cdefs.h>

#include <psp-core.h>
#include <psp-dbg.h>
#include <psp-flash.h>
#include <psp-smn-dev.h>
#include <psp-devs.h>


/**
 * PSP emulator config.
 */
typedef struct PSPEMUCFG
{
    /** Emulation mode. */
    PSPCOREMODE             enmMode;
    /** The flash ROM path. */
    const char              *pszPathFlashRom;
    /** Path to the on chip bootloader if in appropriate mode. */
    const char              *pszPathOnChipBl;
    /** Binary to load, if NULL we get one from the flash image depending on the mode. */
    const char              *pszPathBinLoad;
    /** Flag whether overwritten binaries have the 256 byte header prepended (affects the load address). */
    bool                    fBinContainsHdr;
    /** Debugger port to listen on, 0 means debugger is disabled. */
    uint16_t                uDbgPort;
} PSPEMUCFG;
/** Pointer to a PSPEmu config. */
typedef PSPEMUCFG *PPSPEMUCFG;
/** Pointer to a const PSPEmu config. */
typedef const PSPEMUCFG *PCPSPEMUCFG;


/**
 * Available options for PSPEmu.
 */
static struct option g_aOptions[] =
{
    {"emulation-mode",       required_argument, 0, 'm'},
    {"flash-rom",            required_argument, 0, 'f'},
    {"on-chip-bl",           required_argument, 0, 'o'},
    {"on-chip-bl",           required_argument, 0, 'p'},
    {"bin-load",             required_argument, 0, 'b'},
    {"bin-contains-hdr",     no_argument,       0, 'p'},
    {"dbg",                  required_argument, 0, 'd'},

    {"help",                 no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


static void pspEmuTraceState(PSPCORE hCore, PSPADDR uPspAddr, uint32_t cbInsn, void *pvUser)
{
    printf(">>> Tracing instruction at %#x, instruction size = 0x%x\n", uPspAddr, cbInsn);
    PSPEmuCoreStateDump(hCore);
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

    pCfg->enmMode         = PSPCOREMODE_INVALID;
    pCfg->pszPathFlashRom = NULL;
    pCfg->pszPathOnChipBl = NULL;
    pCfg->pszPathBinLoad  = NULL;
    pCfg->fBinContainsHdr = false;
    pCfg->uDbgPort        = 0;

    while ((ch = getopt_long (argc, argv, "hpb:m:f:o:d:", &g_aOptions[0], &idxOption)) != -1)
    {
        switch (ch)
        {
            case 'h':
            case 'H':
                printf("%s: AMD Platform Secure Processor emulator\n"
                       "    --emulation-mode [app|sys|on-chip-bl]\n"
                       "    --flash-rom <path/to/flash/rom>\n"
                       "    --bin-contains-hdr The binaries contain the 256 byte header, omit if raw binaries\n"
                       "    --bin-load <path/to/binary/to/load>\n"
                       "    --on-chip-bl <path/to/on-chip-bl/binary>\n"
                       "    --dbg <listening port>\n",
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
            rc = PSPEmuCoreCreate(&hCore, Cfg.enmMode);
            if (!rc)
            {
                PSPMMIOM hMmioMgr;

                rc = PSPEmuMmioMgrCreate(&hMmioMgr, hCore);
                if (!rc)
                {
                    PSPSMNM hSmnMgr;
                    rc = PSPEmuSmnMgrCreate(&hSmnMgr, hMmioMgr);
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
                            PPSPMMIODEV pDev = NULL;
                            PPSPSMNDEV pSmnDev = NULL;

                            PSPEmuMmioDevCreate(hMmioMgr, &g_MmioDevRegCcpV5, 0x03000000, &pDev);
                            PSPEmuMmioDevCreate(hMmioMgr, &g_MmioDevRegUnk0x03010000, 0x03010000, &pDev);
                            PSPEmuSmnDevCreate(hSmnMgr, &g_SmnDevRegUnk0x0005e000, 0x0005e000, &pSmnDev);

                            PSPADDR PspAddrStartExec = 0x0;
                            switch (Cfg.enmMode)
                            {
                                case PSPCOREMODE_SYSTEM_ON_CHIP_BL:
                                {
                                    //PSPEmuCoreTraceRegister(hCore, 0xffff0000, 0xffffffff, pspEmuTraceState, NULL);
                                    PspAddrStartExec = 0xffff0000;
                                    break;
                                }
                                case PSPCOREMODE_APP:
                                {
                                    PspAddrStartExec = 0x15100;
                                    break;
                                }
                                case PSPCOREMODE_SYSTEM:
                                {
                                    //PSPEmuCoreTraceRegister(hCore, 0x100, 0x1000, pspEmuTraceState, NULL);
                                    PspAddrStartExec = 0x100;
                                    break;
                                }
                                default:
                                    fprintf(stderr, "Invalid emulation mode selected %d\n", Cfg.enmMode);
                                    rc = -1;
                            }

                            rc = PSPEmuCoreExecSetStartAddr(hCore, PspAddrStartExec);
                            if (!rc)
                            {
                                if (Cfg.uDbgPort)
                                {
                                    /*
                                     * Execute one instruction to initialize the unicorn CPU state properly
                                     * so the debugger has valid values to work with.
                                     */
                                    rc = PSPEmuCoreExecRun(hCore, 1, 0);
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
                                    rc = PSPEmuCoreExecRun(hCore, 0, 0);
                                    if (rc)
                                    {
                                        fprintf(stderr, "Emulation runloop failed with %d\n", rc);
                                        PSPEmuCoreStateDump(hCore);
                                    }
                                }
                            }
                            else
                                fprintf(stderr, "Setting the execution start address failed with %d\n", rc);
                        }
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

