/** @file
 * PSP Emulator - Entry point.
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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <libpspproxy.h>

#include <common/cdefs.h>
#include <common/status.h>
#include <psp-fw/boot-rom-svc-page.h>

#include <psp-ccd.h>
#include <psp-cfg.h>
#include <psp-dbg.h>
#include <psp-proxy.h>
#include <psp-iolog-replay.h>


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
        int rc = PSPEmuCoreExecRun(hPspCore, PSPEMU_CORE_EXEC_F_DEFAULT, 1, PSPEMU_CORE_EXEC_INDEFINITE);
        if (!rc)
        {
            PSPDBG hDbg = NULL;

            rc = PSPEmuDbgCreate(&hDbg, pCfg->uDbgPort, pCfg->cDbgInsnStep, pCfg->PspAddrDbgRunUpTo,
                                 &hCcd, 1, pCfg->hDbgHlp);
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

    PSPCfgInit(&Cfg);

    /* Parse the config first. */
    int rc = PSPCfgParse(&Cfg, argc, (const char * const *)&argv[0]);
    if (STS_SUCCESS(rc))
    {
        /* Create a debug helper module if the debugger is going to be used. */
        if (Cfg.uDbgPort)
            rc = PSPEmuDbgHlpCreate(&Cfg.hDbgHlp);

        if (STS_SUCCESS(rc))
        {
            PSPCCD hCcd = NULL;
            if (   Cfg.idSocketSingle != UINT32_MAX
                && Cfg.idCcdSingle != UINT32_MAX)
                rc = PSPEmuCcdCreate(&hCcd, Cfg.idSocketSingle, Cfg.idCcdSingle, &Cfg);
            else
                rc = PSPEmuCcdCreate(&hCcd, 0, 0, &Cfg);

            if (!rc)
            {
                PSPPROXY hProxy = NULL;
                PSPIOLOGREPLAY hIoLogReplay = NULL;

                /* Setup the proxy if configured. */
                if (Cfg.pszPspProxyAddr)
                {
                    rc = PSPProxyCreate(&hProxy, &Cfg);
                    if (!rc)
                        rc = PSPProxyCcdRegister(hProxy, hCcd);
                }
                else if (Cfg.pszIoLogReplay)
                {
                    rc = PSPIoLogReplayCreate(&hIoLogReplay, Cfg.pszIoLogReplay);
                    if (STS_SUCCESS(rc))
                        rc = PSPIoLogReplayCcdRegister(hIoLogReplay, hCcd);
                }

                if (!rc)
                {
                    if (Cfg.uDbgPort)
                        rc = pspEmuDbgRun(hCcd, &Cfg);
                    else
                        rc = PSPEmuCcdRun(hCcd);
                }

                if (hProxy)
                {
                    PSPProxyCcdDeregister(hProxy, hCcd);
                    PSPProxyDestroy(hProxy);
                }

                if (hIoLogReplay)
                {
                    PSPIoLogReplayCcdDeregister(hIoLogReplay, hCcd);
                    PSPIoLogReplayDestroy(hIoLogReplay);
                }

                PSPEmuCcdDestroy(hCcd);
            }
        }

        PSPCfgFree(&Cfg);
    }
    else
        fprintf(stderr, "Parsing arguments failed with %d\n", rc);

    return 0;
}

