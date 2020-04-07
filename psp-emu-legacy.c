/** @file
 * PSP Emulator - Legacy entry point.
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


int pspEmuMainLegacy(PPSPEMUCFG pCfg)
{
    void *pv = NULL;
    size_t cb = 0;

    int rc = PSPEmuFlashLoadFromFile(pCfg->pszPathFlashRom, &pv, &cb);
    if (!rc)
    {
        PSPCORE hCore;

        pCfg->pvFlashRom = pv;
        pCfg->cbFlashRom = cb;

        rc = PSPEmuCoreCreate(&hCore, pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 320 * _1K : _256K);
        if (!rc)
        {
            PSPIOM hIoMgr;

            rc = PSPEmuIoMgrCreate(&hIoMgr, hCore);
            if (!rc)
            {
                if (pCfg->pszPathOnChipBl)
                {
                    void *pvOnChipBl = NULL;
                    size_t cbOnChipBl = 0;

                    rc = PSPEmuFlashLoadFromFile(pCfg->pszPathOnChipBl, &pvOnChipBl, &cbOnChipBl);
                    if (!rc)
                    {
                        rc = PSPEmuCoreSetOnChipBl(hCore, pvOnChipBl, cbOnChipBl);
                        if (rc)
                            fprintf(stderr, "Setting the on chip bootloader ROM for the PSP core failed with %d\n", rc);
                    }
                    else
                        fprintf(stderr, "Loading the on chip bootloader ROM failed with %d\n", rc);
                }

                if (pCfg->pszPathBootRomSvcPage)
                {
                    PPSPROMSVCPG pBootRomSvcPage = NULL;
                    size_t cbBootRomSvcPage = 0;

                    rc = PSPEmuFlashLoadFromFile(pCfg->pszPathBootRomSvcPage, (void **)&pBootRomSvcPage, &cbBootRomSvcPage);
                    if (!rc)
                    {
                        if (pCfg->fPspDbgMode)
                        {
                            printf("Activating PSP firmware debug mode\n");
                            pBootRomSvcPage->Fields.u32BootMode = 1;
                        }

                        if (pCfg->fLoadPspDir)
                        {
                            printf("Loading PSP 1st level directory from flash image into boot ROM service page\n");
                            uint8_t *pbFlashRom = (uint8_t *)pCfg->pvFlashRom;
                            memcpy(&pBootRomSvcPage->Fields.abFfsDir[0], &pbFlashRom[0x77000], sizeof(pBootRomSvcPage->Fields.abFfsDir)); /** @todo */
                        }

                        PSPADDR PspAddrBsp = pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 0x4f000 : 0x3f000;
                        rc = PSPEmuCoreMemWrite(hCore, PspAddrBsp, pBootRomSvcPage, cbBootRomSvcPage);
                        if (rc)
                            fprintf(stderr, "Initializing the boot ROM service page from the given file failed with %d\n", rc);
                    }
                    else
                        fprintf(stderr, "Loading the boot ROM service page from the given file failed with %d\n", rc);
                }
                /** @todo else: Set one up based on the system information given in the arguments. */

                if (pCfg->pszPathBinLoad)
                {
                    void *pvBin = NULL;
                    size_t cbBin = 0;

                    rc = PSPEmuFlashLoadFromFile(pCfg->pszPathBinLoad, &pvBin, &cbBin);
                    if (!rc)
                    {
                        PSPADDR PspAddrWrite = 0;

                        switch (pCfg->enmMode)
                        {
                            case PSPEMUMODE_SYSTEM:
                                PspAddrWrite = 0x0;
                                break;
                            case PSPEMUMODE_APP:
                                PspAddrWrite = 0x15000;
                                break;
                            default:
                                fprintf(stderr, "Invalid emulation mode selected for the loaded binary\n");
                                return -1;
                        }

                        if (!pCfg->fBinContainsHdr)
                            PspAddrWrite += 256; /* Skip the header part. */

                        rc = PSPEmuCoreMemWrite(hCore, PspAddrWrite, pvBin, cbBin);
                        if (rc)
                            fprintf(stderr, "Writing the binary to PSP memory failed with %d\n", rc);

                        PSPEmuFlashFree(pvBin, cbBin);
                    }
                    else
                        fprintf(stderr, "Loading the binary failed with %d\n", rc);
                }

                if (pCfg->pszAppPreload)
                {
                    void *pvBin = NULL;
                    size_t cbBin = 0;

                    rc = PSPEmuFlashLoadFromFile(pCfg->pszAppPreload, &pvBin, &cbBin);
                    if (!rc)
                    {
                        rc = PSPEmuCoreMemWrite(hCore, 0x15000, pvBin, cbBin);
                        if (rc)
                            fprintf(stderr, "Writing the app binary to PSP memory failed with %d\n", rc);

                        PSPEmuFlashFree(pvBin, cbBin);
                    }
                    else
                        fprintf(stderr, "Loading the app binary failed with %d\n", rc);
                }

                if (!rc)
                {
                    /** @todo Proper initialization,instantiation of attached devices. */
                    PPSPDEV pDev = NULL;
                    PSPSVC hSvc = NULL;
                    PSPPROXYCTX hPspProxyCtx = NULL;

                    if (pCfg->pszPspProxyAddr)
                    {
                        printf("PSP proxy: Connecting to %s\n", pCfg->pszPspProxyAddr);
                        rc = PSPProxyCtxCreate(&hPspProxyCtx, pCfg->pszPspProxyAddr);
                        if (!rc)
                        {
                            printf("PSP proxy: Connected to %s\n", pCfg->pszPspProxyAddr);

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
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegCcpV5, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegTimer, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegMmioUnk, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegSmnUnk, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegX86Unk, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegFuse, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegFlash, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegSmu, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegMp2, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegSts, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegTest, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegX86Uart, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegAcpi, pCfg, &pDev);
                    if (!rc)
                        rc = PSPEmuDevCreate(hIoMgr, &g_DevRegX86Mem, pCfg, &pDev);
                    if (rc)
                        printf("Error creating one of the devices: %d\n", rc);

                    PSPADDR PspAddrStartExec = 0x0;
                    switch (pCfg->enmMode)
                    {
                        case PSPEMUMODE_SYSTEM_ON_CHIP_BL:
                        {
                            //PSPEmuCoreTraceRegister(hCore, 0xffff0000, 0xffffffff, PSPEMU_CORE_TRACE_F_EXEC, pspEmuTraceState, NULL);
                            PspAddrStartExec = 0xffff0000;
                            break;
                        }
                        case PSPEMUMODE_APP:
                        {
                            PspAddrStartExec = 0x15100;
                            rc = PSPEmuSvcStateCreate(&hSvc, hCore, hIoMgr, hPspProxyCtx);
                            break;
                        }
                        case PSPEMUMODE_SYSTEM:
                        {
                            //PSPEmuCoreTraceRegister(hCore, 0x100, 0x20000, PSPEMU_CORE_TRACE_F_EXEC, pspEmuTraceState, NULL);
                            PspAddrStartExec = 0x100;
                            break;
                        }
                        default:
                            fprintf(stderr, "Invalid emulation mode selected %d\n", pCfg->enmMode);
                            rc = -1;
                    }

                    if (   !rc
                        && (   pCfg->fIncptSvc6
                            || pCfg->fTraceSvcs))
                        rc = PSPEmuCoreSvcInjectSet(hCore, &g_Svc6Reg, pCfg);
                    if (!rc)
                        rc = PSPEmuCoreExecSetStartAddr(hCore, PspAddrStartExec);
                    if (!rc)
                    {
                        PSPTRACE hTrace = NULL;

                        if (pCfg->pszTraceLog)
                        {
                            /* Set up a tracer. */
                            rc = PSPEmuTraceCreateForFile(&hTrace, PSPEMU_TRACE_F_DEFAULT, hCore,
                                                          0, pCfg->pszTraceLog);
                            if (!rc)
                                rc = PSPEmuTraceSetDefault(hTrace);
                        }

                        if (!rc)
                        {
                            if (pCfg->uDbgPort)
                            {
                                /*
                                 * Execute one instruction to initialize the unicorn CPU state properly
                                 * so the debugger has valid values to work with.
                                 */
                                rc = PSPEmuCoreExecRun(hCore, 1, PSPEMU_CORE_EXEC_INDEFINITE);
                                if (!rc)
                                {
                                    PSPDBG hDbg = NULL;

                                    rc = PSPEmuDbgCreate(&hDbg, hCore, pCfg->uDbgPort);
                                    if (!rc)
                                    {
                                        printf("Debugger is listening on port %u...\n", pCfg->uDbgPort);
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

    return 0;
}

