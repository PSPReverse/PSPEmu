/** @file
 * PSP Emulator - CCD API.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpspproxy.h>

#include <common/types.h>
#include <common/cdefs.h>
#include <psp-fw/boot-rom-svc-page.h>

#include <psp-ccd.h>
#include <psp-dbg.h>
#include <psp-flash.h>
#include <psp-iom.h>
#include <psp-devs.h>
#include <psp-cfg.h>
#include <psp-svc.h>
#include <psp-trace.h>

/**
 * A single CCD instance.
 */
typedef struct PSPCCDINT
{
    /** The PSP core executing the code. */
    PSPCORE                     hPspCore;
    /** The I/O manager handling I/O accesses. */
    PSPIOM                      hIoMgr;
    /** Emulated supervisor mode state for app emulation mode. */
    PSPSVC                      hSvc;
    /** PSP proxy context handle if configured. */
    PSPPROXYCTX                 hPspProxyCtx;
    /** The debugger handle if configured. */
    PSPDBG                      hDbg;
    /** The trace log handle. */
    PSPTRACE                    hTrace;
    /** The SMN region handle for the ID register. */
    PSPIOMREGIONHANDLE          hSmnRegId;
    /** Head of the instantiated devices. */
    PPSPDEV                     pDevsHead;
    /** The socket ID. */
    uint32_t                    idSocket;
    /** The CCD ID. */
    uint32_t                    idCcd;
} PSPCCDINT;
/** Pointer to a single CCD instance. */
typedef PSPCCDINT *PPSPCCDINT;


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
 * List of known devices.
 */
static PCPSPDEVREG g_apDevs[] =
{
    &g_DevRegCcpV5,
    &g_DevRegTimer,
    &g_DevRegFuse,
    &g_DevRegFlash,
    &g_DevRegSmu,
    &g_DevRegMp2,
    &g_DevRegSts,
    &g_DevRegMmioUnk,
    &g_DevRegAcpi,
    &g_DevRegSmnUnk,
    &g_DevRegX86Unk,
    &g_DevRegX86Uart,
    &g_DevRegX86Mem,

    /* Special device only present for debugging and not existing on real hardware. */
    &g_DevRegTest,
};



static void pspEmuCcdProxyPspMmioUnassignedRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspMmioRead(hPspProxyCtx, offMmio, cbRead, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspMmioUnassignedRead: Failed with %d\n", rc);
}


static void pspEmuCcdProxyPspMmioUnassignedWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspMmioWrite(hPspProxyCtx, offMmio, cbWrite, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspMmioUnassignedWrite: Failed with %d\n", rc);
}


static void pspEmuCcdProxyPspSmnUnassignedRead(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspSmnRead(hPspProxyCtx, 0 /*idCcdTgt*/, offSmn, cbRead, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspSmnUnassignedRead: Failed with %d\n", rc);
}


static void pspEmuCcdProxyPspSmnUnassignedWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspSmnWrite(hPspProxyCtx, 0 /*idCcdTgt*/, offSmn, cbWrite, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspSmnUnassignedWrite: Failed with %d\n", rc);
}


static void pspEmuCcdProxyX86UnassignedRead(X86PADDR offX86Phys, size_t cbRead, void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspX86MmioRead(hPspProxyCtx, offX86Phys, cbRead, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspX86UnassignedRead: Failed with %d\n", rc);
}


static void pspEmuCcdProxyX86UnassignedWrite(X86PADDR offX86Phys, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PSPPROXYCTX hPspProxyCtx = (PSPPROXYCTX)pvUser;

    int rc = PSPProxyCtxPspX86MmioWrite(hPspProxyCtx, offX86Phys, cbWrite, pvVal);
    if (rc)
        fprintf(stderr, "pspEmuProxyPspX86UnassignedWrite: Failed with %d\n", rc);
}


/**
 * CCD ID register read callback.
 */
static void pspEmuCcdIdRead(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPCCDINT pThis = (PPSPCCDINT)pvUser;

    /*
     * This readonly register contains information about the system and environment the accessing
     * code is running on:
     *
     *    [Bits]            [Purpose]
     *     0-1          The physical die ID (CCD)
     *     2-4          Some enumeration it seems, defines maximum values supported by the system (0x4 for EPYC)
     *      5           Socket ID (0 or 1)
     */
    uint32_t u32Val = 0;
    u32Val |= pThis->idCcd & 0x3;
    u32Val |= pThis->idSocket == 0 ? 0 : BIT(5);
    u32Val |= 0x4 << 2; /** @todo Make configurable */

    *(uint32_t *)pvVal = u32Val;
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
 * Returns the device registration record with the given name or NULL if not found.
 *
 * @returns Pointer to the devcice registration record or NULL if not found.
 * @param   pszDevName              The device to look for.
 */
static PCPSPDEVREG pspEmuCcdDeviceFindByName(const char *pszDevName)
{
    for (uint32_t i = 0; i < ELEMENTS(g_apDevs); i++)
    {
        if (!strcmp(g_apDevs[i]->pszName, pszDevName))
            return g_apDevs[i];
    }

    return NULL;
}


/**
 * Instantiate a single given device.
 *
 * @returns status code.
 * @param   pThis                   The CCD instance to instantiate the device for.
 * @param   pDevReg                 The device to instantiate.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdDeviceInstantiate(PPSPCCDINT pThis, PCPSPDEVREG pDevReg, PCPSPEMUCFG pCfg)
{
    PPSPDEV pDev = NULL;
    int rc = PSPEmuDevCreate(pThis->hIoMgr, pDevReg, pCfg, &pDev);
    if (!rc)
    {
        pDev->pNext = pThis->pDevsHead;
        pThis->pDevsHead = pDev;
    }

    return rc;
}


/**
 * Instantiate all the given devices.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to create the devices for.
 * @param   papszDevs               Devices to instantiate.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdDevicesInstantiate(PPSPCCDINT pThis, const char **papszDevs, PCPSPEMUCFG pCfg)
{
    int rc = 0;
    uint32_t idxDev = 0;

    while (   papszDevs[idxDev]
           && !rc)
    {
        PCPSPDEVREG pDevReg = pspEmuCcdDeviceFindByName(papszDevs[idxDev]);
        if (pDevReg)
        {
            rc = pspEmuCcdDeviceInstantiate(pThis, pDevReg, pCfg);
            idxDev++;
        }
        else
            rc = -1;
    }

    if (rc)
    {
        /* Rollback time. */
        PPSPDEV pCur = pThis->pDevsHead;
        while (pCur)
        {
            PPSPDEV pFree = pCur;
            pCur = pCur->pNext;
            PSPEmuDevDestroy(pFree);
        }
    }

    return rc;
}


/**
 * Instantiate the default set of devices.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to create the devices for.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdDevicesInstantiateDefault(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = 0;

    for (uint32_t i = 0; i < ELEMENTS(g_apDevs) && !rc; i++)
        rc = pspEmuCcdDeviceInstantiate(pThis, g_apDevs[i], pCfg);

    /** @todo Rollback */

    return rc;
}


/**
 * Initializes the SRAM memory content of the given CCD PSP.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to initialize the memory of.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdMemoryInit(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = 0;

    if (   pCfg->pvBootRomSvcPage
        && pCfg->cbBootRomSvcPage)
    {
        if (pCfg->cbBootRomSvcPage != _4K)
            return -1;

        PSPADDR PspAddrBrsp = pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 0x4f000 : 0x3f000;
        if (pCfg->fBootRomSvcPageModify)
        {
            PSPROMSVCPG Brsp;

            memcpy(&Brsp, pCfg->pvBootRomSvcPage, sizeof(Brsp));

            if (pCfg->fPspDbgMode)
            {
                printf("Activating PSP firmware debug mode\n");
                Brsp.Fields.u32BootMode = 1;
            }

            if (pCfg->fLoadPspDir)
            {
                printf("Loading PSP 1st level directory from flash image into boot ROM service page\n");
                uint8_t *pbFlashRom = (uint8_t *)pCfg->pvFlashRom;
                memcpy(&Brsp.Fields.abFfsDir[0], &pbFlashRom[0x77000], sizeof(Brsp.Fields.abFfsDir)); /** @todo */
            }

            Brsp.Fields.idPhysDie      = (uint8_t)pThis->idCcd;
            Brsp.Fields.idSocket       = (uint8_t)pThis->idSocket;
            Brsp.Fields.cDiesPerSocket = (uint8_t)pCfg->cCcdsPerSocket;
            /** @todo u8PkgType, core info, cCcxs, cCores, etc. */

            rc = PSPEmuCoreMemWrite(pThis->hPspCore, PspAddrBrsp, &Brsp, sizeof(Brsp));
        }
        else /* No modifcation allowed, just copy it. */
            rc = PSPEmuCoreMemWrite(pThis->hPspCore, PspAddrBrsp, pCfg->pvBootRomSvcPage, pCfg->cbBootRomSvcPage);
    }

    if (   !rc
        && pCfg->pvBinLoad
        && pCfg->cbBinLoad)
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
            case PSPEMUMODE_SYSTEM_ON_CHIP_BL:
            default:
                /** @todo assert() should not happen as the config is already checked. */
                return -1;
        }

        if (!pCfg->fBinContainsHdr)
            PspAddrWrite += 256; /* Skip the header part. */

        rc = PSPEmuCoreMemWrite(pThis->hPspCore, PspAddrWrite, pCfg->pvBinLoad, pCfg->cbBinLoad);
    }

    if (   !rc
        && pCfg->pvAppPreload
        && pCfg->cbAppPreload)
        rc = PSPEmuCoreMemWrite(pThis->hPspCore, 0x15000, pCfg->pvAppPreload, pCfg->cbAppPreload);

    return rc;
}


/**
 * Registers all MMIO/SMN register handlers for the given CCD.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance.
 */
static int pspEmuCcdMmioSmnInit(PPSPCCDINT pThis)
{
    return PSPEmuIoMgrSmnRegister(pThis->hIoMgr, 0x5a870, 4,
                                  pspEmuCcdIdRead, NULL, pThis,
                                  &pThis->hSmnRegId);
}


/**
 * Initializes the PSP proxy for the CCD if configured.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdProxyInit(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = 0;

    if (pCfg->pszPspProxyAddr)
    {
        printf("PSP proxy: Connecting to %s\n", pCfg->pszPspProxyAddr);
        rc = PSPProxyCtxCreate(&pThis->hPspProxyCtx, pCfg->pszPspProxyAddr);
        if (!rc)
        {
            printf("PSP proxy: Connected to %s\n", pCfg->pszPspProxyAddr);

            /* Register the unassigned handlers for the various regions. */
            rc = PSPEmuIoMgrMmioUnassignedSet(pThis->hIoMgr, pspEmuCcdProxyPspMmioUnassignedRead, pspEmuCcdProxyPspMmioUnassignedWrite, pThis->hPspProxyCtx);
            if (!rc)
                rc = PSPEmuIoMgrSmnUnassignedSet(pThis->hIoMgr, pspEmuCcdProxyPspSmnUnassignedRead, pspEmuCcdProxyPspSmnUnassignedWrite, pThis->hPspProxyCtx);
            if (!rc)
                rc = PSPEmuIoMgrX86UnassignedSet(pThis->hIoMgr, pspEmuCcdProxyX86UnassignedRead, pspEmuCcdProxyX86UnassignedWrite, pThis->hPspProxyCtx);
        }
        else
            fprintf(stderr, "Connecting to the PSP proxy failed with %d\n", rc);
    }

    return rc;
}


/**
 * Initializes the execution environment for the CCD.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to initialize the memory of.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdExecEnvInit(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = 0;
    PSPADDR PspAddrStartExec = 0x0;
    switch (pCfg->enmMode)
    {
        case PSPEMUMODE_SYSTEM_ON_CHIP_BL:
        {
            PspAddrStartExec = 0xffff0000;
            break;
        }
        case PSPEMUMODE_APP:
        {
            PspAddrStartExec = 0x15100;
            rc = PSPEmuSvcStateCreate(&pThis->hSvc, pThis->hPspCore, pThis->hIoMgr, pThis->hPspProxyCtx);
            break;
        }
        case PSPEMUMODE_SYSTEM:
        {
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
        rc = PSPEmuCoreSvcInjectSet(pThis->hPspCore, &g_Svc6Reg, (void *)pCfg);
    if (!rc)
        rc = PSPEmuCoreExecSetStartAddr(pThis->hPspCore, PspAddrStartExec);

    return rc;
}


/**
 * Initializes the tracing if configured.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to initialize the debugger for.
 * @param   pCfg                    The global config.
 *
 * @todo Tracing for multiple CCDs is not working right now.
 */
static int pspEmuCcdTraceInit(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = PSPEmuTraceCreateForFile(&pThis->hTrace, PSPEMU_TRACE_F_DEFAULT, pThis->hPspCore,
                                      0, pCfg->pszTraceLog);
    if (!rc)
        rc = PSPEmuTraceSetDefault(pThis->hTrace);

    return rc;
}


/**
 * Initializes the debugger if configured.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to initialize the debugger for.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdDbgInit(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    /*
     * Execute one instruction to initialize the unicorn CPU state properly
     * so the debugger has valid values to work with.
     */
    int rc = PSPEmuCoreExecRun(pThis->hPspCore, 1, PSPEMU_CORE_EXEC_INDEFINITE);
    if (!rc)
    {
        uint32_t uDbgPort = pCfg->uDbgPort + pThis->idCcd;

        rc = PSPEmuDbgCreate(&pThis->hDbg, pThis->hPspCore, uDbgPort);
        if (!rc)
            printf("Debugger for [socket:%u]:[id:%u] is listening on port %u...\n",
                   pThis->idSocket, pThis->idCcd, uDbgPort);
    }

    return rc;
}


/**
 * @todo:
 *  - PSP proxy passthrough.
 */
int PSPEmuCcdCreate(PPSPCCD phCcd, uint32_t idSocket, uint32_t idCcd, PCPSPEMUCFG pCfg)
{
    int rc = 0;
    PPSPCCDINT pThis = (PPSPCCDINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->idSocket = idSocket;
        pThis->idCcd    = idCcd;

        rc = PSPEmuCoreCreate(&pThis->hPspCore, pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 320 * _1K : _256K);
        if (!rc)
        {
            rc = PSPEmuIoMgrCreate(&pThis->hIoMgr, pThis->hPspCore);
            if (!rc)
            {
                /* Set the on chip bootloader if configured. */
                if (pCfg->enmMode == PSPEMUMODE_SYSTEM_ON_CHIP_BL)
                    rc = PSPEmuCoreSetOnChipBl(pThis->hPspCore, pCfg->pvOnChipBl, pCfg->cbOnChipBl);

                if (!rc)
                {
                    /* Create all the devices. */
                    if (pCfg->papszDevs)
                        rc = pspEmuCcdDevicesInstantiate(pThis, pCfg->papszDevs, pCfg);
                    else
                        rc = pspEmuCcdDevicesInstantiateDefault(pThis, pCfg);
                    if (!rc)
                    {
                        /* Initialize the memory content for the PSP. */
                        rc = pspEmuCcdMemoryInit(pThis, pCfg);
                        if (!rc)
                            rc = pspEmuCcdMmioSmnInit(pThis);
                        if (!rc)
                            rc = pspEmuCcdProxyInit(pThis, pCfg);
                        if (!rc)
                            rc = pspEmuCcdExecEnvInit(pThis, pCfg);
                        if (!rc)
                            rc = pspEmuCcdTraceInit(pThis, pCfg);
                        if (   !rc
                            && pCfg->uDbgPort)
                            rc = pspEmuCcdDbgInit(pThis, pCfg);
                        if (!rc)
                        {
                            *phCcd = pThis;
                            return 0;
                        }
                    }

                }

                PSPEmuIoMgrDestroy(pThis->hIoMgr);
            }

            PSPEmuCoreDestroy(pThis->hPspCore);
        }

        free(pThis);
    }
    else
        rc = -1;

    return rc;
}


void PSPEmuCcdDestroy(PSPCCD hCcd)
{
    PPSPCCDINT pThis = hCcd;

    if (pThis->hDbg)
    {
        PSPEmuDbgDestroy(pThis->hDbg);
        pThis->hDbg = NULL;
    }

    if (pThis->hTrace)
    {
        PSPEmuTraceDestroy(pThis->hTrace);
        pThis->hTrace = NULL;
    }

    if (pThis->hSvc)
    {
        PSPEmuSvcStateDestroy(pThis->hSvc);
        pThis->hSvc = NULL;
    }

    if (pThis->hPspProxyCtx)
    {
        PSPProxyCtxDestroy(pThis->hPspProxyCtx);
        pThis->hPspProxyCtx = NULL;
    }

    /* Destroy all devices. */
    PPSPDEV pCur = pThis->pDevsHead;
    while (pCur)
    {
        PPSPDEV pFree = pCur;
        pCur = pCur->pNext;
        PSPEmuDevDestroy(pFree);
    }

    /* Destroy the I/O manager and then the emulation core and last this structure. */
    PSPEmuIoMgrDestroy(pThis->hIoMgr);
    PSPEmuCoreDestroy(pThis->hPspCore);
    free(pThis);
}


int PSPEmuCcdQueryCore(PSPCCD hCcd, PPSPCORE phPspCore)
{
    PPSPCCDINT pThis = hCcd;

    *phPspCore = pThis->hPspCore;
    return 0;
}


int PSPEmuCcdRun(PSPCCD hCcd)
{
    int rc = 0;
    PPSPCCDINT pThis = hCcd;

    if (pThis->hDbg)
        rc = PSPEmuDbgRunloop(pThis->hDbg);
    else
        rc = PSPEmuCoreExecRun(pThis->hPspCore, 0, PSPEMU_CORE_EXEC_INDEFINITE);

    PSPEmuCoreStateDump(pThis->hPspCore);
    return rc;
}

