/** @file
 * PSP Emulator - CCD API.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/types.h>
#include <common/cdefs.h>
#include <common/status.h>
#include <psp-fw/boot-rom-svc-page.h>

#include <psp-ccd.h>
#include <psp-flash.h>
#include <psp-iom.h>
#include <psp-irq.h>
#include <psp-devs.h>
#include <psp-cfg.h>
#include <psp-svc.h>
#include <psp-trace.h>
#include <psp-cov.h>
#include <psp-iolog.h>


/**
 * Memory region descriptor added on demand.
 */
typedef struct PSPCCDMEMREGION
{
    /** Pointer to the next memory region. */
    struct PSPCCDMEMREGION      *pNext;
    /** Address space. */
    PSPADDRSPACE                enmAddrSpace;
    /** The I/O manager handle. */
    PSPIOMREGIONHANDLE          hIoMgrRegion;
} PSPCCDMEMREGION;
/** Pointer to a memory region descriptor. */
typedef PSPCCDMEMREGION *PPSPCCDMEMREGION;


/**
 * A single CCD instance.
 */
typedef struct PSPCCDINT
{
    /** The device interface to use for instantiated devices. */
    PSPDEVIF                    DevIf;
    /** The config assigned to this CCD. */
    PCPSPEMUCFG                 pCfg;
    /** The PSP core executing the code. */
    PSPCORE                     hPspCore;
    /** The I/O manager handling I/O accesses. */
    PSPIOM                      hIoMgr;
    /** The interrupt controller state. */
    PSPIRQ                      hIrq;
    /** Emulated supervisor mode state for app emulation mode. */
    PSPSVC                      hSvc;
    /** The trace log handle. */
    PSPTRACE                    hTrace;
    /** The I/O log handle. */
    PSPIOLOGWR                  hIoLogWr;
    /** MMIO I/O tracepoint handle. */
    PSPIOMTP                    hIoTpIoLogMmio;
    /** SMN I/O tracepoint handle. */
    PSPIOMTP                    hIoTpIoLogSmn;
    /** X86 I/O tracepoint handle. */
    PSPIOMTP                    hIoTpIoLogX86;
    /** The coverage trace handle. */
    PSPCOV                      hCov;
    /** The SMN region handle for the ID register. */
    PSPIOMREGIONHANDLE          hSmnRegId;
    /** Head of the instantiated devices. */
    PPSPDEV                     pDevsHead;
    /** Head of on demand created memory regions. */
    PPSPCCDMEMREGION            pMemRegionsTmpHead;
    /** The socket ID. */
    uint32_t                    idSocket;
    /** The CCD ID. */
    uint32_t                    idCcd;
    /** Flag whether to register the SMN handlers. */
    bool                        fRegSmnHandlers;
    /** SRAM for the PSP CCD. */
    void                        *pvSram;
    /** Size of the SRAM in bytes. */
    size_t                      cbSram;
} PSPCCDINT;
/** Pointer to a single CCD instance. */
typedef PSPCCDINT *PPSPCCDINT;


static bool pspEmuSvcTrace(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);
static bool pspEmuSvcDbgLog(PSPCORE hCore, uint32_t idxSyscall, uint32_t fFlags, void *pvUser);

static bool pspEmuSmcTrace(PSPCORE hCore, uint32_t idxCall, uint32_t fFlags, void *pvUser);

#define PSPEMU_CORE_SVMC_INIT_NULL                   { NULL, NULL, 0 }
#define PSPEMU_CORE_SVMC_INIT_DEF(a_Name, a_Handler) { a_Name, a_Handler, PSPEMU_CORE_SVMC_F_BEFORE }

/**
 * The SVC descriptors table.
 */
static PSPCORESVMCDESC g_aSvcDescs[] =
{
    PSPEMU_CORE_SVMC_INIT_NULL,
    PSPEMU_CORE_SVMC_INIT_NULL,
    PSPEMU_CORE_SVMC_INIT_NULL,
    PSPEMU_CORE_SVMC_INIT_NULL,
    PSPEMU_CORE_SVMC_INIT_NULL,
    PSPEMU_CORE_SVMC_INIT_NULL,
    PSPEMU_CORE_SVMC_INIT_DEF("SvcDbgLog", pspEmuSvcDbgLog),
};


/**
 * SVC injection registration record.
 */
static const PSPCORESVMCREG g_Svc6Reg =
{
    /** GlobalSvmc */
    {
        /** pszName */
        "Trace",
        /** pfnSvmcHnd */
        pspEmuSvcTrace,
        /** fFlags */
        PSPEMU_CORE_SVMC_F_BEFORE | PSPEMU_CORE_SVMC_F_AFTER
    },
    /** cSvmcDescs */
    ELEMENTS(g_aSvcDescs),
    /** paSvmcDescs */
    &g_aSvcDescs[0]
};


/**
 * SMC injection registration record.
 */
static const PSPCORESVMCREG g_SmcReg =
{
    /** GlobalSvmc */
    {
        /** pszName */
        "Trace",
        /** pfnSvmcHnd */
        pspEmuSmcTrace,
        /** fFlags */
        PSPEMU_CORE_SVMC_F_BEFORE | PSPEMU_CORE_SVMC_F_AFTER
    },
    /** cSvmcDescs */
    0,
    /** paSvmcDescs */
    NULL
};


/**
 * Device registration structure.
 *
 * @note This is special as it doesn't is a proper devices
 *       but just acts as marker so we can skip handler registration
 *       if not given in the emulated device list (think of proxy mode).
 */
const PSPDEVREG g_DevRegCcd =
{
    /** pszName */
    "ccd",
    /** pszDesc */
    "CCD related handlers",
    /** cbInstance */
    0,
    /** pfnInit */
    NULL,
    /** pfnDestruct */
    NULL,
    /** pfnReset */
    NULL
};


/**
 * List of known devices.
 */
static PCPSPDEVREG g_apDevs[] =
{
    &g_DevRegCcpV5,
    &g_DevRegTimer1,
    &g_DevRegTimer2,
    &g_DevRegFuse,
    &g_DevRegFlash,
    &g_DevRegSmu,
    &g_DevRegMp2,
    &g_DevRegSts,
    &g_DevRegMmioUnk,
    &g_DevRegAcpi,
    &g_DevRegGpio,
    &g_DevRegIoMux,
    &g_DevRegRtc,
    &g_DevRegLpc,
    &g_DevRegSmnUnk,
    &g_DevRegX86Unk,
    &g_DevRegX86Uart,
    &g_DevRegX86Mem,

    /* Special CCD device. */
    &g_DevRegCcd,

    /* Special device only present for debugging and not existing on real hardware. */
    &g_DevRegTest,
};


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
                               (fFlags & PSPEMU_CORE_SVMC_F_BEFORE)
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
        PSPEmuCoreMemReadVirt(hCore, PspAddrStr, &achStr[0], 512);
        achStr[512 - 1] = '\0'; /* Ensure termination. */
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_SVC, &achStr[0]);

        printf("%s\n", &achStr[0]);
    }

    return true;
}


/**
 * SMC tracer callback.
 */
static bool pspEmuSmcTrace(PSPCORE hCore, uint32_t idxCall, uint32_t fFlags, void *pvUser)
{
    PPSPEMUCFG pCfg = (PPSPEMUCFG)pvUser;

    if (pCfg->fTraceSvcs)
        PSPEmuTraceEvtAddSmc(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_SMC, idxCall,
                               (fFlags & PSPEMU_CORE_SVMC_F_BEFORE)
                             ? true
                             : false /* fEntry*/,
                             NULL /*pszMsg*/);
    return false;
}


/**
 * MMIO tracepoint callback for writing to the I/O log.
 */
static void pspEmuCcdIoLogMmioTrace(PSPADDR offMmioAbs, const char *pszDevId, PSPADDR offMmioDev, size_t cbAccess,
                                    const void *pvVal, uint32_t fFlags, void *pvUser)
{
    (void)pszDevId;
    (void)offMmioDev;

    PPSPCCDINT pThis = (PPSPCCDINT)pvUser;
    PSPADDR PspAddrPc;
    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_PC, &PspAddrPc);
    if (STS_SUCCESS(rc))
    {
        rc = PSPEmuIoLogWrMmioAccAdd(pThis->hIoLogWr, pThis->idCcd, PspAddrPc, offMmioAbs,
                                     (fFlags & PSPEMU_IOM_TRACE_F_WRITE) ? true : false,
                                     cbAccess, pvVal);
        if (STS_FAILURE(rc))
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_MMIO, "PSPEmuIoLogWrMmioAccAdd() -> %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_MMIO, "PSPEmuCoreQueryReg() -> %d\n", rc);
}


/**
 * SMN tracepoint callback for writing to the I/O log.
 */
static void pspEmuCcdIoLogSmnTrace(SMNADDR offSmnAbs, const char *pszDevId, SMNADDR offSmnDev, size_t cbAccess,
                                   const void *pvVal, uint32_t fFlags, void *pvUser)
{
    (void)pszDevId;
    (void)offSmnDev;

    PPSPCCDINT pThis = (PPSPCCDINT)pvUser;
    PSPADDR PspAddrPc;
    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_PC, &PspAddrPc);
    if (STS_SUCCESS(rc))
    {
        rc = PSPEmuIoLogWrSmnAccAdd(pThis->hIoLogWr, pThis->idCcd, PspAddrPc, offSmnAbs,
                                    (fFlags & PSPEMU_IOM_TRACE_F_WRITE) ? true : false,
                                    cbAccess, pvVal);
        if (STS_FAILURE(rc))
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_SMN, "PSPEmuIoLogWrSmnAccAdd() -> %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_MMIO, "PSPEmuCoreQueryReg() -> %d\n", rc);
}


/**
 * X86 tracepoint callback for writing to the I/O log.
 */
static void pspEmuCcdIoLogX86Trace(X86PADDR offX86Abs, const char *pszDevId, X86PADDR offX86Dev, size_t cbAccess,
                                const void *pvVal, uint32_t fFlags, void *pvUser)
{
    (void)pszDevId;
    (void)offX86Dev;

    PPSPCCDINT pThis = (PPSPCCDINT)pvUser;
    PSPADDR PspAddrPc;
    int rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_PC, &PspAddrPc);
    if (STS_SUCCESS(rc))
    {
        rc = PSPEmuIoLogWrX86AccAdd(pThis->hIoLogWr, pThis->idCcd, PspAddrPc, offX86Abs,
                                    (fFlags & PSPEMU_IOM_TRACE_F_WRITE) ? true : false,
                                    cbAccess, pvVal);
        if (STS_FAILURE(rc))
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86, "PSPEmuIoLogWrX86AccAdd() -> %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_MMIO, "PSPEmuCoreQueryReg() -> %d\n", rc);
}


/**
 * @copydoc{PSPDEVIF::pfnIrqSet, Device IRQ callback handler}
 */
static int pspCcdIrqSet(PCPSPDEVIF pDevIf, uint32_t idPrio, uint8_t idIrq, bool fAssert)
{
    PPSPCCDINT pThis = (PPSPCCDINT)pDevIf;

    if (pThis->hIrq)
        return PSPIrqSet(pThis->hIrq, idPrio, idIrq, fAssert);

    return STS_INF_SUCCESS;
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
    int rc = 0;

    if (pDevReg == &g_DevRegCcd)
        pThis->fRegSmnHandlers = true;
    else
    {
        PPSPDEV pDev = NULL;
        rc = PSPEmuDevCreate(pThis->hIoMgr, pDevReg, &pThis->DevIf, pCfg, &pDev);
        if (!rc)
        {
            pDev->pNext = pThis->pDevsHead;
            pThis->pDevsHead = pDev;
        }
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
 * Reset all device states.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to reset all devices for.
 */
static int pspEmuCcdDevicesReset(PPSPCCDINT pThis)
{
    int rc = 0;

    PPSPDEV pDev = pThis->pDevsHead;
    while (   pDev
           && !rc)
    {
        if (pDev->pReg->pfnReset)
            rc = pDev->pReg->pfnReset(pDev);
        pDev = pDev->pNext;
    }

    return rc;
}


/**
 * Create temporary memory regions given on the command line.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to create memory for.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdMemRegionsTmpCreate(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = STS_INF_SUCCESS;

    for (uint32_t i = 0; i < pCfg->cMemCreate && STS_SUCCESS(rc); i++)
    {
        PCPSPEMUCFGMEMREGIONCREATE pMemRegion = &pCfg->paMemCreate[i];
        PPSPCCDMEMREGION pMem = (PPSPCCDMEMREGION)calloc(1, sizeof(*pMem));

        if (pMem)
        {
            switch (pMemRegion->enmAddrSpace)
            {
                case PSPADDRSPACE_X86:
                    rc = PSPEmuIoMgrX86MemRegister(pThis->hIoMgr, pMemRegion->u.PhysX86Addr, pMemRegion->cbRegion, true /*fCanExec*/,
                                                   NULL /*pfnFetch*/, NULL, "TmpMemory", &pMem->hIoMgrRegion);
                    break;
                case PSPADDRSPACE_SMN:
                case PSPADDRSPACE_PSP:
                default:
                    rc = STS_ERR_INVALID_PARAMETER; /** @todo */
                    break;
            }

            if (STS_SUCCESS(rc))
            {
                pMem->pNext = pThis->pMemRegionsTmpHead;
                pThis->pMemRegionsTmpHead = pMem;
            }
            else
                free(pMem);
        }
        else
            rc = STS_ERR_NO_MEMORY;
    }

    return rc;
}


/**
 * Preload any memory descriptors.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to to pre load any memory for.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdMemPreload(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = STS_INF_SUCCESS;

    for (uint32_t i = 0; i < pCfg->cMemPreload && STS_SUCCESS(rc); i++)
    {
        PCPSPEMUCFGMEMPRELOAD pMemPreload = &pCfg->paMemPreload[i];

        void *pvPreload = NULL;
        size_t cbPreload = 0;
        rc = PSPEmuFlashLoadFromFile(pMemPreload->pszFilePreload, &pvPreload, &cbPreload);
        if (STS_SUCCESS(rc))
        {
            switch (pMemPreload->enmAddrSpace)
            {
                case PSPADDRSPACE_PSP:
                    rc = PSPEmuIoMgrPspAddrWrite(pThis->hIoMgr, pMemPreload->u.PspAddr, pvPreload, cbPreload);
                    break;
                case PSPADDRSPACE_X86:
                    rc = PSPEmuIoMgrX86AddrWrite(pThis->hIoMgr, pMemPreload->u.PhysX86Addr, pvPreload, cbPreload);
                    break;
                case PSPADDRSPACE_SMN:
                default:
                    rc = STS_ERR_INVALID_PARAMETER; /** @todo */
                    break;
            }
            PSPEmuFlashFree(pvPreload, cbPreload);
        }
    }

    return rc;
}


/**
 * Resets all memory content of the given CCD PSP to the initial state.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to initialize the memory of.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdMemReset(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = STS_INF_SUCCESS;

    if (   pCfg->pvBootRomSvcPage
        && pCfg->cbBootRomSvcPage)
    {
        if (pCfg->cbBootRomSvcPage != _4K)
            return STS_ERR_INVALID_PARAMETER;

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

    if (   STS_SUCCESS(rc)
        && pCfg->pvBinLoad
        && pCfg->cbBinLoad)
    {
        PSPADDR PspAddrWrite = 0;
        switch (pCfg->enmMode)
        {
            case PSPEMUMODE_SYSTEM:
            case PSPEMUMODE_TRUSTED_OS:
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

        if (   !pCfg->fBinContainsHdr
            && pCfg->enmMode != PSPEMUMODE_TRUSTED_OS)
            PspAddrWrite += 256; /* Skip the header part. */

        rc = PSPEmuCoreMemWrite(pThis->hPspCore, PspAddrWrite, pCfg->pvBinLoad, pCfg->cbBinLoad);
    }

    if (STS_SUCCESS(rc))
        rc = pspEmuCcdMemPreload(pThis, pCfg);

    return rc;
}


/**
 * Initializes the SRAM memory content of the given CCD PSP.
 *
 * @returns Status code.
 * @param   pThis                   The CCD instance to initialize the memory of.
 * @param   pCfg                    The global config.
 */
static int pspEmuCcdMemInit(PPSPCCDINT pThis, PCPSPEMUCFG pCfg)
{
    int rc = STS_INF_SUCCESS;

    pThis->cbSram = pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 320 * _1K : _256K;
    pThis->pvSram = calloc(1, pThis->cbSram);
    if (!pThis->pvSram)
        return STS_ERR_NO_MEMORY;

    /* Set the on chip bootloader if configured. */
    if (pCfg->enmMode == PSPEMUMODE_SYSTEM_ON_CHIP_BL)
        rc = PSPEmuCoreMemRegionAdd(pThis->hPspCore, 0xffff0000, pCfg->cbOnChipBl,
                                    PSPEMU_CORE_MEM_REGION_PROT_F_EXEC | PSPEMU_CORE_MEM_REGION_PROT_F_READ,
                                    pCfg->pvOnChipBl);

    /* Map the SRAM. */
    if (STS_SUCCESS(rc))
        rc = PSPEmuCoreMemRegionAdd(pThis->hPspCore, 0x0, pThis->cbSram,
                                    PSPEMU_CORE_MEM_REGION_PROT_F_EXEC | PSPEMU_CORE_MEM_REGION_PROT_F_READ | PSPEMU_CORE_MEM_REGION_PROT_F_WRITE,
                                    pThis->pvSram);
    if (STS_SUCCESS(rc))
        rc = pspEmuCcdMemRegionsTmpCreate(pThis, pCfg);
    if (STS_SUCCESS(rc))
        rc = pspEmuCcdMemReset(pThis, pCfg);

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
    return PSPEmuIoMgrSmnRegister(pThis->hIoMgr, 0x5a078, 4,
                                  pspEmuCcdIdRead, NULL, pThis,
                                  "CcdId", &pThis->hSmnRegId);
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
            //rc = PSPEmuSvcStateCreate(&pThis->hSvc, pThis->hPspCore, pThis->hIoMgr, pThis->hProxy);
            break;
        }
        case PSPEMUMODE_SYSTEM:
        {
            PspAddrStartExec = 0x100;
            break;
        }
        case PSPEMUMODE_TRUSTED_OS:
        {
            PspAddrStartExec = 0x0;
            break;
        }
        default:
            fprintf(stderr, "Invalid emulation mode selected %d\n", pCfg->enmMode);
            rc = -1;
    }

    if (   !rc
        && (   pCfg->fIncptSvc6
            || pCfg->fTraceSvcs))
    {
        rc = PSPEmuCoreSvcInjectSet(pThis->hPspCore, &g_Svc6Reg, (void *)pCfg);
        if (STS_SUCCESS(rc))
            rc = PSPEmuCoreSmcInjectSet(pThis->hPspCore, &g_SmcReg, (void *)pCfg);
    }
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
    int rc = 0;

    if (pCfg->pszTraceLog)
    {
        rc = PSPEmuTraceCreateForFile(&pThis->hTrace, PSPEMU_TRACE_F_DEFAULT, pThis->hPspCore,
                                      0, pCfg->pszTraceLog);
        if (!rc)
            rc = PSPEmuTraceSetDefault(pThis->hTrace);
    }

    if (pCfg->pszCovTrace)
    {
        PSPADDR PspAddrBegin = 0;
        PSPADDR PspAddrEnd   = 0;

        /* Determine coverage trace range based on the emulation mode. */
        switch (pCfg->enmMode)
        {
            case PSPEMUMODE_APP:
                PspAddrBegin = 0x15100;
                PspAddrEnd   = pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 0x4f000 : 0x3f000;
                break;
            case PSPEMUMODE_SYSTEM:
                PspAddrBegin = 0x100;
                PspAddrEnd   = 0x15000;
                break;
            case PSPEMUMODE_SYSTEM_ON_CHIP_BL:
                PspAddrBegin = 0xffff0000;
                PspAddrEnd   = 0xffffffff;
                break;
            case PSPEMUMODE_TRUSTED_OS:
                PspAddrBegin = 0x01f00000; /* This is where it executes after enabling the MMU. */
                PspAddrEnd   = 0x01ffffff;
                break;
            default:
                rc = -1; /* Should not happen. */
        }

        if (!rc)
            rc = PSPEmuCovCreate(&pThis->hCov, pThis->hPspCore, PspAddrBegin, PspAddrEnd);
    }

    if (pCfg->pszIoLog)
    {
        /* Create an I/O log writer instance and register trace points for all access spaces with IOM. */
        rc = PSPEmuIoLogWrCreate(&pThis->hIoLogWr, 0 /*fFlags*/, pCfg->pszIoLog);
        if (STS_SUCCESS(rc))
        {
            uint32_t fTpFlags = PSPEMU_IOM_TRACE_F_READ | PSPEMU_IOM_TRACE_F_WRITE | PSPEMU_IOM_TRACE_F_AFTER;
            rc = PSPEmuIoMgrMmioTraceRegister(pThis->hIoMgr, 0 /*PspAddrMmioStart*/, 0xffffffff /*PspAddrMmioEnd*/,
                                              0 /*cbAccess*/, fTpFlags, pspEmuCcdIoLogMmioTrace, pThis,
                                              &pThis->hIoTpIoLogMmio);
            if (STS_SUCCESS(rc))
                rc = PSPEmuIoMgrSmnTraceRegister(pThis->hIoMgr, 0 /*SmnAddrStart*/, 0xffffffff /*SmnAddrEnd*/,
                                                 0 /*cbAccess*/, fTpFlags, pspEmuCcdIoLogSmnTrace, pThis,
                                                &pThis->hIoTpIoLogSmn);
            if (STS_SUCCESS(rc))
                rc = PSPEmuIoMgrX86TraceRegister(pThis->hIoMgr, 0 /*PhysX86AddrStart*/, 0xffffffffffffffff /*PhysX86AddrEnd*/,
                                                 0 /*cbAccess*/, fTpFlags, pspEmuCcdIoLogX86Trace, pThis,
                                                 &pThis->hIoTpIoLogX86);
        }
    }

    return rc;
}


/**
 * Destroy all devices for the given CCD instance.
 *
 * @returns nothing.
 * @param   pThis                   The CCD instance.
 */
static void pspEmuCcdDevicesDestroy(PPSPCCDINT pThis)
{
    /* Destroy all devices. */
    PPSPDEV pCur = pThis->pDevsHead;
    while (pCur)
    {
        PPSPDEV pFree = pCur;
        pCur = pCur->pNext;
        PSPEmuDevDestroy(pFree);
    }
}


int PSPEmuCcdCreate(PPSPCCD phCcd, uint32_t idSocket, uint32_t idCcd, PCPSPEMUCFG pCfg)
{
    int rc = 0;
    PPSPCCDINT pThis = (PPSPCCDINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->DevIf.pfnIrqSet    = pspCcdIrqSet;
        pThis->pCfg               = pCfg;
        pThis->idSocket           = idSocket;
        pThis->idCcd              = idCcd;
        pThis->fRegSmnHandlers    = false;
        pThis->hCov               = NULL;
        pThis->pMemRegionsTmpHead = NULL;

        rc = PSPEmuCoreCreate(&pThis->hPspCore);
        if (!rc)
        {
            rc = PSPEmuIoMgrCreate(&pThis->hIoMgr, pThis->hPspCore);
            if (!rc)
            {
                rc = PSPEmuIoMgrTraceAllAccessesSet(pThis->hIoMgr, pCfg->fIomLogAllAccesses);
                if (!rc)
                {
                     /** @todo Make IRQ controller handle passthrough as well (think of mixing real and emulated devices). */
                    if (!pCfg->pszPspProxyAddr)
                        rc = PSPIrqCreate(&pThis->hIrq, pThis->hPspCore, pThis->hIoMgr);
                    if (STS_SUCCESS(rc))
                    {
                        /* Create all the devices. */
                        if (pCfg->papszDevs)
                            rc = pspEmuCcdDevicesInstantiate(pThis, pCfg->papszDevs, pCfg);
                        else
                            rc = pspEmuCcdDevicesInstantiateDefault(pThis, pCfg);
                        if (!rc)
                        {
                            /* Initialize the memory content for the PSP. */
                            rc = pspEmuCcdMemInit(pThis, pCfg);
                            if (   !rc
                                && pThis->fRegSmnHandlers)
                                rc = pspEmuCcdMmioSmnInit(pThis);
                            if (!rc)
                                rc = pspEmuCcdExecEnvInit(pThis, pCfg);
                            if (!rc)
                                rc = pspEmuCcdTraceInit(pThis, pCfg);
                            if (!rc)
                            {
                                *phCcd = pThis;
                                return STS_INF_SUCCESS;
                            }

                            pspEmuCcdDevicesDestroy(pThis);
                        }

                        if (pThis->hIrq)
                            PSPIrqDestroy(pThis->hIrq);
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

    if (pThis->hIoTpIoLogMmio)
    {
        PSPEmuIoMgrTpDeregister(pThis->hIoTpIoLogMmio);
        pThis->hIoTpIoLogMmio = NULL;
    }

    if (pThis->hIoTpIoLogSmn)
    {
        PSPEmuIoMgrTpDeregister(pThis->hIoTpIoLogSmn);
        pThis->hIoTpIoLogSmn = NULL;
    }

    if (pThis->hIoTpIoLogX86)
    {
        PSPEmuIoMgrTpDeregister(pThis->hIoTpIoLogX86);
        pThis->hIoTpIoLogX86 = NULL;
    }

    if (pThis->hIoLogWr)
    {
        PSPEmuIoLogWrDestroy(pThis->hIoLogWr);
        pThis->hIoLogWr = NULL;
    }

    if (pThis->hTrace)
    {
        PSPEmuTraceDestroy(pThis->hTrace);
        pThis->hTrace = NULL;
    }

    if (pThis->hCov)
    {
        /* Dump to file. */
        int rc = PSPEmuCovDumpToFile(pThis->hCov, pThis->pCfg->pszCovTrace);
        if (rc)
            printf("Dumping the coverage trace to %s failed with %d\n", pThis->pCfg->pszCovTrace, rc);
        else
            printf("Dumped the coverage trace successfully to %s\n", pThis->pCfg->pszCovTrace, rc);
        PSPEmuCovDestroy(pThis->hCov);
        pThis->hCov = NULL;
    }

    if (pThis->hSvc)
    {
        PSPEmuSvcStateDestroy(pThis->hSvc);
        pThis->hSvc = NULL;
    }

    pspEmuCcdDevicesDestroy(pThis);

    if (pThis->hIrq)
    {
        PSPIrqDestroy(pThis->hIrq);
        pThis->hIrq = NULL;
    }

    /* Destroy the I/O manager and then the emulation core and last this structure. */
    PSPEmuIoMgrDestroy(pThis->hIoMgr);
    PSPEmuCoreDestroy(pThis->hPspCore);
    if (pThis->pvSram)
        free(pThis->pvSram);
    free(pThis);
}


int PSPEmuCcdQueryCore(PSPCCD hCcd, PPSPCORE phPspCore)
{
    PPSPCCDINT pThis = hCcd;

    *phPspCore = pThis->hPspCore;
    return 0;
}


int PSPEmuCcdQueryIoMgr(PSPCCD hCcd, PPSPIOM phIoMgr)
{
    PPSPCCDINT pThis = hCcd;

    *phIoMgr = pThis->hIoMgr;
    return 0;
}


int PSPEmuCcdReset(PSPCCD hCcd)
{
    PPSPCCDINT pThis = hCcd;

    int rc = pspEmuCcdDevicesReset(pThis);
    if (!rc)
        rc = PSPEmuCoreExecReset(pThis->hPspCore);
    if (!rc)
        rc = pspEmuCcdMemReset(pThis, pThis->pCfg);
    if (!rc)
        rc = pspEmuCcdExecEnvInit(pThis, pThis->pCfg);

    return rc;
}


int PSPEmuCcdRun(PSPCCD hCcd)
{
    PPSPCCDINT pThis = hCcd;

    int rc = PSPEmuCoreExecRun(pThis->hPspCore,
                                 pThis->pCfg->fSingleStepDumpCoreState
                               ? PSPEMU_CORE_EXEC_F_DUMP_CORE_STATE
                               : PSPEMU_CORE_EXEC_F_DEFAULT,
                               0, PSPEMU_CORE_EXEC_INDEFINITE);
    if (rc == PSPEMU_INF_CORE_INSN_WFI_REACHED)
        printf("WFI instruction reached and no WFI handler is set, exiting...\n");
    PSPEmuCoreStateDump(pThis->hPspCore, PSPEMU_CORE_STATE_DUMP_F_DEFAULT, 0 /*cInsns*/);
    return rc;
}

