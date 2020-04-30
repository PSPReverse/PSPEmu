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

#include <common/types.h>
#include <common/cdefs.h>

#include <libpspproxy.h>

#include <psp-proxy.h>
#include <psp-trace.h>
#include <psp-iom.h>


/**
 * PSP MMIO blacklist descriptor.
 */
typedef struct PSPMMIOBLACKLISTDESC
{
    /** MMIO address being blacklisted. */
    PSPADDR                         PspAddrMmio;
    /** Access size, 0 means size doesn't matter. */
    size_t                          cbAcc;
    /** Flag whether writes are blacklisted. */
    bool                            fWrites;
    /** Flag whether reads are blacklisted. */
    bool                            fReads;
    /** Value to return on reads if blacklisted. */
    uint32_t                        u32ValRead;
} PSPMMIOBLACKLISTDESC;
/** Pointer to a blacklist descriptor. */
typedef PSPMMIOBLACKLISTDESC *PPSPMMIOBLACKLISTDESC;
/** Pointer to a const blacklist descriptor. */
typedef const PSPMMIOBLACKLISTDESC *PCPSPMMIOBLACKLISTDESC;


/**
 * PSP SMN blacklist descriptor.
 */
typedef struct PSPSMNBLACKLISTDESC
{
    /** SMN address being blacklisted. */
    SMNADDR                         SmnAddr;
    /** Access size, 0 means size doesn't matter. */
    size_t                          cbAcc;
    /** Flag whether writes are blacklisted. */
    bool                            fWrites;
    /** Flag whether reads are blacklisted. */
    bool                            fReads;
    /** Value to return on reads if blacklisted. */
    uint32_t                        u32ValRead;
} PSPSMNBLACKLISTDESC;
/** Pointer to a blacklist descriptor. */
typedef PSPSMNBLACKLISTDESC *PPSPSMNBLACKLISTDESC;
/** Pointer to a const blacklist descriptor. */
typedef const PSPSMNBLACKLISTDESC *PCPSPSMNBLACKLISTDESC;


/**
 * x86 MMIO blacklist descriptor.
 */
typedef struct PSPX86BLACKLISTDESC
{
    /** SMN address being blacklisted. */
    X86PADDR                        PhysX86Addr;
    /** Access size, 0 means size doesn't matter. */
    size_t                          cbAcc;
    /** Flag whether writes are blacklisted. */
    bool                            fWrites;
    /** Flag whether reads are blacklisted. */
    bool                            fReads;
    /** Value to return on reads if blacklisted. */
    uint32_t                        u32ValRead;
} PSPX86BLACKLISTDESC;
/** Pointer to a blacklist descriptor. */
typedef PSPX86BLACKLISTDESC *PPSPX86BLACKLISTDESC;
/** Pointer to a const blacklist descriptor. */
typedef const PSPX86BLACKLISTDESC *PCPSPX86BLACKLISTDESC;


/** Forward declaration of the PSP proxy instance data. */
typedef struct PSPPROXYINT *PPSPPROXYINT;


/**
 * CCD registration record.
 */
typedef struct PSPPROXYCCD
{
    /** Pointer to the next record. */
    struct PSPPROXYCCD          *pNext;
    /** Pointer to the owning proxy instance. */
    PPSPPROXYINT                pThis;
    /** The CCD handle. */
    PSPCCD                      hCcd;
} PSPPROXYCCD;
/** Pointer to a CCD registration record. */
typedef PSPPROXYCCD *PPSPPROXYCCD;


/**
 * Proxy instance data.
 */
typedef struct PSPPROXYINT
{
    /** PSP proxy context handle. */
    PSPPROXYCTX                 hPspProxyCtx;
    /** The global config. */
    PCPSPEMUCFG                 pCfg;
    /** Head of CCDs registered with this proxy instance. */
    PPSPPROXYCCD                pCcdsHead;
} PSPPROXYINT;


/**
 * MMIO address blacklisted for the Zen on chip bootloader.
 */
static const PSPMMIOBLACKLISTDESC g_aMmioBlacklistedZenOnChip[] =
{
    { 0xfffffff, 4, false, false, 0 } /* Dummy which never triggers. */
};


/**
 * SMN address blacklisted for the Zen off chip bootloader.
 */
static const PSPSMNBLACKLISTDESC g_aSmnBlacklistedZenOffChip[] =
{
    { 0x02dc4000, 0, true, true, 0 }, /* Flash related, accessing breaks communication interface. */
    { 0x02dc4003, 0, true, true, 0 }, /* Flash related, accessing breaks communication interface. */
    { 0x02dc401e, 0, true, true, 0 }, /* Flash related, accessing breaks communication interface. */
    { 0x02dc401f, 0, true, true, 0 }, /* Flash related, accessing breaks communication interface. */
};


/**
 * x86 address blacklisted for the Zen off chip bootloader.
 */
static const PSPX86BLACKLISTDESC g_ax86BlacklistedZenOffChip[] =
{
    { 0xffffffffffffffff, 8, false, false, 0 } /* Dummy which never triggers. */
};


/**
 * Read helper.
 *
 * @returns nothing.
 * @param   pvDst                   Where to store the value.
 * @param   u32Val                  The value to store.
 * @param   cbAcc                   Access width.
 */
static void pspProxyRead(void *pvDst, uint32_t u32Val, size_t cbAcc)
{
    switch (cbAcc)
    {
        case 1:
            *(uint8_t *)pvDst = (uint8_t)u32Val;
            break;
        case 2:
            *(uint16_t *)pvDst = (uint16_t)u32Val;
            break;
        case 4:
            *(uint32_t *)pvDst = u32Val;
            break;
    }
}


/**
 * Determines the BL stage we are in based on some criteria.
 *
 * @returns BL stage.
 * @param   hCcd                    The CCD to determine the stage for.
 */
static PSPPROXYBLSTAGE pspEmuCcdDetermineBlStage(PSPCCD hCcd)
{
    /** @todo Check the PC. */
    return PSPPROXYBLSTAGE_UNKNOWN;
}


static void pspEmuProxyCcdPspMmioUnassignedRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    bool fAllowed = PSPProxyIsMmioAccessAllowed(offMmio, cbRead, false /*fWrite*/,
                                                pspEmuCcdDetermineBlStage(pCcdRec->hCcd),
                                                pThis->pCfg, pvVal);
    if (fAllowed)
    {
        int rc = 0;
        if (cbRead <= sizeof(uint32_t))
            rc = PSPProxyCtxPspMmioRead(pThis->hPspProxyCtx, offMmio, cbRead, pvVal);
        else /* Do a simple memory transfer. */
            rc = PSPProxyCtxPspMemRead(pThis->hPspProxyCtx, offMmio, pvVal, cbRead);
        if (rc)
            fprintf(stderr, "pspEmuProxyPspMmioUnassignedRead: Failed with %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddDevRead(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_MMIO,
                                 "<PROXY/DENIED>", offMmio, pvVal, cbRead);
}


static void pspEmuProxyCcdPspMmioUnassignedWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    bool fAllowed = PSPProxyIsMmioAccessAllowed(offMmio, cbWrite, true /*fWrite*/,
                                                pspEmuCcdDetermineBlStage(pCcdRec->hCcd),
                                                pThis->pCfg, NULL /*pvReadVal*/);
    if (fAllowed)
    {
        int rc = 0;
        if (cbWrite <= sizeof(uint32_t))
            rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, offMmio, cbWrite, pvVal);
        else
            rc = PSPProxyCtxPspMemWrite(pThis->hPspProxyCtx, offMmio, pvVal, cbWrite);
        if (rc)
            fprintf(stderr, "pspEmuProxyPspMmioUnassignedWrite: Failed with %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddDevWrite(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_MMIO,
                                  "<PROXY/DENIED>", offMmio, pvVal, cbWrite);
}


static void pspEmuProxyCcdPspSmnUnassignedRead(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    bool fAllowed = PSPProxyIsSmnAccessAllowed(offSmn, cbRead, false /*fWrite*/,
                                               pspEmuCcdDetermineBlStage(pCcdRec->hCcd),
                                               pThis->pCfg, pvVal);
    if (fAllowed)
    {
        int rc = PSPProxyCtxPspSmnRead(pThis->hPspProxyCtx, 0 /*idCcdTgt*/, offSmn, cbRead, pvVal);
        if (rc)
            fprintf(stderr, "pspEmuProxyPspSmnUnassignedRead: Failed with %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddDevRead(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_SMN,
                                 "<PROXY/DENIED>", offSmn, pvVal, cbRead);
}


static void pspEmuProxyCcdPspSmnUnassignedWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    bool fAllowed = PSPProxyIsSmnAccessAllowed(offSmn, cbWrite, true /*fWrite*/,
                                               pspEmuCcdDetermineBlStage(pCcdRec->hCcd),
                                               pThis->pCfg, NULL /*pvReadVal*/);
    if (fAllowed)
    {
        int rc = PSPProxyCtxPspSmnWrite(pThis->hPspProxyCtx, 0 /*idCcdTgt*/, offSmn, cbWrite, pvVal);
        if (rc)
            fprintf(stderr, "pspEmuProxyPspSmnUnassignedWrite: Failed with %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddDevWrite(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_SMN,
                                  "<PROXY/DENIED>", offSmn, pvVal, cbWrite);
}


static void pspEmuProxyCcdX86UnassignedRead(X86PADDR offX86Phys, size_t cbRead, void *pvVal, bool fMmio,
                                            uint32_t fCaching, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    bool fAllowed = PSPProxyIsX86AccessAllowed(offX86Phys, cbRead, false /*fWrite*/,
                                               pspEmuCcdDetermineBlStage(pCcdRec->hCcd),
                                               pThis->pCfg, pvVal);
    if (fAllowed)
    {
        int rc = 0;

        if (fMmio)
            rc = PSPProxyCtxPspX86MmioRead(pThis->hPspProxyCtx, offX86Phys, cbRead, pvVal);
        else
            rc = PSPProxyCtxPspX86MemRead(pThis->hPspProxyCtx, offX86Phys, pvVal, cbRead);
        if (rc)
            fprintf(stderr, "pspEmuProxyPspX86UnassignedRead: Failed with %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddDevRead(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_X86,
                                 "<PROXY/DENIED>", offX86Phys, pvVal, cbRead);
}


static void pspEmuProxyCcdX86UnassignedWrite(X86PADDR offX86Phys, size_t cbWrite, const void *pvVal, bool fMmio,
                                             uint32_t fCaching, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    bool fAllowed = PSPProxyIsX86AccessAllowed(offX86Phys, cbWrite, true /*fWrite*/,
                                               pspEmuCcdDetermineBlStage(pCcdRec->hCcd),
                                               pThis->pCfg, NULL /*pvReadVal*/);
    if (fAllowed)
    {
        int rc = 0;

        if (fMmio)
            rc = PSPProxyCtxPspX86MmioWrite(pThis->hPspProxyCtx, offX86Phys, cbWrite, pvVal);
        else
            rc = PSPProxyCtxPspX86MemWrite(pThis->hPspProxyCtx, offX86Phys, pvVal, cbWrite);
        if (rc)
            fprintf(stderr, "pspEmuProxyPspX86UnassignedWrite: Failed with %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddDevWrite(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_X86,
                                  "<PROXY/DENIED>", offX86Phys, pvVal, cbWrite);
}


static void pspEmuCcdProxyLogMsg(PSPPROXYCTX hCtx, void *pvUser, const char *pszMsg)
{
    PPSPPROXYINT pThis = (PPSPPROXYINT)pvUser;
    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_PROXY,
                            "%s", pszMsg);
}


static const PSPPROXYIOIF g_PspProxyIoIf =
{
    /** pfnLogMsg */
    pspEmuCcdProxyLogMsg,
    /** pfnOutBufWrite */
    NULL,
    /** pfnInBufPeek */
    NULL,
    /** pfnInBufRead */
    NULL
};


int PSPProxyCreate(PPSPPROXY phProxy, PCPSPEMUCFG pCfg)
{
    int rc = 0;

    PPSPPROXYINT pThis = (PPSPPROXYINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->pCfg      = pCfg;
        pThis->pCcdsHead = NULL;

        printf("PSP proxy: Connecting to %s\n", pCfg->pszPspProxyAddr);
        rc = PSPProxyCtxCreate(&pThis->hPspProxyCtx, pCfg->pszPspProxyAddr, &g_PspProxyIoIf, pThis);
        if (!rc)
        {
            printf("PSP proxy: Connected to %s\n", pCfg->pszPspProxyAddr);
            *phProxy = pThis;
            return 0;
        }
        else
            fprintf(stderr, "Connecting to the PSP proxy failed with %d\n", rc);

        free(pThis);
    }
    else
        rc = -1;

    return rc;
}


void PSPProxyDestroy(PSPPROXY hProxy)
{
    PPSPPROXYINT pThis = hProxy;

    PPSPPROXYCCD pCcdRec = pThis->pCcdsHead;
    while (pCcdRec)
    {
        PPSPPROXYCCD pFree = pCcdRec;
        pCcdRec = pCcdRec->pNext;

        free(pFree);
    }

    PSPProxyCtxDestroy(pThis->hPspProxyCtx);
    free(pThis);
}


int PSPProxyCcdRegister(PSPPROXY hProxy, PSPCCD hCcd)
{
    PPSPPROXYINT pThis = hProxy;

    /** @todo Check for duplicates. */
    int rc = 0;
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)calloc(1, sizeof(*pCcdRec));
    if (pCcdRec)
    {
        PSPIOM hIoMgr;
        rc = PSPEmuCcdQueryIoMgr(hCcd, &hIoMgr);
        if (!rc)
        {
            /* Register the unassigned handlers for the various regions. */
            rc = PSPEmuIoMgrMmioUnassignedSet(hIoMgr, pspEmuProxyCcdPspMmioUnassignedRead, pspEmuProxyCcdPspMmioUnassignedWrite,
                                              "<PROXY>", pCcdRec);
            if (!rc)
                rc = PSPEmuIoMgrSmnUnassignedSet(hIoMgr, pspEmuProxyCcdPspSmnUnassignedRead, pspEmuProxyCcdPspSmnUnassignedWrite,
                                                 "<PROXY>", pCcdRec);
            if (!rc)
                rc = PSPEmuIoMgrX86UnassignedSet(hIoMgr, pspEmuProxyCcdX86UnassignedRead, pspEmuProxyCcdX86UnassignedWrite,
                                                 "<PROXY>", pCcdRec);

            if (!rc)
            {
                pCcdRec->pThis = pThis;
                pCcdRec->hCcd  = hCcd;
                pCcdRec->pNext = pThis->pCcdsHead;

                pThis->pCcdsHead = pCcdRec;
                return 0;
            }
        }

        free(pCcdRec);
    }
    else
        rc = -1;

    return rc;
}


int PSPProxyCcdDeregister(PSPPROXY hProxy, PSPCCD hCcd)
{
    /** @todo */
    return -1;
}


bool PSPProxyIsMmioAccessAllowed(PSPADDR PspAddrMmio, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                 PCPSPEMUCFG pCfg, void *pvReadVal)
{
    if (   (   enmStage == PSPPROXYBLSTAGE_ON_CHIP
            || enmStage == PSPPROXYBLSTAGE_UNKNOWN)
        && pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN)
    {
        for (uint32_t i = 0; i < ELEMENTS(g_aMmioBlacklistedZenOnChip); i++)
        {
            PCPSPMMIOBLACKLISTDESC pDesc = &g_aMmioBlacklistedZenOnChip[i];

            if (pDesc->PspAddrMmio == PspAddrMmio)
            {
                if (   (   pDesc->cbAcc == cbAcc
                        || pDesc->cbAcc == 0)
                    && (   (   fWrite
                            && pDesc->fWrites)
                        || (   !fWrite
                            && pDesc->fReads)))
                {
                    /* On a read return the value to be used instead. */
                    if (!fWrite)
                        pspProxyRead(pvReadVal, pDesc->u32ValRead, cbAcc);
                    return false;
                }

                /* Other checks failed so we can stop searching here (every address only has one descriptor). */
                break;
            }
        }
    }

    return true;
}


bool PSPProxyIsSmnAccessAllowed(SMNADDR SmnAddr, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                PCPSPEMUCFG pCfg, void *pvReadVal)
{
    if (   (   enmStage == PSPPROXYBLSTAGE_OFF_CHIP
            || enmStage == PSPPROXYBLSTAGE_UNKNOWN)
        && pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN)
    {
        for (uint32_t i = 0; i < ELEMENTS(g_aSmnBlacklistedZenOffChip); i++)
        {
            PCPSPSMNBLACKLISTDESC pDesc = &g_aSmnBlacklistedZenOffChip[i];

            if (pDesc->SmnAddr == SmnAddr)
            {
                if (   (   pDesc->cbAcc == cbAcc
                        || pDesc->cbAcc == 0)
                    && (   (   fWrite
                            && pDesc->fWrites)
                        || (   !fWrite
                            && pDesc->fReads)))
                {
                    /* On a read return the value to be used instead. */
                    if (!fWrite)
                        pspProxyRead(pvReadVal, pDesc->u32ValRead, cbAcc);
                    return false;
                }

                /* Other checks failed so we can stop searching here (every address only has one descriptor). */
                break;
            }
        }
    }

    return true;
}


bool PSPProxyIsX86AccessAllowed(X86PADDR PhysX86Addr, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                PCPSPEMUCFG pCfg, void *pvReadVal)
{
    if (   (   enmStage == PSPPROXYBLSTAGE_OFF_CHIP
            || enmStage == PSPPROXYBLSTAGE_UNKNOWN)
        && pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN)
    {
        for (uint32_t i = 0; i < ELEMENTS(g_ax86BlacklistedZenOffChip); i++)
        {
            PCPSPX86BLACKLISTDESC pDesc = &g_ax86BlacklistedZenOffChip[i];

            if (pDesc->PhysX86Addr == PhysX86Addr)
            {
                if (   (   pDesc->cbAcc == cbAcc
                        || pDesc->cbAcc == 0)
                    && (   (   fWrite
                            && pDesc->fWrites)
                        || (   !fWrite
                            && pDesc->fReads)))
                {
                    /* On a read return the value to be used instead. */
                    if (!fWrite)
                        pspProxyRead(pvReadVal, pDesc->u32ValRead, cbAcc);
                    return false;
                }

                /* Other checks failed so we can stop searching here (every address only has one descriptor). */
                break;
            }
        }
    }

    return true;
}

