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


/**
 * Ternary value.
 */
typedef enum PSPTERNARY
{
    /** Invalid value. */
    PSPTERNARY_INVALID = 0,
    /** Undecided value. */
    PSPTERNARY_UNDECIDED,
    /** True value. */
    PSPTERNARY_TRUE,
    /** False value. */
    PSPTERNARY_FALSE
} PSPTERNARY;

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
    /** PSP Proxy start address. */
    PSPPROXYADDR                ProxyAddr;
    /** Access stride (should only ever be 1, 2 or 4 bytes really). */
    size_t                      cbWrStride;
    /** Overall number of bytes buffered. */
    size_t                      cbWrBuffered;
    /** Flag whether the writes all happen to the same address or
     * whether the write will increase the address by the write stride. */
    PSPTERNARY                  enmTriAddrIncrByStride;
    /** Flag whether this is a memset like operation. */
    PSPTERNARY                  enmTriMemset;
    /** Next offset into the data buffer to write to. */
    uint32_t                    offData;
    /** The buffered data. */
    uint8_t                     abWrData[_4K];
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


static const char *pspEmuProxyTernaryToStr(PSPTERNARY enmTernary)
{
    switch (enmTernary)
    {
        case PSPTERNARY_UNDECIDED:
            return "UNDECIDED";
        case PSPTERNARY_TRUE:
            return "TRUE";
        case PSPTERNARY_FALSE:
            return "FALSE";
        default:
            break;
    }

    return "<WHAT>";
}


/**
 * Checks whether two PSP proxy addresses are considered equal.
 *
 * @returns Flag whether the addresses are considered equal or not.
 * @param   pAddr1                  The first address to check.
 * @param   pAddr2                  The address to check against.
 */
static inline bool pspEmuProxyAddrIsEqual(PCPSPPROXYADDR pAddr1, PCPSPPROXYADDR pAddr2)
{
    if (pAddr1->enmAddrSpace != pAddr2->enmAddrSpace)
        return false;

    switch (pAddr1->enmAddrSpace)
    {
        case PSPPROXYADDRSPACE_PSP_MEM:
        case PSPPROXYADDRSPACE_PSP_MMIO:
            if (pAddr1->u.PspAddr != pAddr2->u.PspAddr)
                return false;
            break;
        case PSPPROXYADDRSPACE_SMN:
            if (pAddr1->u.SmnAddr != pAddr2->u.SmnAddr)
                return false;
            break;
        case PSPPROXYADDRSPACE_X86_MEM:
        case PSPPROXYADDRSPACE_X86_MMIO:
            if (   pAddr1->u.X86.PhysX86Addr != pAddr2->u.X86.PhysX86Addr
                || pAddr1->u.X86.fCaching != pAddr2->u.X86.fCaching)
                return false;
            break;
        default:
            return false;
    }

    return true;
}


/**
 * Checks whether the second proxy address is considered larger than the first one.
 *
 * @returns Flag whether the addresses are considered equal or not.
 * @param   pAddr1                  The first address to check.
 * @param   pAddr2                  The address to check against.
 *
 * @note Make sure both addresses have the same address space or this will give bogus results!
 */
static inline bool pspEmuProxyAddrIsBigger(PCPSPPROXYADDR pAddr1, PCPSPPROXYADDR pAddr2)
{
    if (pAddr1->enmAddrSpace != pAddr2->enmAddrSpace)
        return false;

    switch (pAddr1->enmAddrSpace)
    {
        case PSPPROXYADDRSPACE_PSP_MEM:
        case PSPPROXYADDRSPACE_PSP_MMIO:
            if (pAddr1->u.PspAddr < pAddr2->u.PspAddr)
                return true;
            break;
        case PSPPROXYADDRSPACE_SMN:
            if (pAddr1->u.SmnAddr < pAddr2->u.SmnAddr)
                return true;
        case PSPPROXYADDRSPACE_X86_MEM:
        case PSPPROXYADDRSPACE_X86_MMIO:
            if (pAddr1->u.X86.PhysX86Addr < pAddr2->u.X86.PhysX86Addr)
                return true;
        default:
            return false;
    }

    return false;
}


/**
 * Subtracts the given addresses returning the offset between them.
 *
 * @returns offset between addresses.
 * @param   pMinuend                The address to subtract from.
 * @param   pSubtrahend             The address to subtract.
 *
 * @note Make sure both addresses have the same address space or this will give bogus results!
 * @note The minuend should be larger than the subtrahend or the result might surprise you...
 */
static inline uint64_t pspEmuProxyAddrSub(PCPSPPROXYADDR pMinuend, PCPSPPROXYADDR pSubtrahend)
{
    if (pMinuend->enmAddrSpace != pSubtrahend->enmAddrSpace)
        return UINT64_MAX;

    switch (pMinuend->enmAddrSpace)
    {
        case PSPPROXYADDRSPACE_PSP_MEM:
        case PSPPROXYADDRSPACE_PSP_MMIO:
            return pMinuend->u.PspAddr - pSubtrahend->u.PspAddr;
        case PSPPROXYADDRSPACE_SMN:
            return pMinuend->u.SmnAddr - pSubtrahend->u.SmnAddr;
        case PSPPROXYADDRSPACE_X86_MEM:
        case PSPPROXYADDRSPACE_X86_MMIO:
            return pMinuend->u.X86.PhysX86Addr - pSubtrahend->u.X86.PhysX86Addr;
        default:
            break;
    }

    return UINT64_MAX;
}


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
 * Flushes any buffered writes out immediately to the proxied CCD.
 *
 * @returns Status code.
 * @param   pThis                   The proxy instance.
 * @param   pCcdRec                 The CCD record to flush out the buffered writes to.
 */
static int pspEmuProxyCcdWrBufFlush(PPSPPROXYINT pThis, PPSPPROXYCCD pCcdRec)
{
    int rc = 0;

    if (pCcdRec->ProxyAddr.enmAddrSpace != PSPPROXYADDRSPACE_INVALID)
    {
        uint32_t fFlags = PSPPROXY_CTX_ADDR_XFER_F_WRITE;

        if (pCcdRec->enmTriMemset == PSPTERNARY_TRUE)
            fFlags = PSPPROXY_CTX_ADDR_XFER_F_MEMSET;
        if (pCcdRec->enmTriAddrIncrByStride == PSPTERNARY_TRUE)
            fFlags |= PSPPROXY_CTX_ADDR_XFER_F_INCR_ADDR;

        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_PROXY,
                                "Flushing to proxy: cbStride=%zu cbWrBuffered=%zu enmTriMemset=%s enmTriAddrIncrByStride=%s",
                                pCcdRec->cbWrStride, pCcdRec->cbWrBuffered, pspEmuProxyTernaryToStr(pCcdRec->enmTriMemset),
                                pspEmuProxyTernaryToStr(pCcdRec->enmTriAddrIncrByStride));

        rc = PSPProxyCtxPspAddrXfer(pThis->hPspProxyCtx, &pCcdRec->ProxyAddr, fFlags, pCcdRec->cbWrStride,
                                    pCcdRec->cbWrBuffered, &pCcdRec->abWrData[0]);
        if (rc)
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "Flushing write buffer to proxy failed with %d", rc);
        else if (pCcdRec->cbWrStride < pCcdRec->cbWrBuffered) /* Only log if we buffered more than one write. */
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_PROXY,
                                    "Flushed write buffer to proxy");

        pCcdRec->ProxyAddr.enmAddrSpace = PSPPROXYADDRSPACE_INVALID;
        pCcdRec->offData                = 0;
        pCcdRec->cbWrStride             = 0;
        pCcdRec->cbWrBuffered           = 0;
        pCcdRec->enmTriAddrIncrByStride = PSPTERNARY_UNDECIDED;
        pCcdRec->enmTriMemset           = PSPTERNARY_UNDECIDED;
    }
    /* else Nothing to flush */

    return rc;
}


/**
 * Checks whether appending data to the given CCD write buffer is possible.
 *
 * @returnd Flag whether appending is possible.
 * @param   pCcdRec                 The CCD record to buffer the write for.
 * @param   pProxyAddr              The proxy address to check.
 * @param   cbWrite                 Amount of data to write.
 * @param   pfFlushReq              Where to store whether a buffer flush is required before continuing.
 *                                  This needs to be adhered to even if appending is not possible in any case.
 *                                  (Think of really large writes from the CCP etc. which won't be buffered
 *                                  in an case but flushing previous writes are required before passing the write
 *                                  through).
 */
static bool pspEmuProxyCcdWrBufIsAppendPossible(PPSPPROXYCCD pCcdRec, PCPSPPROXYADDR pProxyAddr,
                                                const void *pvLocal, size_t cbWrite, bool *pfFlushReq)
{
    *pfFlushReq = true;

    /* Large and unaligned writes can't be buffered at all. */
    if (   cbWrite != 1
        && cbWrite != 2
        && cbWrite != 4)
        return false;

    /* If there is nothing buffered currently we don't need any flushing and can append straight away. */
    if (pCcdRec->ProxyAddr.enmAddrSpace != PSPPROXYADDRSPACE_INVALID)
    {
        /* A full write buffer needs flushing. */
        if (pCcdRec->offData == sizeof(pCcdRec->abWrData))
            return true;

        /* Writes to different address spaces can't be buffered without flushing. */
        if (pCcdRec->ProxyAddr.enmAddrSpace != pProxyAddr->enmAddrSpace)
            return true;

        /* Writes with different strides can't be buffered. */
        if (pCcdRec->cbWrStride != cbWrite)
            return true;

        /* x86 writes with different caching attributes can't be buffered. */
        if (   (   (pProxyAddr->enmAddrSpace == PSPPROXYADDRSPACE_X86_MEM)
                || (pProxyAddr->enmAddrSpace == PSPPROXYADDRSPACE_X86_MMIO))
            && (pCcdRec->ProxyAddr.u.X86.fCaching != pProxyAddr->u.X86.fCaching))
            return true;

        /*
         * If we are in the middle of a memset operation and the current value doesn't match
         * what is being set we can't buffer anymore.
         */
        if (   pCcdRec->enmTriMemset == PSPTERNARY_TRUE
            && memcmp(&pCcdRec->abWrData[0], pvLocal, cbWrite))
            return true;

        /* We can buffer accesses to always the same address or contiguous accesses */
        bool fAddrEqual = pspEmuProxyAddrIsEqual(&pCcdRec->ProxyAddr, pProxyAddr);
        bool fAddrBigger = pspEmuProxyAddrIsBigger(&pCcdRec->ProxyAddr, pProxyAddr);
        if (pCcdRec->enmTriAddrIncrByStride == PSPTERNARY_TRUE)
        {
            /*
             * Written to address needs to be bigger and the offset needs to be adjacent to
             * what is currently buffered.
             */
            if (   !fAddrBigger
                || pspEmuProxyAddrSub(pProxyAddr, &pCcdRec->ProxyAddr) != pCcdRec->cbWrBuffered)
                return true;
        }
        else if (pCcdRec->enmTriAddrIncrByStride == PSPTERNARY_FALSE)
        {
            if (!fAddrEqual)
                return true;
        }
        else
        {
            /*
             * Undecided, so addresses which are not equal or not adjacent to the start address
             * stop buffering.
             */
            if (   (   !fAddrBigger
                    || pspEmuProxyAddrSub(pProxyAddr, &pCcdRec->ProxyAddr) != pCcdRec->cbWrBuffered)
                && !fAddrEqual)
                return true;
        }
    }

    /* If we reached this part we can append the write without any flushing required. */
    *pfFlushReq = false;
    return true;
}


/**
 * Appends the given write to the internal buffer flushing out previous writes if necessary.
 *
 * @returns Flag whether the data could be appended or not.
 * @param   pThis                   The proxy instance.
 * @param   pCcdRec                 The CCD record to buffer the write for.
 * @param   pProxyAddr              The proxy address to buffer the write for.
 * @param   pvLocal                 The local data to buffer.
 * @param   cbWrite                 Size of the write.
 */
static bool pspEmuProxyCcdWrBufAppend(PPSPPROXYINT pThis, PPSPPROXYCCD pCcdRec, PCPSPPROXYADDR pProxyAddr,
                                      const void *pvLocal, size_t cbWrite)
{
    bool fFlushReq = false;
    bool fCanAppend = pspEmuProxyCcdWrBufIsAppendPossible(pCcdRec, pProxyAddr, pvLocal,
                                                          cbWrite, &fFlushReq);

    if (fFlushReq)
        pspEmuProxyCcdWrBufFlush(pThis, pCcdRec);

    if (fCanAppend)
    {
        if (pCcdRec->ProxyAddr.enmAddrSpace == PSPPROXYADDRSPACE_INVALID)
        {
            pCcdRec->ProxyAddr    = *pProxyAddr;
            pCcdRec->cbWrStride   = cbWrite;
            pCcdRec->cbWrBuffered = cbWrite;
            pCcdRec->offData      = cbWrite;
            memcpy(&pCcdRec->abWrData[0], pvLocal, cbWrite);
        }
        else
        {
            /* Second write determines whether this is a memset like operation or a regular write. */
            if (pCcdRec->cbWrBuffered == pCcdRec->cbWrStride)
            {
                if (!memcmp(&pCcdRec->abWrData[0], pvLocal, pCcdRec->cbWrStride))
                    pCcdRec->enmTriMemset = PSPTERNARY_TRUE;
                else
                    pCcdRec->enmTriMemset = PSPTERNARY_FALSE;
            }

            if (pCcdRec->enmTriMemset == PSPTERNARY_FALSE)
            {
                memcpy(&pCcdRec->abWrData[pCcdRec->offData], pvLocal, cbWrite);
                pCcdRec->offData += cbWrite;
            }

            /* Second write determines the write mode. */
            if (!pspEmuProxyAddrIsEqual(&pCcdRec->ProxyAddr, pProxyAddr))
                pCcdRec->enmTriAddrIncrByStride = PSPTERNARY_TRUE;
            else
                pCcdRec->enmTriAddrIncrByStride = PSPTERNARY_FALSE;

            pCcdRec->cbWrBuffered += pCcdRec->cbWrStride;
        }
    }

    return fCanAppend;
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

    /* Reads will flush any buffered writes immediately and reset the write buffering. */
    pspEmuProxyCcdWrBufFlush(pThis, pCcdRec);

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
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyCcdPspMmioUnassignedRead() failed with %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddDevRead(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_MMIO,
                                 "<PROXY/DENIED>", offMmio, pvVal, cbRead);
}


static void pspEmuProxyCcdPspMmioUnassignedWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    /** @todo Implement buffering for MMIO accesses. */
    pspEmuProxyCcdWrBufFlush(pThis, pCcdRec);

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
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyCcdPspMmioUnassignedWrite() failed with %d", rc);
    }
    else
        PSPEmuTraceEvtAddDevWrite(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_MMIO,
                                  "<PROXY/DENIED>", offMmio, pvVal, cbWrite);
}


static void pspEmuProxyCcdPspSmnUnassignedRead(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    /* Reads will flush any buffered writes immediately and reset the write buffering. */
    pspEmuProxyCcdWrBufFlush(pThis, pCcdRec);

    bool fAllowed = PSPProxyIsSmnAccessAllowed(offSmn, cbRead, false /*fWrite*/,
                                               pspEmuCcdDetermineBlStage(pCcdRec->hCcd),
                                               pThis->pCfg, pvVal);
    if (fAllowed)
    {
        int rc = PSPProxyCtxPspSmnRead(pThis->hPspProxyCtx, 0 /*idCcdTgt*/, offSmn, cbRead, pvVal);
        if (rc)
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyCcdPspSmnUnassignedRead() failed with %d", rc);
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
        bool fAppended = false;

        if (pThis->pCfg->fProxyWrBuffer)
        {
            PSPPROXYADDR ProxyAddr;
            ProxyAddr.enmAddrSpace = PSPPROXYADDRSPACE_SMN;
            ProxyAddr.u.SmnAddr    = offSmn;
            fAppended = pspEmuProxyCcdWrBufAppend(pThis, pCcdRec, &ProxyAddr, pvVal, cbWrite);
        }

        if (!fAppended)
        {
            int rc = PSPProxyCtxPspSmnWrite(pThis->hPspProxyCtx, 0 /*idCcdTgt*/, offSmn, cbWrite, pvVal);
            if (rc)
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                        "pspEmuProxyCcdPspSmnUnassignedWrite() failed with %d", rc);
        }
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

    /* Reads will flush any buffered writes immediately and reset the write buffering. */
    pspEmuProxyCcdWrBufFlush(pThis, pCcdRec);

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
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyCcdX86UnassignedRead() failed with %d", rc);
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
        bool fAppended = false;

        if (pThis->pCfg->fProxyWrBuffer)
        {
            PSPPROXYADDR ProxyAddr;
            ProxyAddr.enmAddrSpace      = fMmio ? PSPPROXYADDRSPACE_X86_MMIO : PSPPROXYADDRSPACE_X86_MEM;
            ProxyAddr.u.X86.PhysX86Addr = offX86Phys;
            ProxyAddr.u.X86.fCaching    = fCaching;
            fAppended = pspEmuProxyCcdWrBufAppend(pThis, pCcdRec, &ProxyAddr, pvVal, cbWrite);
        }

        if (!fAppended)
        {
            int rc = 0;

            if (fMmio)
                rc = PSPProxyCtxPspX86MmioWrite(pThis->hPspProxyCtx, offX86Phys, cbWrite, pvVal);
            else
                rc = PSPProxyCtxPspX86MemWrite(pThis->hPspProxyCtx, offX86Phys, pvVal, cbWrite);
            if (rc)
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                        "pspEmuProxyCcdX86UnassignedWrite() failed with %d", rc);
        }
    }
    else
        PSPEmuTraceEvtAddDevWrite(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_X86,
                                  "<PROXY/DENIED>", offX86Phys, pvVal, cbWrite);
}


static int pspEmuProxyWfiReached(PSPCORE hCore, PSPADDR PspAddrPc, bool *pfIrq, bool *pfFirq, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    uint32_t idCcd = 0; /** @todo Multiple CCD support. */
    int rc = 0;

    do
    {
        rc = PSPProxyCtxPspWaitForIrq(pThis->hPspProxyCtx, &idCcd, pfIrq, pfFirq, 10 * 1000);
        if (!rc)
            break;
        else if (rc == -2)
        {
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyWfiReached() Waiting for Interrupt for CCD %u...\n", idCcd);
            rc = 0;
        }
    } while (!rc);

    return rc;
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
        PSPCORE hPspCore;
        rc = PSPEmuCcdQueryIoMgr(hCcd, &hIoMgr);
        if (!rc)
            rc = PSPEmuCcdQueryCore(hCcd, &hPspCore);
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
                rc = PSPEmuCoreWfiSet(hPspCore, pspEmuProxyWfiReached, pCcdRec);

            if (!rc)
            {
                pCcdRec->pThis                  = pThis;
                pCcdRec->hCcd                   = hCcd;
                pCcdRec->ProxyAddr.enmAddrSpace = PSPPROXYADDRSPACE_INVALID;
                pCcdRec->offData                = 0;
                pCcdRec->enmTriAddrIncrByStride = PSPTERNARY_UNDECIDED;
                pCcdRec->enmTriMemset           = PSPTERNARY_UNDECIDED;
                pCcdRec->pNext                  = pThis->pCcdsHead;

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

