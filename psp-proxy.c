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
#include <psp/ccp.h>

#include <libpspproxy.h>

#include <psp-proxy.h>
#include <psp-trace.h>
#include <psp-iom.h>
#include <psp-flash.h>


/**
 * A datum read/written.
 */
typedef union PSPDATUM
{
    uint8_t   u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    uint8_t  ab[8];
} PSPDATUM;
typedef PSPDATUM *PPSPDATUM;


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
 * CCP Proxy data.
 */
typedef struct PSPPROXYCCP
{
    /** The CCP proxy callback table. */
    CCPPROXY                    CcpProxyIf;
    /** Pointer to the owning proxy instance. */
    PPSPPROXYINT                pThis;
} PSPPROXYCCP;
/** Pointer to a CCP proxy instance. */
typedef PSPPROXYCCP *PPSPPROXYCCP;
/** Pointer to a const CCP proxy instance. */
typedef const PSPPROXYCCP *PCPSPPROXYCCP;


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
    /** The trace point handle for secure OS handover. */
    PSPCORETP                   hTpSecureOsHandover;
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
    /** Number of I/O tracepoint handles in the array below. */
    uint32_t                    cIoTpWt;
    /** Array of I/O tracepoint handles for possible write through memory regions - variable in size. */
    PSPIOMTP                    ahIoTpWt[1];
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
    /** CCP proxy data if enabled. */
    PSPPROXYCCP                 CcpProxy;
} PSPPROXYINT;


/**
 * MMIO address blacklisted for the Zen on chip bootloader.
 */
static const PSPMMIOBLACKLISTDESC g_aMmioBlacklistedZenOnChip[] =
{
    { 0x320001c, 4, true,  false, 0 },
    { 0x3a0001c, 4, true,  false, 0 },
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
#if 0
    /*
     * The following monitor commands release the x86 cores on an Ryzen 1700x (1 CCD, 2CCX, 8 cores):
     *
     *     monitor proxy.SmnWrite 0x18002ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18022ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18042ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18062ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18402ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18422ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18442ff0 4 0x80000000
     *     monitor proxy.SmnWrite 0x18462ff0 4 0x80000000
     */
    { 0x18002ff0, 0, true, true, 0 }, /* Releases x86 core. */
    { 0x18022ff0, 0, true, true, 0 }, /* Releases x86 core. */
    { 0x18042ff0, 0, true, true, 0 }, /* Releases x86 core. */
    { 0x18062ff0, 0, true, true, 0 }, /* Releases x86 core. */
    { 0x18402ff0, 0, true, true, 0 }, /* Releases x86 core. */
    { 0x18422ff0, 0, true, true, 0 }, /* Releases x86 core. */
    { 0x18442ff0, 0, true, true, 0 }, /* Releases x86 core. */
    { 0x18462ff0, 0, true, true, 0 }, /* Releases x86 core. */
#endif
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


static int pspEmuProxyWfiReached(PSPCORE hCore, PSPADDR PspAddrPc, uint32_t fFlags, bool *pfIrq, bool *pfFirq, void *pvUser)
{
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    uint32_t idCcd = 0; /** @todo Multiple CCD support. */

    if (fFlags & PSPEMU_CORE_WFI_CHECK) /* Do a non blocking check. */
    {
        int rc = PSPProxyCtxPspWaitForIrq(pThis->hPspProxyCtx, &idCcd, pfIrq, pfFirq, 0);
        if (STS_SUCCESS(rc))
        {
            PSPEmuCoreIrqSet(hCore, *pfIrq);
            PSPEmuCoreFiqSet(hCore, *pfFirq);
        }

        return STS_INF_SUCCESS;
    }

    int rc = STS_INF_SUCCESS;
    do
    {
        rc = PSPProxyCtxPspWaitForIrq(pThis->hPspProxyCtx, &idCcd, pfIrq, pfFirq, 10 * 1000);
        if (!rc)
        {
            PSPEmuCoreIrqSet(hCore, *pfIrq);
            PSPEmuCoreFiqSet(hCore, *pfFirq);
            break;
        }
        else if (rc == STS_ERR_PSP_PROXY_WFI_NO_CHANGE)
        {
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyWfiReached() Waiting for Interrupt for CCD %u...\n", idCcd);
            rc = STS_INF_SUCCESS;
        }
    } while (STS_SUCCESS(rc));

    return rc;
}


/**
 * Trace hook which gets called, when the off chip BL is about to jump to the trusted OS loader living
 * in secure DRAM.
 *
 * @returns nothing.
 * @param   hCore                   The PSP core where the hook was registered.
 * @param   hTp                     The trace point handle triggering.
 * @param   fTpFlags                Flag indicating the access triggering the tracepoint, see PSPEMU_CORE_TRACE_F_XXX.
 * @param   uPspAddr                The PC, should match the registration.
 * @param   cbInsn                  Size of the instruction in bytes.
 * @param   pvVal                   Pointer to the value being written for write memory trace hooks, undefined otherwise.
 * @param   pvUser                  Opaque user data given during registration.
 */
static void pspEmuProxyTrustedOsHandover(PSPCORE hCore, PSPCORETP hTp, uint32_t fTpFlags, PSPADDR uPspAddr, uint32_t cbInsn, const void *pvVal, void *pvUser)
{
    PPSPPROXYINT pThis = (PPSPPROXYINT)pvUser;

    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_PROXY,
                            "Jumping to trusted OS loader in secure DRAM...\n");

    /* Query the register state. */
    PSPCOREREG aenmRegs[13];
    uint32_t au32Gprs[13];
    for (uint32_t i = 0; i < ELEMENTS(aenmRegs); i++)
        aenmRegs[i] = PSPCOREREG_R0 + i;

    int rc = PSPEmuCoreQueryRegBatch(hCore, &aenmRegs[0], ELEMENTS(aenmRegs), &au32Gprs[0]);
    if (!rc)
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_PROXY,
                                "    R0: %#08x R1: %#08x R2: %#08x R3: %#08x\n",
                                au32Gprs[0], au32Gprs[1], au32Gprs[2], au32Gprs[3]);

        /* Sync the BRSP. */
        uint8_t abData[_4K];
        rc = PSPEmuCoreMemRead(hCore, 0x3f000, &abData[0], sizeof(abData));
        if (!rc)
            rc = PSPProxyCtxPspMemWrite(pThis->hPspProxyCtx, 0x3f000, &abData[0], sizeof(abData));
        if (!rc)
        {
            /* Sync the usermode region. */
            PSPPADDR PspAddrStart = 0x15000;
            size_t cbUsrModeRegion = 0x28000;

            while (   cbUsrModeRegion
                   && !rc)
            {
                rc = PSPEmuCoreMemRead(hCore, PspAddrStart, &abData[0], sizeof(abData));
                if (!rc)
                    rc = PSPProxyCtxPspMemWrite(pThis->hPspProxyCtx, PspAddrStart, &abData[0], sizeof(abData));
                PspAddrStart    += sizeof(abData);
                cbUsrModeRegion -= sizeof(abData);
            }
        }

        if (!rc)
        {
            /*
             * We need to map the secure DRAM in the first x86 mapping slot, do that by issuing a bunch of MMIO writes.
             * The secure DRAM region is hardcoded here.
             */
            uint32_t uVal = 0x003fff7e; /* Secure DRAM base. */
            rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, 0x3230000, sizeof(uVal), &uVal);
            if (!rc)
            {
                uVal = 0x12; /* Unknown but fixed value. */
                rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, 0x3230004, sizeof(uVal), &uVal);
            }
            if (!rc)
            {
                uVal = 0x4; /* DRAM. */
                rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, 0x3230008, sizeof(uVal), &uVal);
                if (!rc)
                    rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, 0x323000c, sizeof(uVal), &uVal);
            }
            if (!rc)
            {
                uVal = 0xffffffff; /* Unknown but fixed value. */
                rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, 0x32303e0, sizeof(uVal), &uVal);
            }
            if (!rc)
            {
                uVal = 0xc0808000; /* Maybe some caching flags. */
                rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, 0x32304d8, sizeof(uVal), &uVal);
            }

            if (!rc)
            {
                /* The destination is stored in r0. */
                rc = PSPProxyCtxBranchTo(pThis->hPspProxyCtx, au32Gprs[0], au32Gprs[0] & 0x1 ? true : false /*fThumb*/, &au32Gprs[0]);
                if (!rc)
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_PROXY,
                                            "pspEmuProxyTrustedOsHandover() handover complete\n", rc);
                else
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                            "pspEmuProxyTrustedOsHandover() handover failed with %d\n", rc);
            }
            else
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                        "pspEmuProxyTrustedOsHandover() Mapping x86 secure DRAM region failed with %d\n", rc);
        }
        else
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyTrustedOsHandover() syncing the BRSP failed with %d\n", rc);
    }
    else
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                "pspEmuProxyTrustedOsHandover() querying register set failed with %d\n", rc);
}


/**
 * Configures a given queue.
 *
 * @returns Status code.
 * @param   pThis                   The PSP proxy instance.
 * @param   idxQueue                The queue index.
 * @param   uCfg                    The config to use.
 */
static int pspEmuProxyCcpQueueCfg(PPSPPROXYINT pThis, uint32_t idxQueue, uint8_t uCfg)
{
    uint32_t uCcpReg = 0;
    int rc = PSPProxyCtxPspMmioRead(pThis->hPspProxyCtx, CCP_V5_MMIO_ADDRESS + 4, sizeof(uCcpReg), &uCcpReg);
    if (!rc)
    {
        uCcpReg = (uCcpReg & ~(7 << (idxQueue * 3))) | (uCfg << (idxQueue * 3));
        rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, CCP_V5_MMIO_ADDRESS + 4, sizeof(uCcpReg), &uCcpReg);
    }

    return rc;
}


/**
 * Executes the given request on the proxied CCP.
 *
 * @returns Status code.
 * @param   pThis                   The PSP proxy instance.
 * @param   pCcpReq                 The CCP request to execute.
 * @param   pu32CcpSts              Where to store the CCP status.
 */
static int pspEmuProxyCcpReqExec(PPSPPROXYINT pThis, PCCCP5REQ pCcpReq, uint32_t *pu32CcpSts)
{
    PSPPADDR PspAddrReq = 0;

    /* Copy the request over. */
    int rc = PSPProxyCtxScratchSpaceAlloc(pThis->hPspProxyCtx, 2*sizeof(*pCcpReq), &PspAddrReq);
    if (!rc)
    {
        uint32_t idxQueue = 0;
        /** @todo Sort out the alignment issue, for now we just the descriptor spot used by the real off chip BL in the BRSP. */
        PSPPADDR PspAddrReqAligned = 0x3f800; //(PspAddrReq + (sizeof(*pCcpReq) - 1)) & ~(sizeof(*pCcpReq) - 1); /* Need to be aligned to the CCP descriptor size. */
        printf("CCP request address %#x\n", PspAddrReqAligned);
        rc = PSPProxyCtxPspMemWrite(pThis->hPspProxyCtx, PspAddrReqAligned, pCcpReq, sizeof(*pCcpReq));
        if (!rc)
        {
            /* Set up MMIO registers. */
            rc = pspEmuProxyCcpQueueCfg(pThis, idxQueue, 0x6);
            if (!rc)
            {
                uint32_t uVal = PspAddrReqAligned + sizeof(*pCcpReq);
                PSPPADDR PspAddrCcpQBase =  CCP_V5_MMIO_ADDRESS + CCP_V5_Q_OFFSET + idxQueue * CCP_V5_Q_SIZE;
                rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, PspAddrCcpQBase + CCP_V5_Q_REG_TAIL, sizeof(uVal), &uVal);
                if (!rc)
                    rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, PspAddrCcpQBase + CCP_V5_Q_REG_HEAD, sizeof(PspAddrReqAligned), &PspAddrReqAligned);
                if (!rc)
                {
                    uVal = 0xd;
                    rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, PspAddrCcpQBase + CCP_V5_Q_REG_CTRL, sizeof(uVal), &uVal);
                    if (!rc)
                    {
                        /* Wait for the CCP to become idle again. */
                        uVal = 0;
                        do
                        {
                            rc = PSPProxyCtxPspMmioRead(pThis->hPspProxyCtx, PspAddrCcpQBase + CCP_V5_Q_REG_CTRL, sizeof(uVal), &uVal);
                        } while (   !rc
                                 && !(uVal & CCP_V5_Q_REG_CTRL_HALT));

                        if (!rc)
                        {
                            rc = PSPProxyCtxPspMmioRead(pThis->hPspProxyCtx, PspAddrCcpQBase + CCP_V5_Q_REG_STATUS, sizeof(*pu32CcpSts), pu32CcpSts);
                            if (rc)
                                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                                        "pspEmuProxyCcpReqExec() Reading CCP request status failed with %d\n", rc);
                        }
                        else
                            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                                    "pspEmuProxyCcpReqExec() Waiting for CCP queue to become idle failed with %d\n", rc);
                    }
                    else
                        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                                "pspEmuProxyCcpReqExec() Starting CCP queue failed with %d\n", rc);
                }
                else
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                            "pspEmuProxyCcpReqExec() Preparing CCP queue registers failed with %d\n", rc);
            }
            else
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                        "pspEmuProxyCcpReqExec() Queue configuration failed %d\n", rc);
        }
        else
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyCcpReqExec() Writing CCP request descriptor into scratch space failed with %d\n", rc);

        PSPProxyCtxScratchSpaceFree(pThis->hPspProxyCtx, PspAddrReq, sizeof(*pCcpReq));
    }
    else
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                "pspEmuProxyCcpReqExec() Allocating scratch space for request failed with %d\n", rc);

    return rc;
}


/**
 * CCP proxy AES operation callback.
 */
static int pspEmuProxyCcpAesDo(PCCCPPROXY pCcpProxyIf, uint32_t u32Dw0, size_t cbSrc, const void *pvSrc,
                               void *pvDst, uint32_t uKeyLsb, const void *pvIv, size_t cbIv, uint32_t *pu32CcpSts)
{
    int rc = STS_INF_SUCCESS;
    PCPSPPROXYCCP pCcpProxy = (PCPSPPROXYCCP)pCcpProxyIf;
    PPSPPROXYINT pThis = pCcpProxy->pThis;

    if (pvIv && cbIv)
    {
#if 0 /** @todo (Not required for unwrapping the IKEK but would be nice to have) */
        PSPPADDR PspAddrIv;

        /* Copy the IV over and into an LSB first. */
        int rc = PSPProxyCtxScratchSpaceAlloc(pThis->hPspProxyCtx, cbIv, &PspAddrIv);
        if (!rc)
        {
            rc = PSPProxyCtxPspMemWrite(pThis->hPspProxyCtx, PspAddrIv, pvIv, cbIv);
            if (!rc)
            {
                /* Prepare a passthrough request and execute it. */
                CCP5REQ CcpReq;

                CcpReq.u32Dw0                   = ;
                CcpReq.cbSrc                    = cbIv;
                CcpReq.u32AddrSrcLow            = PspAddrIv;
                CcpReq.u16AddrSrcHigh           = 0;
                CcpReq.u16SrcMemType            =
                CcpReq.Op.NonSha.u32AddrDstLow  = 0xa0; /* Fixed LSB for now. */
                CcpReq.Op.NonSha.u16AddrDstHigh = 0;
                CcpReq.Op.NonSha.u16DstMemType  = ;
                CcpReq.u32AddrKeyLow            = 0;
                CcpReq.u16AddrKeyHigh           = 0;
                CcpReq.u16KeyMemType            = 0;

                uint32_t u32CcpSts = CCP_V5_STATUS_SUCCESS;
                rc = pspEmuProxyCcpReqExec(pThis, &CcpReq, &u32CcpSts);
                if (   rc
                    || u32CcpSts != CCP_V5_STATUS_SUCCESS)
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                            "pspEmuProxyCcpAesDo() Executing request failed with rc=%d u32CcpSts=%u\n", rc, u32CcpSts);
                if (u32CcpSts != CCP_V5_STATUS_SUCCESS)
                    rc = STS_ERR_GENERAL_ERROR;
            }
            else
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                        "pspEmuProxyCcpAesDo() Copying IV over failed with %d\n", rc);

            PSPProxyCtxScratchSpaceFree(pThis->hPspProxyCtx, PspAddrIv, cbIv);
        }
        else
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyCcpAesDo() Allocating scratch space for IV failed with %d\n", rc);
#else
        return STS_ERR_GENERAL_ERROR;
#endif
    }

    if (!rc)
    {
        PSPPADDR PspAddrSrc = 0;
        PSPPADDR PspAddrDst = 0;

        /* Now do the real AES operation. Start by copying over the source data. */
        rc = PSPProxyCtxScratchSpaceAlloc(pThis->hPspProxyCtx, cbSrc, &PspAddrDst);
        if (!rc)
            rc = PSPProxyCtxScratchSpaceAlloc(pThis->hPspProxyCtx, cbSrc, &PspAddrSrc);
        if (!rc)
        {
            rc = PSPProxyCtxPspMemWrite(pThis->hPspProxyCtx, PspAddrSrc, pvSrc, cbSrc);
            if (!rc)
            {
                /* Prepare request and execute it. */
                CCP5REQ CcpReq;

                CcpReq.u32Dw0                   = u32Dw0;
                CcpReq.cbSrc                    = cbSrc;
                CcpReq.u32AddrSrcLow            = PspAddrSrc;
                CcpReq.u16AddrSrcHigh           = 0;
                CcpReq.u16SrcMemType            = CCP_V5_MEM_TYPE_LOCAL; /** @todo Give IV LSB ID when implemented. */
                CcpReq.Op.NonSha.u32AddrDstLow  = PspAddrDst;
                CcpReq.Op.NonSha.u16AddrDstHigh = 0;
                CcpReq.Op.NonSha.u16DstMemType  = CCP_V5_MEM_TYPE_LOCAL;
                CcpReq.u32AddrKeyLow            = uKeyLsb;
                CcpReq.u16AddrKeyHigh           = 0;
                CcpReq.u16KeyMemType            = CCP_V5_MEM_TYPE_SB;
                rc = pspEmuProxyCcpReqExec(pThis, &CcpReq, pu32CcpSts);
                if (!rc)
                {
                    /* Copy the data back. */
                    rc = PSPProxyCtxPspMemRead(pThis->hPspProxyCtx, PspAddrDst, pvDst, cbSrc);
                    if (rc)
                        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                                "pspEmuProxyCcpAesDo() Reading destination data back failed with %d\n", rc);
                }
                else
                {
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                            "pspEmuProxyCcpAesDo() Executing AES request failed with rc=%d\n", rc);
                }
            }
            else
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                        "pspEmuProxyCcpAesDo() Copying source data over failed with %d\n", rc);

            PSPProxyCtxScratchSpaceFree(pThis->hPspProxyCtx, PspAddrDst, cbSrc);
            PSPProxyCtxScratchSpaceFree(pThis->hPspProxyCtx, PspAddrSrc, cbSrc);
        }
        else
        {
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                    "pspEmuProxyCcpAesDo() Allocating scratch space for source or destination failed with %d\n", rc);

            if (PspAddrDst)
                PSPProxyCtxScratchSpaceFree(pThis->hPspProxyCtx, PspAddrDst, cbSrc);
        }
    }

    return rc;
}


/**
 * MMIO tracepoint callback for writing to the I/O log.
 */
static void pspProxyMemWtPspTrace(PSPADDR offMmioAbs, const char *pszDevId, PSPADDR offMmioDev, size_t cbAccess,
                                  const void *pvVal, uint32_t fFlags, void *pvUser)
{
    (void)pszDevId;
    (void)offMmioDev;

    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    /* This doesn't go through the blacklist checking as we assume the user knows what he did when creating the write through regions... */
    int rc = STS_INF_SUCCESS;
    if (   cbAccess == 1
        || cbAccess == 2
        || cbAccess == 4) /* Even it is not MMIO writing memory that way doesn't hurt and every other access must be memory like. */
        rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, offMmioAbs, cbAccess, pvVal);
    else
        rc = PSPProxyCtxPspMemWrite(pThis->hPspProxyCtx, offMmioAbs, pvVal, cbAccess);
    if (STS_FAILURE(rc))
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                "pspProxyMemWtPspTrace() failed with %d", rc);
}


/**
 * SMN tracepoint callback for writing to the I/O log.
 */
static void pspProxyMemWtSmnTrace(SMNADDR offSmnAbs, const char *pszDevId, SMNADDR offSmnDev, size_t cbAccess,
                                  const void *pvVal, uint32_t fFlags, void *pvUser)
{
    (void)pszDevId;
    (void)offSmnDev;

    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    /* This doesn't go through the blacklist checking as we assume the user knows what he did when creating the write through regions... */
    int rc = PSPProxyCtxPspSmnWrite(pThis->hPspProxyCtx, 0 /*idCcdTgt*/, offSmnAbs, cbAccess, pvVal);
    if (STS_FAILURE(rc))
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                "pspProxyMemWtSmnTrace() failed with %d", rc);
}


/**
 * X86 tracepoint callback for writing to the I/O log.
 */
static void pspProxyMemWtX86Trace(X86PADDR offX86Abs, const char *pszDevId, X86PADDR offX86Dev, size_t cbAccess,
                                  const void *pvVal, uint32_t fFlags, void *pvUser)
{
    (void)pszDevId;
    (void)offX86Dev;

    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)pvUser;
    PPSPPROXYINT pThis = pCcdRec->pThis;

    /* This doesn't go through the blacklist checking as we assume the user knows what he did when creating the write through regions... */
    int rc = STS_INF_SUCCESS;
    if (   cbAccess == 1
        || cbAccess == 2
        || cbAccess == 4) /* Even it is not MMIO writing memory that way doesn't hurt and every other access must be memory like. */
        rc = PSPProxyCtxPspX86MmioWrite(pThis->hPspProxyCtx, offX86Abs, cbAccess, pvVal);
    else
        rc = PSPProxyCtxPspX86MemWrite(pThis->hPspProxyCtx, offX86Abs, pvVal, cbAccess);
    if (STS_FAILURE(rc))
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_PROXY,
                                "pspProxyMemWtX86Trace() failed with %d", rc);
}


/**
 * Registers configured write through regions with the given I/O manager.
 *
 * @returns Status code.
 * @param   pCcdRec                 The CCD record the I/O manager belongs to.
 * @param   hIoMgr                  The I/O manager handle to register the regions with.
 * @param   paProxyMemWt            The array of write through regions to configure.
 * @param   cProxyMemWt             Number of write through regions to configure.
 */
static int pspProxyCcdMemWriteThroughRegister(PPSPPROXYCCD pCcdRec, PSPIOM hIoMgr, PCPSPEMUCFGPROXYMEMWT paProxyMemWt, uint32_t cProxyMemWt)
{
    int rc = STS_INF_SUCCESS;

    pCcdRec->cIoTpWt = cProxyMemWt;

    for (uint32_t i = 0; (i < cProxyMemWt) && STS_SUCCESS(rc); i++)
    {
         uint32_t fTpFlags = PSPEMU_IOM_TRACE_F_WRITE | PSPEMU_IOM_TRACE_F_AFTER;
        PCPSPEMUCFGPROXYMEMWT pMemWt = &paProxyMemWt[i];

        switch (pMemWt->enmAddrSpace)
        {
            case PSPADDRSPACE_PSP:
            case PSPADDRSPACE_PSP_MEM:
            case PSPADDRSPACE_PSP_MMIO:
            {
                /** @todo SRAM tracepoints could kill the proxy stub on the real PSP so we don't do them for now
                 * (they will not trigger). */
                rc = PSPEmuIoMgrMmioTraceRegister(hIoMgr, pMemWt->u.PspAddr, pMemWt->u.PspAddr + pMemWt->cbRegion - 1,
                                                  0 /*cbAccess*/, fTpFlags, pspProxyMemWtPspTrace, pCcdRec,
                                                  &pCcdRec->ahIoTpWt[i]);
                break;
            }
            case PSPADDRSPACE_SMN:
            {
                rc = PSPEmuIoMgrSmnTraceRegister(hIoMgr, pMemWt->u.SmnAddr, pMemWt->u.SmnAddr + pMemWt->cbRegion - 1,
                                                 0 /*cbAccess*/, fTpFlags, pspProxyMemWtSmnTrace, pCcdRec,
                                                 &pCcdRec->ahIoTpWt[i]);
                break;
            }
            case PSPADDRSPACE_X86:
            case PSPADDRSPACE_X86_MEM:
            case PSPADDRSPACE_X86_MMIO:
            {
                rc = PSPEmuIoMgrX86TraceRegister(hIoMgr, pMemWt->u.PhysX86Addr, pMemWt->u.PhysX86Addr + pMemWt->cbRegion - 1,
                                                 0 /*cbAccess*/, fTpFlags, pspProxyMemWtX86Trace, pCcdRec,
                                                 &pCcdRec->ahIoTpWt[i]);
                break;
            }
        }
    }

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


/**
 * @copydoc{DBGHLPCMD,pfnCmd}
 */
static int pspProxyDbgCmdMmioRead(PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPPROXYINT pThis = (PPSPPROXYINT)pvUser;

    const char *pszAddr = pszArgs;
    const char *pszSz   = pszArgs ? strchr(pszAddr, ' ') : NULL;

    if (   pszAddr
        && pszSz)
    {
        /* Get past the space. */
        pszSz++;

        char *pszAddrEnd = NULL;
        PSPPADDR MmioAddr = strtoul(pszAddr, &pszAddrEnd, 0 /*base*/);
        if (   pszAddrEnd != pszAddr
            && *pszAddrEnd == ' ')
        {
            if (   pszSz[1] == '\0'
                && (   pszSz[0] == '1'
                    || pszSz[0] == '2'
                    || pszSz[0] == '4'))
            {
                size_t cbRead = (size_t)(pszSz[0] - '0');
                PSPDATUM Datum;
                int rc = PSPProxyCtxPspMmioRead(pThis->hPspProxyCtx, MmioAddr, cbRead, &Datum.ab[0]);
                if (STS_SUCCESS(rc))
                {
                    uint32_t u32Val;

                    switch (cbRead)
                    {
                        case 1:
                            u32Val = Datum.u8;
                            break;
                        case 2:
                            u32Val = Datum.u16;
                            break;
                        case 4:
                            u32Val = Datum.u32;
                            break;
                        default:
                            pHlp->pfnPrintf(pHlp, "Something is really buggy here cbRead=%zu!\n", cbRead);
                    }

                    pHlp->pfnPrintf(pHlp, "MMIO %#x %zu: %#x\n", MmioAddr, cbRead, u32Val);
                }
                else
                    pHlp->pfnPrintf(pHlp, "Reading %zu bytes from MMIO address %#x failed with %d\n", cbRead, MmioAddr, rc);
            }
            else
                pHlp->pfnPrintf(pHlp, "Size parameter is invalid, must be 1, 2 or 4\n");
        }
        else
            pHlp->pfnPrintf(pHlp, "Address parameter is invalid\n");
    }
    else
        pHlp->pfnPrintf(pHlp, "Invalid number of arguments, command takes exactly two: <addr> <sz>\n");

    return STS_INF_SUCCESS;
}


/**
 * @copydoc{DBGHLPCMD,pfnCmd}
 */
static int pspProxyDbgCmdMmioWrite(PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPPROXYINT pThis = (PPSPPROXYINT)pvUser;

    const char *pszAddr = pszArgs;
    const char *pszSz   = pszArgs ? strchr(pszAddr,   ' ') : NULL;
    const char *pszVal  = pszSz   ? strchr(pszSz + 1, ' ') : NULL;

    if (   pszAddr
        && pszSz
        && pszVal)
    {
        /* Get past the space. */
        pszSz++;
        pszVal++;

        char *pszTmpEnd = NULL;
        PSPPADDR MmioAddr = strtoul(pszAddr, &pszTmpEnd, 0 /*base*/);
        if (   pszTmpEnd != pszAddr
            && *pszTmpEnd == ' ')
        {
            if (   pszSz[1] == ' '
                && (   pszSz[0] == '1'
                    || pszSz[0] == '2'
                    || pszSz[0] == '4'))
            {
                size_t cbWrite = (size_t)(pszSz[0] - '0');
                uint32_t u32Val = strtoul(pszVal, &pszTmpEnd, 0 /*base*/);;

                if (   pszTmpEnd != pszVal
                    && *pszTmpEnd == '\0')
                {
                    PSPDATUM Datum;

                    switch (cbWrite)
                    {
                        case 1:
                            Datum.u8 = (uint8_t)u32Val;
                            break;
                        case 2:
                            Datum.u16 = (uint16_t)u32Val;
                            break;
                        case 4:
                            Datum.u32 = (uint32_t)u32Val;
                            break;
                        default:
                            pHlp->pfnPrintf(pHlp, "Something is really buggy here cbWrite=%zu!\n", cbWrite);
                    }

                    int rc = PSPProxyCtxPspMmioWrite(pThis->hPspProxyCtx, MmioAddr, cbWrite, &Datum.ab[0]);
                    if (STS_SUCCESS(rc))
                        pHlp->pfnPrintf(pHlp, "MMIO %#x %zu: %#x\n", MmioAddr, cbWrite, u32Val);
                    else
                        pHlp->pfnPrintf(pHlp, "Writing %zu bytes to MMIO address %#x failed with %d\n", cbWrite, MmioAddr, rc);
                }
                else
                    pHlp->pfnPrintf(pHlp, "Value parameter is invalid: %s\n", pszVal);
            }
            else
                pHlp->pfnPrintf(pHlp, "Size parameter is invalid, must be 1, 2 or 4\n");
        }
        else
            pHlp->pfnPrintf(pHlp, "Address parameter is invalid\n");
    }
    else
        pHlp->pfnPrintf(pHlp, "Invalid number of arguments, command takes exactly two: <addr> <sz>\n");

    return STS_INF_SUCCESS;
}


/**
 * @copydoc{DBGHLPCMD,pfnCmd}
 */
static int pspProxyDbgCmdSmnRead(PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPPROXYINT pThis = (PPSPPROXYINT)pvUser;

    const char *pszAddr = pszArgs;
    const char *pszSz   = pszArgs ? strchr(pszAddr, ' ') : NULL;

    if (   pszAddr
        && pszSz)
    {
        /* Get past the space. */
        pszSz++;

        char *pszAddrEnd = NULL;
        SMNADDR SmnAddr = strtoul(pszAddr, &pszAddrEnd, 0 /*base*/);
        if (   pszAddrEnd != pszAddr
            && *pszAddrEnd == ' ')
        {
            if (   pszSz[1] == '\0'
                && (   pszSz[0] == '1'
                    || pszSz[0] == '2'
                    || pszSz[0] == '4'))
            {
                size_t cbRead = (size_t)(pszSz[0] - '0');
                PSPDATUM Datum;
                int rc = PSPProxyCtxPspSmnRead(pThis->hPspProxyCtx, 0 /*idCcdTgt*/, SmnAddr, cbRead, &Datum.ab[0]);
                if (STS_SUCCESS(rc))
                {
                    uint32_t u32Val;

                    switch (cbRead)
                    {
                        case 1:
                            u32Val = Datum.u8;
                            break;
                        case 2:
                            u32Val = Datum.u16;
                            break;
                        case 4:
                            u32Val = Datum.u32;
                            break;
                        default:
                            pHlp->pfnPrintf(pHlp, "Something is really buggy here cbRead=%zu!\n", cbRead);
                    }

                    pHlp->pfnPrintf(pHlp, "SMN %#x %zu: %#x\n", SmnAddr, cbRead, u32Val);
                }
                else
                    pHlp->pfnPrintf(pHlp, "Reading %zu bytes from SMN address %#x failed with %d\n", cbRead, SmnAddr, rc);
            }
            else
                pHlp->pfnPrintf(pHlp, "Size parameter is invalid, must be 1, 2 or 4\n");
        }
        else
            pHlp->pfnPrintf(pHlp, "Address parameter is invalid\n");
    }
    else
        pHlp->pfnPrintf(pHlp, "Invalid number of arguments, command takes exactly three: <addr> <sz> <val>\n");

    return STS_INF_SUCCESS;
}


/**
 * @copydoc{DBGHLPCMD,pfnCmd}
 */
static int pspProxyDbgCmdSmnWrite(PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPPROXYINT pThis = (PPSPPROXYINT)pvUser;

    const char *pszAddr = pszArgs;
    const char *pszSz   = pszArgs ? strchr(pszAddr,   ' ') : NULL;
    const char *pszVal  = pszSz   ? strchr(pszSz + 1, ' ') : NULL;

    if (   pszAddr
        && pszSz
        && pszVal)
    {
        /* Get past the space. */
        pszSz++;
        pszVal++;

        char *pszTmpEnd = NULL;
        SMNADDR SmnAddr = strtoul(pszAddr, &pszTmpEnd, 0 /*base*/);
        if (   pszTmpEnd != pszAddr
            && *pszTmpEnd == ' ')
        {
            if (   pszSz[1] == ' '
                && (   pszSz[0] == '1'
                    || pszSz[0] == '2'
                    || pszSz[0] == '4'))
            {
                size_t cbWrite = (size_t)(pszSz[0] - '0');
                uint32_t u32Val = strtoul(pszVal, &pszTmpEnd, 0 /*base*/);;

                if (   pszTmpEnd != pszVal
                    && *pszTmpEnd == '\0')
                {
                    PSPDATUM Datum;

                    switch (cbWrite)
                    {
                        case 1:
                            Datum.u8 = (uint8_t)u32Val;
                            break;
                        case 2:
                            Datum.u16 = (uint16_t)u32Val;
                            break;
                        case 4:
                            Datum.u32 = (uint32_t)u32Val;
                            break;
                        default:
                            pHlp->pfnPrintf(pHlp, "Something is really buggy here cbWrite=%zu!\n", cbWrite);
                    }

                    int rc = PSPProxyCtxPspSmnWrite(pThis->hPspProxyCtx, 0 /*idCcdTgt*/, SmnAddr, cbWrite, &Datum.ab[0]);
                    if (STS_SUCCESS(rc))
                        pHlp->pfnPrintf(pHlp, "SMN %#x %zu: %#x\n", SmnAddr, cbWrite, u32Val);
                    else
                        pHlp->pfnPrintf(pHlp, "Writing %zu bytes to SMN address %#x failed with %d\n", cbWrite, SmnAddr, rc);
                }
                else
                    pHlp->pfnPrintf(pHlp, "Value parameter is invalid: %s\n", pszVal);
            }
            else
                pHlp->pfnPrintf(pHlp, "Size parameter is invalid, must be 1, 2 or 4\n");
        }
        else
            pHlp->pfnPrintf(pHlp, "Address parameter is invalid\n");
    }
    else
        pHlp->pfnPrintf(pHlp, "Invalid number of arguments, command takes exactly three: <addr> <sz> <val>\n");

    return STS_INF_SUCCESS;
}


static int pspProxyDbgX86ReadWorker(PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser, bool fMmio)
{
    PPSPPROXYINT pThis = (PPSPPROXYINT)pvUser;

    const char *pszAddr = pszArgs;
    const char *pszSz   = pszArgs ? strchr(pszAddr, ' ') : NULL;

    if (   pszAddr
        && pszSz)
    {
        /* Get past the space. */
        pszSz++;

        char *pszAddrEnd = NULL;
        X86PADDR PhysX86Addr = strtoull(pszAddr, &pszAddrEnd, 0 /*base*/);
        if (   pszAddrEnd != pszAddr
            && *pszAddrEnd == ' ')
        {
            if (   pszSz[1] == '\0'
                && (   pszSz[0] == '1'
                    || pszSz[0] == '2'
                    || pszSz[0] == '4'
                    || pszSz[0] == '8'))
            {
                size_t cbRead = (size_t)(pszSz[0] - '0');
                PSPDATUM Datum;
                int rc;
                if (fMmio)
                    rc = PSPProxyCtxPspX86MmioRead(pThis->hPspProxyCtx, PhysX86Addr, cbRead, &Datum.ab[0]);
                else
                    rc = PSPProxyCtxPspX86MemRead(pThis->hPspProxyCtx, PhysX86Addr, &Datum.ab[0], cbRead);
                if (STS_SUCCESS(rc))
                {
                    uint64_t u64Val;

                    switch (cbRead)
                    {
                        case 1:
                            u64Val = Datum.u8;
                            break;
                        case 2:
                            u64Val = Datum.u16;
                            break;
                        case 4:
                            u64Val = Datum.u32;
                            break;
                        case 8:
                            u64Val = Datum.u64;
                            break;
                        default:
                            pHlp->pfnPrintf(pHlp, "Something is really buggy here cbRead=%zu!\n", cbRead);
                    }

                    pHlp->pfnPrintf(pHlp, "SMN %#llx %zu: %#llx\n", PhysX86Addr, cbRead, u64Val);
                }
                else
                    pHlp->pfnPrintf(pHlp, "Reading %zu bytes from x86 address %#llx failed with %d\n", cbRead, PhysX86Addr, rc);
            }
            else
                pHlp->pfnPrintf(pHlp, "Size parameter is invalid, must be 1, 2, 4 or 8\n");
        }
        else
            pHlp->pfnPrintf(pHlp, "Address parameter is invalid\n");
    }
    else
        pHlp->pfnPrintf(pHlp, "Invalid number of arguments, command takes exactly two: <addr> <sz>\n");

    return STS_INF_SUCCESS;
}


/**
 * @copydoc{DBGHLPCMD,pfnCmd}
 */
static int pspProxyDbgCmdX86MemRead(PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    return pspProxyDbgX86ReadWorker(hDbgHlp, pHlp, pszArgs, pvUser, false /*fMmio*/);
}


/**
 * @copydoc{DBGHLPCMD,pfnCmd}
 */
static int pspProxyDbgCmdX86MemWriteFile(PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPPROXYINT pThis = (PPSPPROXYINT)pvUser;

    const char *pszAddr = pszArgs;
    const char *pszFile = pszArgs ? strchr(pszAddr, ' ') : NULL;

    if (   pszAddr
        && pszFile)
    {
        /* Get past the space. */
        pszFile++;

        char *pszAddrEnd = NULL;
        X86PADDR PhysX86Addr = strtoull(pszAddr, &pszAddrEnd, 0 /*base*/);
        if (   pszAddrEnd != pszAddr
            && *pszAddrEnd == ' ')
        {
            void *pv = NULL;
            size_t cb = 0;
            int rc = PSPEmuFlashLoadFromFile(pszFile, &pv, &cb);
            if (STS_SUCCESS(rc))
            {
                rc = PSPProxyCtxPspX86MemWrite(pThis->hPspProxyCtx, PhysX86Addr, pv, cb);
                if (STS_FAILURE(rc))
                    pHlp->pfnPrintf(pHlp, "Writing file \"%s\" to memory at %#llx failed with %d\n", pszFile, PhysX86Addr, rc);

                free(pv);
            }
            else
                pHlp->pfnPrintf(pHlp, "Opening file \"%s\" failed with %d\n", pszFile, rc);
        }
        else
            pHlp->pfnPrintf(pHlp, "Address parameter is invalid\n");
    }
    else
        pHlp->pfnPrintf(pHlp, "Invalid number of arguments, command takes exactly two: <addr> <file>\n");

    return STS_INF_SUCCESS;
}


/**
 * @copydoc{DBGHLPCMD,pfnCmd}
 */
static int pspProxyDbgCmdX86MmioRead(PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    return pspProxyDbgX86ReadWorker(hDbgHlp, pHlp, pszArgs, pvUser, true /*fMmio*/);
}


/**
 * Arra of proxy related debugger commands registered with the debugger.
 */
static const DBGHLPCMD g_aProxyDbgCmds[] =
{
    { "proxy.MmioRead",         "Reads a value from the given MMIO address, arguments: <addr> <sz>",                     pspProxyDbgCmdMmioRead        },
    { "proxy.MmioWrite",        "Writes a value to the given MMIO address, arguments: <addr> <sz> <val>",                pspProxyDbgCmdMmioWrite       },
    { "proxy.SmnRead",          "Reads a value from the given SMN address, arguments: <addr> <sz>",                      pspProxyDbgCmdSmnRead         },
    { "proxy.SmnWrite",         "Writes a value to the given SMN address, arguments: <addr> <sz> <val>",                 pspProxyDbgCmdSmnWrite        },
    { "proxy.X86MemRead",       "Reads a value from the given x86 as a normal memory address, arguments: <addr> <sz>",   pspProxyDbgCmdX86MemRead      },
    { "proxy.X86MemWriteFile",  "Writes data from the given file to the destination address, arguments: <addr> <file>",  pspProxyDbgCmdX86MemWriteFile },
    { "proxy.X86MmioRead",      "Reads a value from the given x86 as MMIO address, arguments: <addr> <sz>",              pspProxyDbgCmdX86MmioRead     },
};


int PSPProxyCreate(PPSPPROXY phProxy, PPSPEMUCFG pCfg)
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
            if (pCfg->fCcpProxy)
            {
                /* Set up the CCP proxy instance data. */
                pThis->CcpProxy.pThis = pThis;
                pThis->CcpProxy.CcpProxyIf.pfnAesDo = pspEmuProxyCcpAesDo;
                pCfg->pCcpProxyIf = &pThis->CcpProxy.CcpProxyIf;
            }

            /* Register our custom commands. */
            PSPEmuDbgHlpCmdRegister(pCfg->hDbgHlp, g_aProxyDbgCmds, ELEMENTS(g_aProxyDbgCmds), pThis);

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
    int rc = STS_INF_SUCCESS;
    PPSPPROXYCCD pCcdRec = (PPSPPROXYCCD)calloc(1, sizeof(*pCcdRec) + pThis->pCfg->cProxyMemWt * sizeof(PSPIOMTP));
    if (pCcdRec)
    {
        PSPIOM hIoMgr;
        PSPCORE hPspCore;
        rc = PSPEmuCcdQueryIoMgr(hCcd, &hIoMgr);
        if (STS_SUCCESS(rc))
            rc = PSPEmuCcdQueryCore(hCcd, &hPspCore);
        if (STS_SUCCESS(rc))
        {
            /* Register the unassigned handlers for the various regions. */
            rc = PSPEmuIoMgrMmioUnassignedSet(hIoMgr, pspEmuProxyCcdPspMmioUnassignedRead, pspEmuProxyCcdPspMmioUnassignedWrite,
                                              "<PROXY>", pCcdRec);
            if (STS_SUCCESS(rc))
                rc = PSPEmuIoMgrSmnUnassignedSet(hIoMgr, pspEmuProxyCcdPspSmnUnassignedRead, pspEmuProxyCcdPspSmnUnassignedWrite,
                                                 "<PROXY>", pCcdRec);
            if (STS_SUCCESS(rc))
                rc = PSPEmuIoMgrX86UnassignedSet(hIoMgr, pspEmuProxyCcdX86UnassignedRead, pspEmuProxyCcdX86UnassignedWrite,
                                                 "<PROXY>", pCcdRec);
            if (STS_SUCCESS(rc))
                rc = PSPEmuCoreWfiSet(hPspCore, pspEmuProxyWfiReached, pCcdRec);

            /** @todo Only for primary CCD? */
            if (   STS_SUCCESS(rc)
                && pThis->pCfg->PspAddrProxyTrustedOsHandover)
                rc = PSPEmuCoreTraceRegister(hPspCore,
                                             pThis->pCfg->PspAddrProxyTrustedOsHandover,
                                             pThis->pCfg->PspAddrProxyTrustedOsHandover,
                                             PSPEMU_CORE_TRACE_F_EXEC, ARMASID_ANY,
                                             pspEmuProxyTrustedOsHandover, pThis,
                                             &pCcdRec->hTpSecureOsHandover);
            if (   STS_SUCCESS(rc)
                && pThis->pCfg->paProxyMemWt)
                rc = pspProxyCcdMemWriteThroughRegister(pCcdRec, hIoMgr, pThis->pCfg->paProxyMemWt, pThis->pCfg->cProxyMemWt);

            if (STS_SUCCESS(rc))
            {
                pCcdRec->pThis                  = pThis;
                pCcdRec->hCcd                   = hCcd;
                pCcdRec->ProxyAddr.enmAddrSpace = PSPPROXYADDRSPACE_INVALID;
                pCcdRec->offData                = 0;
                pCcdRec->enmTriAddrIncrByStride = PSPTERNARY_UNDECIDED;
                pCcdRec->enmTriMemset           = PSPTERNARY_UNDECIDED;
                pCcdRec->pNext                  = pThis->pCcdsHead;

                pThis->pCcdsHead = pCcdRec;
                return STS_INF_SUCCESS;
            }
        }

        free(pCcdRec);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


int PSPProxyCcdDeregister(PSPPROXY hProxy, PSPCCD hCcd)
{
    /** @todo */
    return STS_ERR_GENERAL_ERROR;
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

