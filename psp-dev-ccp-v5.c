/** @file
 * PSP Emulator - CCPv5 device.
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

/** @page pg_dev_ccp_v5   CCPv5 - Cryptographic Co-Processor version 5
 *
 * @todo Write something here.
 */


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* OpenSSL version 1.0.x support (see https://www.openssl.org/docs/man1.1.0/man3/EVP_MD_CTX_new.html#HISTORY) */
# if OPENSSL_VERSION_NUMBER < 0x10100000 // = OpenSSL 1.1.0
#  define EVP_MD_CTX_new EVP_MD_CTX_create
#  define EVP_MD_CTX_free EVP_MD_CTX_destroy
# endif

#include <zlib.h>

/* Missing in zlib.h */
# ifndef Z_DEF_WBITS
#  define Z_DEF_WBITS        MAX_WBITS
# endif

#include <common/cdefs.h>
#include <psp/ccp.h>

#include <psp-devs.h>
#include <psp-trace.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/** Address type the CCP uses (created from low and high parts). */
typedef uint64_t CCPADDR;
/** Create a CCP address from the given low and high parts. */
#define CCP_ADDR_CREATE_FROM_HI_LO(a_High, a_Low) (((CCPADDR)(a_High) << 32) | (a_Low))


/**
 * A single CCP queue.
 */
typedef struct CCPQUEUE
{
    /** Control register. */
    uint32_t                        u32RegCtrl;
    /** Request descriptor tail pointer. */
    uint32_t                        u32RegReqTail;
    /** Request descriptor head pointer. */
    uint32_t                        u32RegReqHead;
    /** Request status register. */
    uint32_t                        u32RegSts;
} CCPQUEUE;
/** Pointer to a single CCP queue. */
typedef CCPQUEUE *PCCPQUEUE;
/** Pointer to a single const CCP queue. */
typedef const CCPQUEUE *PCCCPQUEUE;


/**
 * A single local storage buffer.
 */
typedef struct CCPLSB
{
    /** View dependent data. */
    union
    {
        /** A single slot. */
        struct
        {
            /** 32byte data. */
            uint8_t                 abData[32];
        } aSlots[128];
        /* Contiguous view of the complete LSB. */
        uint8_t                     abLsb[1];
    } u;
} CCPLSB;
/** Pointer to a local storage buffer. */
typedef CCPLSB *PCCPLSB;
/** Pointer to a const local storage buffer. */
typedef const CCPLSB *PCCCPLSB;


/**
 * CCP device instance data.
 */
typedef struct PSPDEVCCP
{
    /** Pointer to device instance. */
    PPSPDEV                         pDev;
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE              hMmio;
    /** MMIO2 region handle. */
    PSPIOMREGIONHANDLE              hMmio2;
    /** The first CCP queue. */
    CCPQUEUE                        Queue1;
    /** The second CCP queue. */
    CCPQUEUE                        Queue2;
    /** The local storage buffer. */
    CCPLSB                          Lsb;
    /** The openssl SHA context currently in use. This doesn't really belong here
     * as the state is contained in an LSB but for use with openssl and to support
     * multi-part messages we have to store it here, luckily the PSP is single threaded
     * so the code will only every process one SHA operation at a time.
     */
    EVP_MD_CTX                      *pOsslShaCtx;
    /** The openssl AES context currently in use, same note as above applies. */
    EVP_CIPHER_CTX                  *pOsslAesCtx;
    /** The zlib decompression state. */
    z_stream                        Zlib;
    /** Size of the last transfer in bytes (written to local PSP memory). */
    size_t                          cbWrittenLast;
} PSPDEVCCP;
/** Pointer to the device instance data. */
typedef PSPDEVCCP *PPSPDEVCCP;


/**
 * Data transfer context.
 */
typedef struct CCPXFERCTX
{
    /** The read callback. */
    int    (*pfnRead) (PPSPDEVCCP pThis, CCPADDR CcpAddr, void *pvDst, size_t cbRead);
    /** The write callback. */
    int    (*pfnWrite) (PPSPDEVCCP pThis, CCPADDR CcpAddr, const void *pvSrc, size_t cbWrite);
    /** The CCP device instance the context is for. */
    PPSPDEVCCP                  pThis;
    /** Current source address. */
    CCPADDR                     CcpAddrSrc;
    /** Amount of data to read left. */
    size_t                      cbReadLeft;
    /** Current destination address. */
    CCPADDR                     CcpAddrDst;
    /** Amount of data to write left. */
    size_t                      cbWriteLeft;
    /** Flag whether to write in reverse order. */
    bool                        fWriteRev;
} CCPXFERCTX;
/** Pointer to an xfer context. */
typedef CCPXFERCTX *PCCPXFERCTX;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/


/**
 * Transfer data from system memory to a local buffer.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   CcpAddr             The address to read from (x86 physical address).
 * @param   pvDst               Where to store the read data.
 * @param   cbRead              How much to read.
 */
static int pspDevCcpXferMemSysRead(PPSPDEVCCP pThis, CCPADDR CcpAddr, void *pvDst, size_t cbRead)
{
    return -1;
}


/**
 * Transfer data from a local buffer to system memory.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   CcpAddr             The address to write to (x86 physical address).
 * @param   pvSrc               The data to write.
 * @param   cbWrite             How much to write.
 */
static int pspDevCcpXferMemSysWrite(PPSPDEVCCP pThis, CCPADDR CcpAddr, const void *pvSrc, size_t cbWrite)
{
    return -1;
}


/**
 * Transfer data from a local storage buffer to a local buffer.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   CcpAddr             The address to read from (LSB address).
 * @param   pvDst               Where to store the read data.
 * @param   cbRead              How much to read.
 */
static int pspDevCcpXferMemLsbRead(PPSPDEVCCP pThis, CCPADDR CcpAddr, void *pvDst, size_t cbRead)
{
    int rc = 0;

    if (   CcpAddr < sizeof(pThis->Lsb)
        && CcpAddr + cbRead <= sizeof(pThis->Lsb))
        memcpy(pvDst, &pThis->Lsb.u.abLsb[CcpAddr], cbRead);
    else
    {
        printf("CCP: Invalid LSB read offset=%#x cbRead=%zu\n", (uint32_t)CcpAddr, cbRead);
        rc = -1;
    }

    return rc;
}


/**
 * Transfer data from a local buffer to a local storage buffer.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   CcpAddr             The address to write to (LSB address).
 * @param   pvSrc               The data to write.
 * @param   cbWrite             How much to write.
 */
static int pspDevCcpXferMemLsbWrite(PPSPDEVCCP pThis, CCPADDR CcpAddr, const void *pvSrc, size_t cbWrite)
{
    int rc = 0;

    if (   CcpAddr < sizeof(pThis->Lsb)
        && CcpAddr + cbWrite <= sizeof(pThis->Lsb))
        memcpy(&pThis->Lsb.u.abLsb[CcpAddr], pvSrc, cbWrite);
    else
    {
        printf("CCP: Invalid LSB write offset=%#x cbWrite=%zu\n", (uint32_t)CcpAddr, cbWrite);
        rc = -1;
    }

    return rc;
}


/**
 * Transfer data from a local PSP memory address (SRAM,MMIO) to a local buffer.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   CcpAddr             The address to read from (PSP address).
 * @param   pvDst               Where to store the read data.
 * @param   cbRead              How much to read.
 */
static int pspDevCcpXferMemLocalRead(PPSPDEVCCP pThis, CCPADDR CcpAddr, void *pvDst, size_t cbRead)
{
    return PSPEmuIoMgrPspAddrRead(pThis->pDev->hIoMgr, (uint32_t)CcpAddr, pvDst, cbRead);
}


/**
 * Transfer data from a local buffer to a local PSP memory address (SRAM,MMIO).
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   CcpAddr             The address to write to (PSP address).
 * @param   pvSrc               The data to write.
 * @param   cbWrite             How much to write.
 */
static int pspDevCcpXferMemLocalWrite(PPSPDEVCCP pThis, CCPADDR CcpAddr, const void *pvSrc, size_t cbWrite)
{
    int rc = PSPEmuIoMgrPspAddrWrite(pThis->pDev->hIoMgr, (uint32_t)CcpAddr, pvSrc, cbWrite);
    if (!rc)
        pThis->cbWrittenLast += cbWrite;

    return rc;
}


/**
 * Initializes a data transfer context.
 *
 * @returns Status code.
 * @param   pCtx                The transfer context to initialize.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The CCP request to take memory types from.
 * @param   fSha                Flag whether this context is for the SHA engine.
 * @param   cbWrite             Amount of bytes to write in total.
 * @param   fWriteRev           Flag whether to write the data in reverse order.
 */
static int pspDevCcpXferCtxInit(PCCPXFERCTX pCtx, PPSPDEVCCP pThis, PCCCP5REQ pReq, bool fSha, size_t cbWrite,
                                bool fWriteRev)
{
    pThis->cbWrittenLast = 0;

    pCtx->pThis      = pThis;
    pCtx->CcpAddrSrc = CCP_ADDR_CREATE_FROM_HI_LO(pReq->u16AddrSrcHigh, pReq->u32AddrSrcLow);
    pCtx->cbReadLeft = pReq->cbSrc;
    pCtx->fWriteRev  = fWriteRev;
    switch (CCP_V5_MEM_TYPE_GET(pReq->u16SrcMemType))
    {
        case CCP_V5_MEM_TYPE_SYSTEM:
            pCtx->pfnRead = pspDevCcpXferMemSysRead;
            break;
        case CCP_V5_MEM_TYPE_SB:
            pCtx->pfnRead = pspDevCcpXferMemLsbRead;
            break;
        case CCP_V5_MEM_TYPE_LOCAL:
            pCtx->pfnRead = pspDevCcpXferMemLocalRead;
            break;
        default:
            return -1;
    }

    pCtx->cbWriteLeft = cbWrite;
    if (!fSha)
    {
        pCtx->CcpAddrDst = CCP_ADDR_CREATE_FROM_HI_LO(pReq->Op.NonSha.u16AddrDstHigh, pReq->Op.NonSha.u32AddrDstLow);
        switch (CCP_V5_MEM_TYPE_GET(pReq->Op.NonSha.u16DstMemType))
        {
            case CCP_V5_MEM_TYPE_SYSTEM:
                pCtx->pfnWrite = pspDevCcpXferMemSysWrite;
                break;
            case CCP_V5_MEM_TYPE_SB:
                pCtx->pfnWrite = pspDevCcpXferMemLsbWrite;
                break;
            case CCP_V5_MEM_TYPE_LOCAL:
                pCtx->pfnWrite = pspDevCcpXferMemLocalWrite;
                break;
            default:
                return -1;
        }
    }
    else /* SHA always writes to the LSB. */
    {
        uint8_t uLsbCtxId = CCP_V5_MEM_LSB_CTX_ID_GET(pReq->u16SrcMemType);
        if (uLsbCtxId < ELEMENTS(pThis->Lsb.u.aSlots))
        {
            pCtx->pfnWrite = pspDevCcpXferMemLsbWrite;
            pCtx->CcpAddrDst = uLsbCtxId * sizeof(pThis->Lsb.u.aSlots[0].abData);
        }
        else
            return -1;
    }

    if (pCtx->fWriteRev)
        pCtx->CcpAddrDst += pCtx->cbWriteLeft;

    return 0;
}


/**
 * Executes a read pass using the given transfer context.
 *
 * @returns Status code.
 * @param   pCtx                The transfer context to use.
 * @param   pvDst               Where to store the read data.
 * @param   cbRead              How much to read.
 * @param   pcbRead             Where to store the amount of data actually read, optional.
 */
static int pspDevCcpXferCtxRead(PCCPXFERCTX pCtx, void *pvDst, size_t cbRead, size_t *pcbRead)
{
    int rc = 0;
    size_t cbThisRead = MIN(cbRead, pCtx->cbReadLeft);

    if (    cbThisRead
        && (   pcbRead
            || cbThisRead == cbRead))
    {
        rc = pCtx->pfnRead(pCtx->pThis, pCtx->CcpAddrSrc, pvDst, cbThisRead);
        if (!rc)
        {
            pCtx->cbReadLeft -= cbThisRead;
            pCtx->CcpAddrSrc += cbThisRead;
            if (pcbRead)
                *pcbRead = cbThisRead;
        }
    }
    else
        rc = -1;

    return rc;
}


/**
 * Executes a write pass using the given transfer context.
 *
 * @returns Status code.
 * @param   pCtx                The transfer context to use.
 * @param   pvSrc               The data to write.
 * @param   cbWrite             How much to write.
 * @param   pcbWritten          Where to store the amount of data actually written, optional.
 */
static int pspDevCcpXferCtxWrite(PCCPXFERCTX pCtx, const void *pvSrc, size_t cbWrite, size_t *pcbWritten)
{
    int rc = 0;
    size_t cbThisWrite = MIN(cbWrite, pCtx->cbWriteLeft);

    if (    cbThisWrite
        && (   pcbWritten
            || cbThisWrite == cbWrite))
    {
        if (pCtx->fWriteRev)
        {
            const uint8_t *pbSrc = (const uint8_t *)pvSrc;

            /** @todo Unoptimized single byte writes... */
            while (   cbThisWrite
                   && !rc)
            {
                pCtx->CcpAddrDst--;
                rc = pCtx->pfnWrite(pCtx->pThis, pCtx->CcpAddrDst, pbSrc, 1);
                cbThisWrite--;
                pbSrc++;
            }

            if (   !rc
                && pcbWritten)
                *pcbWritten = cbThisWrite;
        }
        else
        {
            rc = pCtx->pfnWrite(pCtx->pThis, pCtx->CcpAddrDst, pvSrc, cbThisWrite);
            if (!rc)
            {
                pCtx->cbWriteLeft -= cbThisWrite;
                pCtx->CcpAddrDst  += cbThisWrite;
                if (pcbWritten)
                    *pcbWritten = cbThisWrite;
            }
        }
    }
    else
        rc = -1;

    return rc;
}


/**
 * Reverses the data in the given buffer.
 *
 * @returns nothing.
 * @param   pbBuf                   The buffer to reverse the data in.
 * @param   cbBuf                   Size of the buffer to reverse.
 */
static void pspDevCcpReverseBuf(uint8_t *pbBuf, size_t cbBuf)
{
    uint8_t *pbBufTop = pbBuf + cbBuf - 1;

    while (pbBuf < pbBufTop)
    {
        uint8_t bTmp = *pbBuf;
        *pbBuf = *pbBufTop;
        *pbBufTop = bTmp;
        pbBuf++;
        pbBufTop--;
    }
}


/**
 * Copies the key material pointed to by the request into a supplied buffer.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to get the key address from.
 * @param   cbKey               Size of the key buffer.
 * @param   pvKey               Where to store the key material.
 */
static int pspDevCcpKeyCopyFromReq(PPSPDEVCCP pThis, PCCCP5REQ pReq, size_t cbKey, void *pvKey)
{
    int rc = 0;

    if (CCP_V5_MEM_TYPE_GET(pReq->u16KeyMemType) == CCP_V5_MEM_TYPE_LOCAL)
    {
        CCPADDR CcpAddrKey = CCP_ADDR_CREATE_FROM_HI_LO(pReq->u16AddrKeyHigh, pReq->u32AddrKeyLow);
        rc = pspDevCcpXferMemLocalRead(pThis, CcpAddrKey, pvKey, cbKey);
    }
    else if (CCP_V5_MEM_TYPE_GET(pReq->u16KeyMemType) == CCP_V5_MEM_TYPE_SB)
    {
        CCPADDR CcpAddrKey = CCP_ADDR_CREATE_FROM_HI_LO(pReq->u16AddrKeyHigh, pReq->u32AddrKeyLow);
        if (   CcpAddrKey < sizeof(pThis->Lsb)
            && CcpAddrKey + cbKey <= sizeof(pThis->Lsb))
            memcpy(pvKey, &pThis->Lsb.u.abLsb[CcpAddrKey], cbKey);
        else
            rc = -1;
    }

    return rc;
}


/**
 * Copies data from an LSB into a supplied buffer.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   CcpAddrLsb          CCP LSB address to copy from.
 * @param   cb                  Amount of bytes to copy.
 * @param   pv                  Where to store the data.
 */
static int pspDevCcpCopyFromLsb(PPSPDEVCCP pThis, CCPADDR CcpAddrLsb, size_t cb, void *pv)
{
    int rc = 0;

    if (   CcpAddrLsb < sizeof(pThis->Lsb)
        && CcpAddrLsb + cb <= sizeof(pThis->Lsb))
        memcpy(pv, &pThis->Lsb.u.abLsb[CcpAddrLsb], cb);
    else
        rc = -1;

    return rc;
}


/**
 * Returns the string representation of the given CCP request engine field.
 *
 * @returns Engine description.
 * @param   uEngine                 The engine to convert to a stirng.
 */
static const char *pspDevCcpReqEngineToStr(uint32_t uEngine)
{
    switch (uEngine)
    {
        case CCP_V5_ENGINE_AES:
            return "AES";
        case CCP_V5_ENGINE_XTS_AES128:
            return "XTS_AES_128";
        case CCP_V5_ENGINE_DES3:
            return "DES3";
        case CCP_V5_ENGINE_SHA:
            return "SHA";
        case CCP_V5_ENGINE_RSA:
            return "RSA";
        case CCP_V5_ENGINE_PASSTHRU:
            return "PASSTHROUGH";
        case CCP_V5_ENGINE_ZLIB_DECOMP:
            return "ZLIB_DECOMPRESS";
        case CCP_V5_ENGINE_ECC:
            return "ECC";
    }

    return "<INVALID>";
}


/**
 * Extracts and dumps information about the given AES function.
 *
 * @returns nothing.
 * @param   pszBuf              The buffer to dump into.
 * @param   cbBuf               Size of the buffer in bytes.
 * @param   uFunc               The function part of dword 0.
 * @param   u32Dw0Raw           The raw dw0 value used for dumping.
 * @param   pszEngine           The used engine string.
 */
static void pspDevCcpReqDumpAesFunction(char *pszBuf, size_t cbBuf, uint32_t uFunc,
                                        uint32_t u32Dw0Raw, const char *pszEngine)
{
    uint8_t uSz      = CCP_V5_ENGINE_AES_SZ_GET(uFunc);
    uint8_t fEncrypt = CCP_V5_ENGINE_AES_ENCRYPT_GET(uFunc);
    uint8_t uMode    = CCP_V5_ENGINE_AES_MODE_GET(uFunc);
    uint8_t uAesType = CCP_V5_ENGINE_AES_TYPE_GET(uFunc);

    const char *pszMode    = "<INVALID>";
    const char *pszAesType = "<INVALID>";

    switch (uMode)
    {
        case CCP_V5_ENGINE_AES_MODE_ECB:
            pszMode = "ECB";
            break;
        case CCP_V5_ENGINE_AES_MODE_CBC:
            pszMode = "CBC";
            break;
        case CCP_V5_ENGINE_AES_MODE_OFB:
            pszMode = "OFB";
            break;
        case CCP_V5_ENGINE_AES_MODE_CFB:
            pszMode = "CFB";
            break;
        case CCP_V5_ENGINE_AES_MODE_CTR:
            pszMode = "CTR";
            break;
        case CCP_V5_ENGINE_AES_MODE_CMAC:
            pszMode = "CMAC";
            break;
        case CCP_V5_ENGINE_AES_MODE_GHASH:
            pszMode = "GHASH";
            break;
        case CCP_V5_ENGINE_AES_MODE_GCTR:
            pszMode = "GCTR";
            break;
        case CCP_V5_ENGINE_AES_MODE_GCM:
            pszMode = "GCM";
            break;
        case CCP_V5_ENGINE_AES_MODE_GMAC:
            pszMode = "GMAC";
            break;
    }

    switch (uAesType)
    {
        case CCP_V5_ENGINE_AES_TYPE_128:
            pszAesType = "AES128";
            break;
        case CCP_V5_ENGINE_AES_TYPE_192:
            pszAesType = "AES192";
            break;
        case CCP_V5_ENGINE_AES_TYPE_256:
            pszAesType = "AES256";
            break;
    }

    snprintf(pszBuf, cbBuf, "u32Dw0:             0x%08x (Engine: %s, AES Type: %s, Mode: %s, Encrypt: %u, Size: %u)",
                                                 u32Dw0Raw, pszEngine, pszAesType, pszMode, fEncrypt, uSz);
}


/**
 * Extracts and dumps information about the given SHA function.
 *
 * @returns nothing.
 * @param   pszBuf              The buffer to dump into.
 * @param   cbBuf               Size of the buffer in bytes.
 * @param   uFunc               The function part of dword 0.
 * @param   u32Dw0Raw           The raw dw0 value used for dumping.
 * @param   pszEngine           The used engine string.
 */
static void pspDevCcpReqDumpShaFunction(char *pszBuf, size_t cbBuf, uint32_t uFunc,
                                        uint32_t u32Dw0Raw, const char *pszEngine)
{
    uint32_t uShaType = CCP_V5_ENGINE_SHA_TYPE_GET(uFunc);
    const char *pszShaType = "<INVALID>";

    switch (uShaType)
    {
        case CCP_V5_ENGINE_SHA_TYPE_1:
            pszShaType = "SHA1";
            break;
        case CCP_V5_ENGINE_SHA_TYPE_224:
            pszShaType = "SHA224";
            break;
        case CCP_V5_ENGINE_SHA_TYPE_256:
            pszShaType = "SHA256";
            break;
        case CCP_V5_ENGINE_SHA_TYPE_384:
            pszShaType = "SHA384";
            break;
        case CCP_V5_ENGINE_SHA_TYPE_512:
            pszShaType = "SHA512";
            break;
    }

    snprintf(pszBuf, cbBuf, "u32Dw0:             0x%08x (Engine: %s, SHA type: %s)",
                                                 u32Dw0Raw, pszEngine, pszShaType);
}


/**
 * Extracts and dumps information about the given PASSTHRU function.
 *
 * @returns nothing.
 * @param   pszBuf              The buffer to dump into.
 * @param   cbBuf               Size of the buffer in bytes.
 * @param   uFunc               The function part of dword 0.
 * @param   u32Dw0Raw           The raw dw0 value used for dumping.
 * @param   pszEngine           The used engine string.
 */
static void pspDevCcpReqDumpPassthruFunction(char *pszBuf, size_t cbBuf, uint32_t uFunc,
                                             uint32_t u32Dw0Raw, const char *pszEngine)
{
    uint8_t uByteSwap = CCP_V5_ENGINE_PASSTHRU_BYTESWAP_GET(uFunc);
    uint8_t uBitwise  = CCP_V5_ENGINE_PASSTHRU_BITWISE_GET(uFunc);
    uint8_t uReflect  = CCP_V5_ENGINE_PASSTHRU_REFLECT_GET(uFunc);

    const char *pszByteSwap = "<INVALID>";
    const char *pszBitwise  = "<INVALID>";

    switch (uByteSwap)
    {
        case CCP_V5_ENGINE_PASSTHRU_BYTESWAP_NOOP:
            pszByteSwap = "NOOP";
            break;
        case CCP_V5_ENGINE_PASSTHRU_BYTESWAP_32BIT:
            pszByteSwap = "32BIT";
            break;
        case CCP_V5_ENGINE_PASSTHRU_BYTESWAP_256BIT:
            pszByteSwap = "256BIT";
            break;
    }

    switch (uBitwise)
    {
        case CCP_V5_ENGINE_PASSTHRU_BITWISE_NOOP:
            pszBitwise = "NOOP";
            break;
        case CCP_V5_ENGINE_PASSTHRU_BITWISE_AND:
            pszBitwise = "AND";
            break;
        case CCP_V5_ENGINE_PASSTHRU_BITWISE_OR:
            pszBitwise = "OR";
            break;
        case CCP_V5_ENGINE_PASSTHRU_BITWISE_XOR:
            pszBitwise = "XOR";
            break;
        case CCP_V5_ENGINE_PASSTHRU_BITWISE_MASK:
            pszBitwise = "MASK";
            break;
    }

    snprintf(pszBuf, cbBuf, "u32Dw0:             0x%08x (Engine: %s, ByteSwap: %s, Bitwise: %s, Reflect: %#x)",
                                                 u32Dw0Raw, pszEngine, pszByteSwap, pszBitwise, uReflect);
}


/**
 * Extracts and dumps information about the given RSA function.
 *
 * @returns nothing.
 * @param   pszBuf              The buffer to dump into.
 * @param   cbBuf               Size of the buffer in bytes.
 * @param   uFunc               The function part of dword 0.
 * @param   u32Dw0Raw           The raw dw0 value used for dumping.
 * @param   pszEngine           The used engine string.
 */
static void pspDevCcpReqDumpRsaFunction(char *pszBuf, size_t cbBuf, uint32_t uFunc,
                                        uint32_t u32Dw0Raw, const char *pszEngine)
{
    uint16_t uSz   = CCP_V5_ENGINE_RSA_SZ_GET(uFunc);
    uint8_t  uMode = CCP_V5_ENGINE_RSA_MODE_GET(uFunc);

    snprintf(pszBuf, cbBuf, "u32Dw0:             0x%08x (Engine: %s, Mode: %u, Size: %u)",
                                                 u32Dw0Raw, pszEngine, uMode, uSz);
}


/**
 * Dumps the CCP5 request descriptor.
 *
 * @returns nothing.
 * @param   pReq                The request to dump.
 */
static void pspDevCcpDumpReq(PCCCP5REQ pReq, PSPADDR PspAddrReq)
{
    uint32_t uEngine   = CCP_V5_ENGINE_GET(pReq->u32Dw0);
    uint32_t uFunction = CCP_V5_ENGINE_FUNC_GET(pReq->u32Dw0);
    const char *pszEngine   = pspDevCcpReqEngineToStr(uEngine);
    char szDw0[512];

    if (uEngine == CCP_V5_ENGINE_AES)
        pspDevCcpReqDumpAesFunction(&szDw0[0], sizeof(szDw0), uFunction, pReq->u32Dw0, pszEngine);
    else if (uEngine == CCP_V5_ENGINE_SHA)
        pspDevCcpReqDumpShaFunction(&szDw0[0], sizeof(szDw0), uFunction, pReq->u32Dw0, pszEngine);
    else if (uEngine == CCP_V5_ENGINE_PASSTHRU)
        pspDevCcpReqDumpPassthruFunction(&szDw0[0], sizeof(szDw0), uFunction, pReq->u32Dw0, pszEngine);
    else if (uEngine == CCP_V5_ENGINE_RSA)
        pspDevCcpReqDumpRsaFunction(&szDw0[0], sizeof(szDw0), uFunction, pReq->u32Dw0, pszEngine);
    else
        snprintf(&szDw0[0], sizeof(szDw0), "u32Dw0:             0x%08x (Engine: %s)",
                                                                pReq->u32Dw0, pszEngine);

    if (uEngine != CCP_V5_ENGINE_SHA)
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                "CCP Request 0x%08x:\n"
                                "    %s\n"
                                "    cbSrc:              %u\n"
                                "    u32AddrSrcLow:      0x%08x\n"
                                "    u16AddrSrcHigh:     0x%08x\n"
                                "    u16SrcMemType:      0x%08x (MemType: %u, LsbCtxId: %u, Fixed: %u)\n"
                                "    u32AddrDstLow:      0x%08x\n"
                                "    u16AddrDstHigh:     0x%08x\n"
                                "    u16DstMemType:      0x%08x (MemType: %u, Fixed: %u)\n"
                                "    u32AddrKeyLow:      0x%08x\n"
                                "    u16AddrKeyHigh:     0x%08x\n"
                                "    u16KeyMemType:      0x%08x\n",
                                PspAddrReq, &szDw0[0], pReq->cbSrc, pReq->u32AddrSrcLow, pReq->u16AddrSrcHigh,
                                pReq->u16SrcMemType, CCP_V5_MEM_TYPE_GET(pReq->u16SrcMemType),
                                CCP_V5_MEM_LSB_CTX_ID_GET(pReq->u16SrcMemType), CCP_V5_MEM_LSB_FIXED_GET(pReq->u16SrcMemType),
                                pReq->Op.NonSha.u32AddrDstLow, pReq->Op.NonSha.u16AddrDstHigh,
                                pReq->Op.NonSha.u16DstMemType, CCP_V5_MEM_TYPE_GET(pReq->Op.NonSha.u16DstMemType),
                                CCP_V5_MEM_LSB_FIXED_GET(pReq->Op.NonSha.u16DstMemType),
                                pReq->u32AddrKeyLow, pReq->u16AddrKeyHigh, pReq->u16KeyMemType);
    else
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                "CCP Request 0x%08x:\n"
                                "    %s\n"
                                "    cbSrc:              %u\n"
                                "    u32AddrSrcLow:      0x%08x\n"
                                "    u16AddrSrcHigh:     0x%08x\n"
                                "    u16SrcMemType:      0x%08x (MemType: %u, LsbCtxId: %u, Fixed: %u)\n"
                                "    u32ShaBitsLow:      0x%08x\n"
                                "    u32ShaBitsHigh:     0x%08x\n"
                                "    u32AddrKeyLow:      0x%08x\n"
                                "    u16AddrKeyHigh:     0x%08x\n"
                                "    u16KeyMemType:      0x%08x\n",
                                PspAddrReq, &szDw0[0], pReq->cbSrc, pReq->u32AddrSrcLow, pReq->u16AddrSrcHigh,
                                pReq->u16SrcMemType, CCP_V5_MEM_TYPE_GET(pReq->u16SrcMemType),
                                CCP_V5_MEM_LSB_CTX_ID_GET(pReq->u16SrcMemType), CCP_V5_MEM_LSB_FIXED_GET(pReq->u16SrcMemType),
                                pReq->Op.Sha.u32ShaBitsLow, pReq->Op.Sha.u32ShaBitsHigh,
                                pReq->u32AddrKeyLow, pReq->u16AddrKeyHigh, pReq->u16KeyMemType);
}


/**
 * Processes a passthru request.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to process.
 * @param   uFunc               The engine specific function.
 */
static int pspDevCcpReqPassthruProcess(PPSPDEVCCP pThis, PCCCP5REQ pReq, uint32_t uFunc)
{
    int rc = 0;
    uint8_t uByteSwap = CCP_V5_ENGINE_PASSTHRU_BYTESWAP_GET(uFunc);
    uint8_t uBitwise  = CCP_V5_ENGINE_PASSTHRU_BITWISE_GET(uFunc);
    uint8_t uReflect  = CCP_V5_ENGINE_PASSTHRU_REFLECT_GET(uFunc);

    if (   uBitwise == CCP_V5_ENGINE_PASSTHRU_BITWISE_NOOP
        && (   uByteSwap == CCP_V5_ENGINE_PASSTHRU_BYTESWAP_NOOP
            || (   uByteSwap == CCP_V5_ENGINE_PASSTHRU_BYTESWAP_256BIT
                && pReq->cbSrc == 32))
        && uReflect == 0)
    {
        size_t cbLeft = pReq->cbSrc;
        CCPXFERCTX XferCtx;

        rc = pspDevCcpXferCtxInit(&XferCtx, pThis, pReq, false /*fSha*/, cbLeft,
                                  uByteSwap == CCP_V5_ENGINE_PASSTHRU_BYTESWAP_256BIT ? true : false /*fWriteRev*/);
        if (!rc)
        {
            uint8_t abData[_4K];
            while (   !rc
                   && cbLeft)
            {
                size_t cbThisProc = MIN(cbLeft, sizeof(abData));

                rc = pspDevCcpXferCtxRead(&XferCtx, &abData[0], cbThisProc, NULL);
                if (!rc)
                    rc = pspDevCcpXferCtxWrite(&XferCtx, &abData[0], cbThisProc, NULL);

                cbLeft -= cbThisProc;
            }
        }
    }
    else
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_CCP,
                                "CCP: PASSTHRU ERROR uBitwise=%u, uByteSwap=%u and uReflect=%u not implemented yet!\n",
                                uBitwise, uByteSwap, uReflect);
        rc = -1;
    }

    return rc;
}


/**
 * Processes a SHA request.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to process.
 * @param   uFunc               The engine specific function.
 * @param   fInit               Flag whether to initialize the context state.
 * @param   fEom                Flag whether this request marks the end ofthe message.
 */
static int pspDevCcpReqShaProcess(PPSPDEVCCP pThis, PCCCP5REQ pReq, uint32_t uFunc,
                                  bool fInit, bool fEom)
{
    int rc = 0;
    uint32_t uShaType = CCP_V5_ENGINE_SHA_TYPE_GET(uFunc);

    /* Only sha256 implemented so far. */
    if (   uShaType == CCP_V5_ENGINE_SHA_TYPE_256
        || uShaType == CCP_V5_ENGINE_SHA_TYPE_384)
    {
        const EVP_MD *pOsslEvpSha = NULL;
        size_t cbLeft = pReq->cbSrc;
        size_t cbDigest = 0;
        CCPXFERCTX XferCtx;

        if (uShaType == CCP_V5_ENGINE_SHA_TYPE_256)
        {
            pOsslEvpSha = EVP_sha256();
            cbDigest = 32;
        }
        else
        {
            pOsslEvpSha = EVP_sha384();
            cbDigest = 48;
        }

         /*
          * The final SHA in the LSB seems to be in big endian format because it is always copied out
          * using the 256bit byteswap passthrough function. We will write it in reverse order here,
          * to avoid any hacks in the passthrough code.
          */
        rc = pspDevCcpXferCtxInit(&XferCtx, pThis, pReq, true /*fSha*/, EVP_MD_size(pOsslEvpSha),
                                  true /*fWriteRev*/);
        if (!rc)
        {
            /*
             * The storage buffer contains the initial sha256 state, which we will ignore
             * because that is already part of the openssl context.
             */
            if (fInit)
            {
                pThis->pOsslShaCtx = EVP_MD_CTX_new();
                if (!pThis->pOsslShaCtx)
                    rc = -1;
                else if (EVP_DigestInit_ex(pThis->pOsslShaCtx, pOsslEvpSha, NULL) != 1)
                    rc = -1;
            }

            while (   !rc
                   && cbLeft)
            {
                uint8_t abData[256];
                size_t cbThisProc = MIN(cbLeft, sizeof(abData));

                rc = pspDevCcpXferCtxRead(&XferCtx, &abData[0], cbThisProc, NULL);
                if (!rc)
                {
                    if (EVP_DigestUpdate(pThis->pOsslShaCtx, &abData[0], cbThisProc) != 1)
                        rc = -1;
                }

                cbLeft -= cbThisProc;
            }

            if (   !rc
                && fEom)
            {
                /* Finalize state and write to the storage buffer. */
                uint8_t *pbDigest = alloca(cbDigest);
                if (EVP_DigestFinal_ex(pThis->pOsslShaCtx, pbDigest, NULL) == 1)
                    rc = pspDevCcpXferCtxWrite(&XferCtx, pbDigest, cbDigest, NULL);
                else
                    rc = -1;

                EVP_MD_CTX_free(pThis->pOsslShaCtx);
                pThis->pOsslShaCtx = NULL;
            }
        }
    }
    else
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_CCP,
                                "CCP: SHA ERROR uShaType=%u fInit=%u fEom=%u u32ShaBitsHigh=%u u32ShaBitsLow=%u not implemented yet!\n",
                                uShaType, fInit, fEom, pReq->Op.Sha.u32ShaBitsHigh, pReq->Op.Sha.u32ShaBitsLow);
        rc = -1;
    }

    return rc;
}


/**
 * CCP AES passthrough operation.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to process.
 * @param   fUseIv              Flag whether the request uses an IV.
 */
static int pspDevCcpReqAesPassthrough(PPSPDEVCCP pThis, PCCCP5REQ pReq, bool fUseIv)
{
    int rc = 0;

    /*
     * Impose a limit on the amount of data to process for now, this should really be used
     * only for unwrapping the 128bit IKEK.
     */
    if (pReq->cbSrc <= _4K)
    {
        CCPXFERCTX XferCtx;
        uint8_t abSrc[_4K];
        uint8_t abDst[_4K];
        uint8_t abIv[128 / 8];
        uint8_t uLsbCtxId = CCP_V5_MEM_LSB_CTX_ID_GET(pReq->u16SrcMemType);
        CCPADDR CcpAddrIv = uLsbCtxId * sizeof(pThis->Lsb.u.aSlots[0].abData);
        CCPADDR CcpAddrKey = CCP_ADDR_CREATE_FROM_HI_LO(pReq->u16AddrKeyHigh, pReq->u32AddrKeyLow);
        uint32_t u32CcpSts;

        rc = pspDevCcpXferCtxInit(&XferCtx, pThis, pReq, false /*fSha*/, pReq->cbSrc,
                                  false /*fWriteRev*/);
        if (!rc && fUseIv)
            rc = pspDevCcpCopyFromLsb(pThis, CcpAddrIv, sizeof(abIv), &abIv[0]);
        if (!rc)
            rc = pspDevCcpXferCtxRead(&XferCtx, &abSrc[0], pReq->cbSrc, NULL);
        if (!rc)
            rc = pThis->pDev->pCfg->pCcpProxyIf->pfnAesDo(pThis->pDev->pCfg->pCcpProxyIf,
                                                          pReq->u32Dw0, pReq->cbSrc,
                                                          &abSrc[0], &abDst[0], (uint32_t)CcpAddrKey,
                                                          fUseIv ? &abIv[0] : NULL, fUseIv ? sizeof(abIv) : 0,
                                                          &u32CcpSts);
        if (!rc)
        {
            if ((u32CcpSts & 0x3f) == CCP_V5_STATUS_SUCCESS)
                rc = pspDevCcpXferCtxWrite(&XferCtx, &abDst[0], pReq->cbSrc, NULL);
            else
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: CCP returned status %#x!\n", u32CcpSts & 0x3f);
                rc = -1;
            }
        }
        else
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_CCP,
                                    "CCP: AES passthrough operation failed with %d!\n", rc);
    }
    else
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_CCP,
                                "CCP: AES passthrough with too much data %u!\n", pReq->cbSrc);
        rc = -1;
    }

    return rc;
}


/**
 * Processes a AES request.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to process.
 * @param   uFunc               The engine specific function.
 * @param   fInit               Flag whether to initialize the context state.
 * @param   fEom                Flag whether this request marks the end ofthe message.
 */
static int pspDevCcpReqAesProcess(PPSPDEVCCP pThis, PCCCP5REQ pReq, uint32_t uFunc,
                                  bool fInit, bool fEom)
{
    int     rc       = 0;
    uint8_t uSz      = CCP_V5_ENGINE_AES_SZ_GET(uFunc);
    uint8_t fEncrypt = CCP_V5_ENGINE_AES_ENCRYPT_GET(uFunc);
    uint8_t uMode    = CCP_V5_ENGINE_AES_MODE_GET(uFunc);
    uint8_t uAesType = CCP_V5_ENGINE_AES_TYPE_GET(uFunc);

    /* If the request uses a protected LSB and CCP passthrough is available we use the real CCP. */
    if (   CCP_V5_MEM_TYPE_GET(pReq->u16KeyMemType) == CCP_V5_MEM_TYPE_SB
        && CCP_ADDR_CREATE_FROM_HI_LO(pReq->u16AddrKeyHigh, pReq->u32AddrKeyLow) < 0xa0
        && pThis->pDev->pCfg->pCcpProxyIf)
        return pspDevCcpReqAesPassthrough(pThis, pReq, uMode == CCP_V5_ENGINE_AES_MODE_CBC ? true : false /*fUseIv*/);

    if (   uSz == 0
        && (   uMode == CCP_V5_ENGINE_AES_MODE_ECB
            || uMode == CCP_V5_ENGINE_AES_MODE_CBC)
        && (   uAesType == CCP_V5_ENGINE_AES_TYPE_256
            || uAesType == CCP_V5_ENGINE_AES_TYPE_128))
    {
        const EVP_CIPHER *pOsslEvpAes = NULL;
        size_t cbLeft = pReq->cbSrc;
        size_t cbKey = 0;
        bool fUseIv = false;
        CCPXFERCTX XferCtx;

        if (uAesType == CCP_V5_ENGINE_AES_TYPE_256)
        {
            cbKey = 256 / 8;

            if (uMode == CCP_V5_ENGINE_AES_MODE_ECB)
                pOsslEvpAes = EVP_aes_256_ecb();
            else if (uMode == CCP_V5_ENGINE_AES_MODE_CBC)
            {
                pOsslEvpAes = EVP_aes_256_cbc();
                fUseIv = true;
            }
            else
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_CCP, "CCP: Internal AES error");
                rc = -1;
            }

        }
        else if (uAesType == CCP_V5_ENGINE_AES_TYPE_128)
        {
            cbKey = 128 / 8;

            if (uMode == CCP_V5_ENGINE_AES_MODE_ECB)
                pOsslEvpAes = EVP_aes_128_ecb();
            else if (uMode == CCP_V5_ENGINE_AES_MODE_CBC)
            {
                pOsslEvpAes = EVP_aes_128_cbc();
                fUseIv = true;
            }
            else
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_CCP, "CCP: Internal AES error");
                rc = -1;
            }
        }
        else
        {
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_FATAL_ERROR, PSPTRACEEVTORIGIN_CCP, "CCP: Internal AES error");
            rc = -1;
        }

        if (!rc)
            rc = pspDevCcpXferCtxInit(&XferCtx, pThis, pReq, false /*fSha*/, pReq->cbSrc /**@todo Correct? */,
                                      false /*fWriteRev*/);
        if (!rc)
        {
            uint8_t abKey[256 / 8];
            uint8_t abIv[128 / 8];
            rc = pspDevCcpKeyCopyFromReq(pThis, pReq, cbKey, &abKey[0]);
            if (!rc) /* The key is given in reverse order (Linux kernel mentions big endian). */
                pspDevCcpReverseBuf(&abKey[0], cbKey);
            if (!rc && fUseIv)
            {
                /*
                 * The IV is always given in the LSB which ID is given in the source memory type.
                 * And we need to reverse the IV as well.
                 */
                uint8_t uLsbCtxId = CCP_V5_MEM_LSB_CTX_ID_GET(pReq->u16SrcMemType);
                CCPADDR CcpAddrIv = uLsbCtxId * sizeof(pThis->Lsb.u.aSlots[0].abData);

                rc = pspDevCcpCopyFromLsb(pThis, CcpAddrIv, sizeof(abIv), &abIv[0]);
                pspDevCcpReverseBuf(&abIv[0], sizeof(abIv));
            }
            if (!rc)
            {
                pThis->pOsslAesCtx = EVP_CIPHER_CTX_new();
                if (!pThis->pOsslAesCtx)
                    rc = -1;
                else if (fEncrypt)
                {
                    if (EVP_EncryptInit_ex(pThis->pOsslAesCtx, pOsslEvpAes, NULL, &abKey[0],
                                           fUseIv ? &abIv[0] : NULL) != 1)
                        rc = -1;
                }
                else
                {
                    if (EVP_DecryptInit_ex(pThis->pOsslAesCtx, pOsslEvpAes, NULL, &abKey[0],
                                           fUseIv ? &abIv[0] : NULL) != 1)
                        rc = -1;
                }

                if (EVP_CIPHER_CTX_set_padding(pThis->pOsslAesCtx, 0) != 1)
                    rc = -1;
            }

            while (   !rc
                   && cbLeft)
            {
                uint8_t abDataIn[512];
                uint8_t abDataOut[512];
                size_t cbThisProc = MIN(cbLeft, sizeof(abDataIn));
                int cbOut = 0;

                rc = pspDevCcpXferCtxRead(&XferCtx, &abDataIn[0], cbThisProc, NULL);
                if (!rc)
                {
                    if (fEncrypt)
                    {
                        if (EVP_EncryptUpdate(pThis->pOsslAesCtx, &abDataOut[0], &cbOut, &abDataIn[0], cbThisProc) != 1)
                            rc = -1;
                    }
                    else
                    {
                        if (EVP_DecryptUpdate(pThis->pOsslAesCtx, &abDataOut[0], &cbOut, &abDataIn[0], cbThisProc) != 1)
                            rc = -1;
                    }
                }

                if (   !rc
                    && cbOut)
                    rc = pspDevCcpXferCtxWrite(&XferCtx, &abDataOut[0], cbOut, NULL);

                cbLeft -= cbThisProc;
            }

            if (   !rc
                && fEom)
            {
                /* Finalize state. */
                uint8_t abDataOut[512];
                int cbOut = 0;

                if (fEncrypt)
                {
                    if (EVP_EncryptFinal_ex(pThis->pOsslAesCtx, &abDataOut[0], &cbOut) != 1)
                        rc = -1;
                }
                else
                {
                    if (EVP_DecryptFinal_ex(pThis->pOsslAesCtx, &abDataOut[0], &cbOut) != 1)
                        rc = -1;
                }

                if (   !rc
                    && cbOut)
                    rc = pspDevCcpXferCtxWrite(&XferCtx, &abDataOut[0], cbOut, NULL);

                EVP_CIPHER_CTX_free(pThis->pOsslAesCtx);
                pThis->pOsslAesCtx = NULL;
            }
        }
    }
    else
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_CCP,
                                "CCP: AES ERROR uAesType=%u uMode=%u fEncrypt=%u uSz=%u not implemented yet!\n",
                                uAesType, uMode, fEncrypt, uSz);
        rc = -1;
    }

    return rc;
}


/**
 * Processes a ZLIB decompression request.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to process.
 * @param   uFunc               The engine specific function.
 * @param   fInit               Flag whether to initialize the context state.
 * @param   fEom                Flag whether this request marks the end ofthe message.
 */
static int pspDevCcpReqZlibProcess(PPSPDEVCCP pThis, PCCCP5REQ pReq, uint32_t uFunc,
                                   bool fInit, bool fEom)
{
    (void)uFunc; /* Ignored */

    CCPXFERCTX XferCtx;
    int rc = pspDevCcpXferCtxInit(&XferCtx, pThis, pReq, false /*fSha*/, UINT32_MAX,
                                  false /*fWriteRev*/);
    if (!rc)
    {
        size_t cbReadLeft = pReq->cbSrc;

        if (fInit)
        {
            memset(&pThis->Zlib, 0, sizeof(pThis->Zlib));
            int rcZlib = inflateInit2(&pThis->Zlib, Z_DEF_WBITS);
            if (rcZlib < 0)
                rc = -1;
        }

        uint8_t abDecomp[_4K];
        uint32_t offDecomp = 0;
        memset(&abDecomp[0], 0, sizeof(abDecomp));

        while (   !rc
               && cbReadLeft)
        {
            uint8_t abData[_4K];
            size_t cbThisRead = MIN(cbReadLeft, sizeof(abData));

            rc = pspDevCcpXferCtxRead(&XferCtx, &abData[0], cbThisRead, NULL);
            if (!rc)
            {
                pThis->Zlib.avail_in = cbThisRead;
                pThis->Zlib.next_in  = &abData[0];

                while (   pThis->Zlib.avail_in
                       && !rc)
                {
                    size_t cbDecompLeft = sizeof(abDecomp) - offDecomp;

                    pThis->Zlib.next_out  = (Bytef *)&abDecomp[offDecomp];
                    pThis->Zlib.avail_out = cbDecompLeft;

                    int rcZlib = inflate(&pThis->Zlib, Z_NO_FLUSH);
                    if (pThis->Zlib.avail_out < cbDecompLeft)
                    {
                        offDecomp += cbDecompLeft - pThis->Zlib.avail_out;
                        /* Write the chunk if the decompression buffer is full. */
                        if (offDecomp == sizeof(abDecomp))
                        {
                            rc = pspDevCcpXferCtxWrite(&XferCtx, &abDecomp[0], sizeof(abDecomp), NULL);
                            offDecomp = 0; /* Off to the next round. */
                        }
                    }
                    if (   !rc
                        && rcZlib == Z_STREAM_END)
                        break;
                }
            }

            cbReadLeft -= cbThisRead;
        }

        /* Write the last chunk. */
        if (   !rc
            && offDecomp)
            rc = pspDevCcpXferCtxWrite(&XferCtx, &abDecomp[0], offDecomp, NULL);

        if (fEom)
        {
            int rcZlib = inflateEnd(&pThis->Zlib);
            if (   rcZlib < 0
                && !rc)
                rc = -1;
        }
    }

    return rc;
}


/**
 * Processes a RSA request.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to process.
 * @param   uFunc               The engine specific function.
 * @param   fInit               Flag whether to initialize the context state.
 * @param   fEom                Flag whether this request marks the end ofthe message.
 */
static int pspDevCcpReqRsaProcess(PPSPDEVCCP pThis, PCCCP5REQ pReq, uint32_t uFunc,
                                  bool fInit, bool fEom)
{
    int      rc    = 0;
    uint16_t uSz   = CCP_V5_ENGINE_RSA_SZ_GET(uFunc);
    uint8_t  uMode = CCP_V5_ENGINE_RSA_MODE_GET(uFunc);

    /* Support RSA 2048 and 4096 */
    if (   uMode == 0
        && (   (   uSz == 256
                && pReq->cbSrc == 512)
            || (   uSz == 512
                && pReq->cbSrc == 1024)))
    {
        /* The key contains the exponent as a 2048bit or 4096bit integer. */
        uint8_t abExp[512];
        rc = pspDevCcpKeyCopyFromReq(pThis, pReq, uSz, &abExp[0]);
        if (!rc)
        {
            bool fFreeBignums = true;
            BIGNUM *pExp = BN_lebin2bn(&abExp[0], uSz / 2, NULL);
            RSA *pRsaPubKey = RSA_new();
            if (pExp && pRsaPubKey)
            {
                CCPXFERCTX XferCtx;
                rc = pspDevCcpXferCtxInit(&XferCtx, pThis, pReq, false /*fSha*/, uSz,
                                          false /*fWriteRev*/);
                if (!rc)
                {
                    /*
                     * The source buffer contains the modulus as a 2048bit integer in little endian format
                     * followed by the message the process (why the modulus is not part of the key buffer
                     * remains a mystery).
                     */
                    uint8_t abData[1024];

                    rc = pspDevCcpXferCtxRead(&XferCtx, &abData[0], pReq->cbSrc, NULL);
                    if (!rc)
                    {
                        BIGNUM *pMod = BN_lebin2bn(&abData[0], pReq->cbSrc / 2, NULL);
                        if (pMod)
                        {
                            uint8_t abResult[512];

                            RSA_set0_key(pRsaPubKey, pMod, pExp, NULL);

                            /* The RSA public key structure has taken over the memory and freeing it will free the exponent and modulus as well. */
                            fFreeBignums = false;

                            /* Need to convert to little endian format. */
                            pspDevCcpReverseBuf(&abData[uSz], pReq->cbSrc / 2);
                            size_t cbEnc = RSA_public_encrypt(pReq->cbSrc / 2, &abData[uSz], &abResult[0], pRsaPubKey, RSA_NO_PADDING);
                            if (cbEnc == uSz)
                            {
                                /* Need to swap endianess of result buffer as well. */
                                pspDevCcpReverseBuf(&abResult[0], uSz);
                                rc = pspDevCcpXferCtxWrite(&XferCtx, &abResult[0], uSz, NULL);
                            }
                            else
                                rc = -1;

                            if (fFreeBignums)
                                BN_clear_free(pMod);
                        }
                        else
                            rc = -1;
                    }
                }
            }
            else
                rc = -1;

            if (pRsaPubKey)
                RSA_free(pRsaPubKey);
            if (fFreeBignums && pExp)
                BN_clear_free(pExp);
        }
    }
    else
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_CCP,
                                "CCP: RSA ERROR uMode=%u uSz=%u not implemented yet!\n",
                                uMode, uSz);
        rc = -1;
    }

    return rc;
}


/**
 * Processes an ECC request.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to process.
 * @param   uFunc               The engine specific function.
 * @param   fInit               Flag whether to initialize the context state.
 * @param   fEom                Flag whether this request marks the end of the message.
 */
static int pspDevCcpReqEccProcess(PPSPDEVCCP pThis, PCCCP5REQ pReq, uint32_t uFunc,
                                  bool fInit, bool fEom)
{
    int      rc    = 0;
    uint16_t uBits = CCP_V5_ENGINE_ECC_BIT_COUNT_GET(uFunc);
    uint8_t  uOp   = CCP_V5_ENGINE_ECC_OP_GET(uFunc);

    /* Check bit count (we have 0x48 bytes, or 576 bits) */
    if (uBits <= 576)
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_CCP,
            "CCP: ECC with %u bits\n", uBits);

        /** @todo */
        switch (uOp)
        {
            case CCP_V5_ENGINE_ECC_OP_MUL_FIELD:
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: ECC operation MUL (field) not implemented!\n"
                                        );
                break;
            }
            case CCP_V5_ENGINE_ECC_OP_ADD_FIELD:
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: ECC operation ADD (field) not implemented!\n"
                                        );
                break;
            }
            case CCP_V5_ENGINE_ECC_OP_INV_FIELD:
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: ECC operation INV (field) not implemented!\n"
                                        );
                break;
            }
            case CCP_V5_ENGINE_ECC_OP_ADD_CURVE:
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: ECC operation ADD (curve) not implemented!\n"
                                        );
                break;
            }
            case CCP_V5_ENGINE_ECC_OP_MUL_CURVE:
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: ECC operation MUL (curve) not implemented!\n"
                                        );
                break;
            }
            case CCP_V5_ENGINE_ECC_OP_DOUBLE_CURVE:
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: ECC operation DOUBLE (curve) not implemented!\n"
                                        );
                break;
            }
            case CCP_V5_ENGINE_ECC_OP_MUL_ADD_CURVE:
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: ECC operation MUL_ADD (curve) not implemented!\n"
                                        );
                break;
            }
            default:
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_CCP,
                                        "CCP: ECC ERROR uOp=%u not implemented!\n",
                                        uOp);
                rc = -1;
            }
        }
    }
    else
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_CCP,
                                "CCP: ECC ERROR uBits=%u is too large!\n",
                                uBits);
        rc = -1;
    }

    return rc;
}


/**
 * Processes the given request.
 *
 * @returns Status code.
 * @param   pThis               The CCP device instance data.
 * @param   pReq                The request to process.
 */
static int pspDevCcpReqProcess(PPSPDEVCCP pThis, PCCCP5REQ pReq)
{
    int rc = 0;
    uint32_t uEngine   = CCP_V5_ENGINE_GET(pReq->u32Dw0);
    uint32_t uFunction = CCP_V5_ENGINE_FUNC_GET(pReq->u32Dw0);
    bool     fInit     = CCP_V5_ENGINE_INIT_GET(pReq->u32Dw0);
    bool     fEom      = CCP_V5_ENGINE_EOM_GET(pReq->u32Dw0);

    switch (uEngine)
    {
        case CCP_V5_ENGINE_PASSTHRU:
        {
            rc = pspDevCcpReqPassthruProcess(pThis, pReq, uFunction);
            break;
        }
        case CCP_V5_ENGINE_SHA:
        {
            rc = pspDevCcpReqShaProcess(pThis, pReq, uFunction, fInit, fEom);
            break;
        }
        case CCP_V5_ENGINE_AES:
        {
            rc = pspDevCcpReqAesProcess(pThis, pReq, uFunction, fInit, fEom);
            break;
        }
        case CCP_V5_ENGINE_ZLIB_DECOMP:
        {
            rc = pspDevCcpReqZlibProcess(pThis, pReq, uFunction, fInit, fEom);
            break;
        }
        case CCP_V5_ENGINE_RSA:
        {
            rc = pspDevCcpReqRsaProcess(pThis, pReq, uFunction, fInit, fEom);
            break;
        }
        case CCP_V5_ENGINE_XTS_AES128:
        case CCP_V5_ENGINE_DES3:
            /** @todo */
            break;
        case CCP_V5_ENGINE_ECC:
            rc = pspDevCcpReqEccProcess(pThis, pReq, uFunction, fInit, fEom);
            break;
        default:
            rc = -1;
    }

    return rc;
}


/**
 * Handles register read from a specific queue.
 *
 * @returns nothing.
 * @param   pThis               The CCP device instance data.
 * @param   pQueue              The queue to read a register from.
 * @param   offRegQ             The register offset to read from.
 * @param   pu32Dst             Whereto store the register content.
 */
static void pspDevCcpMmioQueueRegRead(PPSPDEVCCP pThis, PCCPQUEUE pQueue, uint32_t offRegQ, uint32_t *pu32Dst)
{
    /*
     * This used to be in the write handler where it would make probably more sense
     * but this caused a fatal stack overwrite during the last CCP request of the on chip bootloader
     * to presumably overwrite some scratch buffer with data. The request is triggered by the
     * function at address 0xffff48c8 in our on chip bootloader version from a 1st gen Epyc CPU.
     *
     * The request looks like the following:
     * CCP Request 0x0003f900:
     *     u32Dw0:             0x00500011 (Engine: PASSTHROUGH, ByteSwap: NOOP, Bitwise: NOOP, Reflect: 0)
     *     cbSrc:              27160
     *     u32AddrSrcLow:      0x00000000
     *     u16AddrSrcHigh:     0x00000000
     *     u16SrcMemType:      0x000001d2 (MemType: 2, LsbCtxId: 116, Fixed: 0)
     *     u32AddrDstLow:      0x00038500
     *     u16AddrDstHigh:     0x00000000
     *     u16DstMemType:      0x00000002 (MemType: 2, Fixed: 0)
     *     u32AddrKeyLow:      0x00000000
     *     u16AddrKeyHigh:     0x00000000
     *     u16KeyMemType:      0x00000000
     *
     * The CCP writes 27160 bytes starting at 0x38500 which spills into the stack of the on chip bootloader
     * ranging from 0x3efff down to 0x3ef00. This will overwrite the stack return address of the on_chip_bl_ccp_start_cmd()
     * function at 0xffff7878 with an invalid value causing a CPU exception.
     *
     * The only reason this doesn't blows up on real hardware is the asynchronous nature of the CCP. When the request is started
     * the ARM core will execute the return instruction before the CCP can trash the stack frame and leave the dangerous zone.
     * The code called afterwards to wait for the CCP to finish doesn't need any stack and everything else is preserved making
     * the on chip bootloader survive and successfully call into the off chip bootloader. So the obvious fix with our synchronous
     * CCP implementation is to defer the request until the bootloader polls the control register to wait for the CCP to halt again.
     * Thanks AMD!
     */
    if (pQueue->u32RegCtrl & CCP_V5_Q_REG_CTRL_RUN) /* Running bit set? Process requests. */
    {
        /* Clear halt and running bit. */
        pQueue->u32RegCtrl &= ~(CCP_V5_Q_REG_CTRL_RUN | CCP_V5_Q_REG_CTRL_HALT);

        uint32_t u32ReqTail = pQueue->u32RegReqTail;
        uint32_t u32ReqHead = pQueue->u32RegReqHead;

        while (u32ReqTail < u32ReqHead)
        {
            CCP5REQ Req;

            int rc = PSPEmuIoMgrPspAddrRead(pThis->pDev->hIoMgr, u32ReqTail, &Req, sizeof(Req));
            if (!rc)
            {
                pspDevCcpDumpReq(&Req, u32ReqTail);
                rc = pspDevCcpReqProcess(pThis, &Req);
                if (!rc)
                    pQueue->u32RegSts = CCP_V5_Q_REG_STATUS_SUCCESS;
                else
                    pQueue->u32RegSts = CCP_V5_Q_REG_STATUS_ERROR;
            }
            else
            {
                printf("CCP: Failed to read request from 0x%08x with rc=%d\n", u32ReqTail, rc);
                pQueue->u32RegSts = CCP_V5_Q_REG_STATUS_ERROR; /* Signal error. */
                break;
            }

            u32ReqTail += sizeof(Req);
        }

        /* Set halt bit again. */
        pQueue->u32RegReqTail = u32ReqTail;
        pQueue->u32RegCtrl |= CCP_V5_Q_REG_CTRL_HALT;
    }

    switch (offRegQ)
    {
        case CCP_V5_Q_REG_CTRL:
            *pu32Dst = pQueue->u32RegCtrl;
            break;
        case CCP_V5_Q_REG_HEAD:
            *pu32Dst = pQueue->u32RegReqHead;
            break;
        case CCP_V5_Q_REG_TAIL:
            *pu32Dst = pQueue->u32RegReqTail;
            break;
        case CCP_V5_Q_REG_STATUS:
            *pu32Dst = pQueue->u32RegSts;
            break;
    }
}


/**
 * Handles a register write to a specific queue.
 *
 * @returns nothing.
 * @param   pThis               The CCP device instance data.
 * @param   pQueue              The queue to write to.
 * @param   offRegQ             Offset of the register to write.
 * @param   u32Val              The value to write
 */
static void pspDevCcpMmioQueueRegWrite(PPSPDEVCCP pThis, PCCPQUEUE pQueue, uint32_t offRegQ, uint32_t u32Val)
{
    switch (offRegQ)
    {
        case CCP_V5_Q_REG_CTRL:
            pQueue->u32RegCtrl = u32Val;
            break;
        case CCP_V5_Q_REG_HEAD:
            pQueue->u32RegReqHead = u32Val;
            if (pQueue->u32RegReqTail + 0x20 <= pQueue->u32RegReqHead)
            {
                pQueue->u32RegCtrl &= ~CCP_V5_Q_REG_CTRL_HALT;
                pQueue->u32RegCtrl |= CCP_V5_Q_REG_CTRL_RUN;
            }
            break;
        case CCP_V5_Q_REG_TAIL:
            pQueue->u32RegReqTail = u32Val;
            if (pQueue->u32RegReqTail + 0x20 <= pQueue->u32RegReqHead)
            {
                pQueue->u32RegCtrl &= ~CCP_V5_Q_REG_CTRL_HALT;
                pQueue->u32RegCtrl |= CCP_V5_Q_REG_CTRL_RUN;
            }
            break;
        case CCP_V5_Q_REG_STATUS:
            pQueue->u32RegSts = u32Val;
            break;
    }
}


static void pspDevCcpMmioRead(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVCCP pThis = (PPSPDEVCCP)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        printf("%s: offMmio=%#x cbRead=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbRead);
        return;
    }

    if (offMmio >= CCP_V5_Q_OFFSET)
    {
        /* Queue access. */
        offMmio -= CCP_V5_Q_OFFSET;
        uint32_t uQueue = offMmio / CCP_V5_Q_SIZE;
        uint32_t offRegQ = offMmio % CCP_V5_Q_SIZE;

        if (uQueue == 0)
            pspDevCcpMmioQueueRegRead(pThis, &pThis->Queue1, offRegQ, (uint32_t *)pvDst);
        else if (uQueue == 1)
            pspDevCcpMmioQueueRegRead(pThis, &pThis->Queue2, offRegQ, (uint32_t *)pvDst);
        else
            printf("%s: offMmio=%#x cbRead=%zu uQueue=%u -> Invalid queue\n", __FUNCTION__, offMmio, cbRead, uQueue);
    }
    else
    {
        /** @todo Global register access. */
    }
}


static void pspDevCcpMmioWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVCCP pThis = (PPSPDEVCCP)pvUser;

    if (cbWrite != sizeof(uint32_t))
    {
        printf("%s: offMmio=%#x cbWrite=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbWrite);
        return;
    }

    if (offMmio >= CCP_V5_Q_OFFSET)
    {
        /* Queue access. */
        offMmio -= CCP_V5_Q_OFFSET;
        uint32_t uQueue = offMmio / CCP_V5_Q_SIZE;
        uint32_t offRegQ = offMmio % CCP_V5_Q_SIZE;

        if (uQueue == 0)
            pspDevCcpMmioQueueRegWrite(pThis, &pThis->Queue1, offRegQ, *(const uint32_t *)pvVal);
        else if (uQueue == 1)
            pspDevCcpMmioQueueRegWrite(pThis, &pThis->Queue2, offRegQ, *(const uint32_t *)pvVal);
        else
            printf("%s: offMmio=%#x cbWrite=%zu uQueue=%u -> Invalid queue\n", __FUNCTION__, offMmio, cbWrite, uQueue);
    }
    else
    {
        /** @todo Global register access. */
    }
}


static void pspDevCcpMmioRead2(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVCCP pThis = (PPSPDEVCCP)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        printf("%s: offMmio=%#x cbRead=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbRead);
        return;
    }

    switch (offMmio)
    {
        case 0x28: /* Contains the transfer size of the last oepration? (Zen2 uses it to read the decompressed size). */
            *(uint32_t *)pvDst = pThis->cbWrittenLast;
            break;
        case 0x38:
            *(uint32_t *)pvDst = 0x1; /* Zen1 on chip BL waits for bit 0 to become 1. */
            break;
        default:
            *(uint32_t *)pvDst = 0;
    }
}


static int pspDevCcpInit(PPSPDEV pDev)
{
    PPSPDEVCCP pThis = (PPSPDEVCCP)&pDev->abInstance[0];

    pThis->pDev             = pDev;
    pThis->Queue1.u32RegCtrl = CCP_V5_Q_REG_CTRL_HALT; /* Halt bit set. */
    pThis->Queue1.u32RegSts  = CCP_V5_Q_REG_STATUS_SUCCESS;
    pThis->Queue2.u32RegCtrl = CCP_V5_Q_REG_CTRL_HALT; /* Halt bit set. */
    pThis->Queue2.u32RegSts  = CCP_V5_Q_REG_STATUS_SUCCESS;
    pThis->pOsslShaCtx      = NULL;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, CCP_V5_MMIO_ADDRESS, CCP_V5_Q_OFFSET + 2*CCP_V5_Q_SIZE,
                                     pspDevCcpMmioRead, pspDevCcpMmioWrite, pThis,
                                     "CCPv5 Global+Queue", &pThis->hMmio);
    /** @todo Not sure this really belongs to the CCP (could be some other hardware block) but
     * a register in that range is accessed starting with Zen2 after a CCP zlib decompression operation.
     */
    if (!rc)
        rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, CCP_V5_MMIO_ADDRESS_2, CCP_V5_MMIO_SIZE_2,
                                     pspDevCcpMmioRead2, NULL, pThis,
                                     "CCPv5 + 0x6000", &pThis->hMmio2);
    return rc;
}


static void pspDevCcpDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegCcpV5 =
{
    /** pszName */
    "ccp-v5",
    /** pszDesc */
    "CCPv5",
    /** cbInstance */
    sizeof(PSPDEVCCP),
    /** pfnInit */
    pspDevCcpInit,
    /** pfnDestruct */
    pspDevCcpDestruct,
    /** pfnReset */
    NULL
};

