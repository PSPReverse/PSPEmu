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

#include <openssl/evp.h>

#include <common/cdefs.h>

#include <psp-devs.h>


/*********************************************************************************************************************************
*   Defined Constants And Macros                                                                                                 *
*********************************************************************************************************************************/
/** @name CCP engine defines.
 * @{ */
/** AES engine. */
#define CCP_V5_ENGINE_AES                           0
/** XTS-AES128 engine. */
#define CCP_V5_ENGINE_XTS_AES128                    1
/** DES3 engine. */
#define CCP_V5_ENGINE_DES3                          2
/** SHA engine. */
#define CCP_V5_ENGINE_SHA                           3
/** RSA engine. */
#define CCP_V5_ENGINE_RSA                           4
/** PASSTHRU engine. */
#define CCP_V5_ENGINE_PASSTHRU                      5
/** ZLIB decompression engine. */
#define CCP_V5_ENGINE_ZLIB_DECOMP                   6
/** ECC engine. */
#define CCP_V5_ENGINE_ECC                           7
/** Return the engine from the given dword. */
#define CCP_V5_ENGINE_GET(a_Dw0)                    (((a_Dw0) >> 20) & 0xf)
/** Return the engine specific function from the given dword. */
#define CCP_V5_ENGINE_FUNC_GET(a_Dw0)               (((a_Dw0) >> 5) & 0x7fff)
/** Return the end of message field from the given dword. */
#define CCP_V5_ENGINE_EOM_GET(a_Dw0)                (((a_Dw0) >> 4) & 0x1)
/** Return the init field from the given dword. */
#define CCP_V5_ENGINE_INIT_GET(a_Dw0)               (((a_Dw0) >> 3) & 0x1)
/** @} */

/** @name AES engine specific defines.
 * @{ */
/** AES ECB mode. */
#define CCP_V5_ENGINE_AES_MODE_ECB                  0
/** AES CBC mode. */
#define CCP_V5_ENGINE_AES_MODE_CBC                  1
/** AES OFB mode. */
#define CCP_V5_ENGINE_AES_MODE_OFB                  2
/** AES CFB mode. */
#define CCP_V5_ENGINE_AES_MODE_CFB                  3
/** AES CTR mode. */
#define CCP_V5_ENGINE_AES_MODE_CTR                  4
/** AES CMAC mode. */
#define CCP_V5_ENGINE_AES_MODE_CMAC                 5
/** AES GHASH mode. */
#define CCP_V5_ENGINE_AES_MODE_GHASH                6
/** AES GCTR mode. */
#define CCP_V5_ENGINE_AES_MODE_GCTR                 7
/** AES GCM mode. */
#define CCP_V5_ENGINE_AES_MODE_GCM                  8
/** AES GMAC mode. */
#define CCP_V5_ENGINE_AES_MODE_GMAC                 9
/** Return the AES mode from the given function. */
#define CCP_V5_ENGINE_AES_MODE_GET(a_Func)          (((a_Func) >> 8) & 0x1f)

/** AES128 type. */
#define CCP_V5_ENGINE_AES_TYPE_128                  0
/** AES192 type. */
#define CCP_V5_ENGINE_AES_TYPE_192                  1
/** AES256 type. */
#define CCP_V5_ENGINE_AES_TYPE_256                  2
/** Return the AES type from the given function. */
#define CCP_V5_ENGINE_AES_TYPE_GET(a_Func)          (((a_Func) >> 13) & 0x3)

/** Return the AES encrypt/decrypt flag from the given function. */
#define CCP_V5_ENGINE_AES_ENCRYPT_GET(a_Func)       (!!(((a_Func) >> 7) & 0x1))
/** Return the AES size from the given function. */
#define CCP_V5_ENGINE_AES_SZ_GET(a_Func)            ((a_Func) & 0x7f)
/** @} */

/** @name SHA engine specific defines.
 * @{ */
/** SHA1 type. */
#define CCP_V5_ENGINE_SHA_TYPE_1                    1
/** SHA224 type. */
#define CCP_V5_ENGINE_SHA_TYPE_224                  2
/** SHA256 type. */
#define CCP_V5_ENGINE_SHA_TYPE_256                  3
/** SHA384 type. */
#define CCP_V5_ENGINE_SHA_TYPE_384                  4
/** SHA512 type. */
#define CCP_V5_ENGINE_SHA_TYPE_512                  5
/** Return the SHA type from the given function. */
#define CCP_V5_ENGINE_SHA_TYPE_GET(a_Func)          (((a_Func) >> 10) & 0xf)
/** @} */

/** @name PASSTHRU engine specific defines.
 * @{ */
/** Bitwise no-op. */
#define CCP_V5_ENGINE_PASSTHRU_BITWISE_NOOP         0
/** Bitwise and. */
#define CCP_V5_ENGINE_PASSTHRU_BITWISE_AND          1
/** Bitwise or. */
#define CCP_V5_ENGINE_PASSTHRU_BITWISE_OR           2
/** Bitwise xor. */
#define CCP_V5_ENGINE_PASSTHRU_BITWISE_XOR          3
/** Bitwise mask. */
#define CCP_V5_ENGINE_PASSTHRU_BITWISE_MASK         4
/** Return the PASSTHRU bitwise operation from the given function. */
#define CCP_V5_ENGINE_PASSTHRU_BITWISE_GET(a_Func)  (((a_Func) >> 2) & 0x7)

/** Byteswap no-op. */
#define CCP_V5_ENGINE_PASSTHRU_BYTESWAP_NOOP        0
/** Byteswap 32bit. */
#define CCP_V5_ENGINE_PASSTHRU_BYTESWAP_32BIT       1
/** Byteswap 256bit. */
#define CCP_V5_ENGINE_PASSTHRU_BYTESWAP_256BIT      2
/** Return the PASSTHRU byteswap operation from the given function. */
#define CCP_V5_ENGINE_PASSTHRU_BYTESWAP_GET(a_Func) ((a_Func) & 0x3)

/** Return the PASSTHRU reflect operation from the given function. */
#define CCP_V5_ENGINE_PASSTHRU_REFLECT_GET(a_Func)  (((a_Func) >> 5) & 0x3)
/** @} */

/** @name Available memory types.
 * @{ */
/** System memory (DRAM). */
#define CCP_V5_MEM_TYPE_SYSTEM                      0
/** Local storage buffer. */
#define CCP_V5_MEM_TYPE_SB                          1
/** Local PSP SRAM. */
#define CCP_V5_MEM_TYPE_LOCAL                       2
/** Retrieve the memory type from the given 16bit word. */
#define CCP_V5_MEM_TYPE_GET(a_MemType)              ((a_MemType) & 0x3)
/** Retrieve the LSB context ID from the given 16bit word. */
#define CCP_V5_MEM_LSB_CTX_ID_GET(a_MemType)        (((a_MemType) >> 2) & 0xff)
/** Retrieve the LSB context ID from the given 16bit word. */
#define CCP_V5_MEM_LSB_FIXED_GET(a_MemType)         (((a_MemType) >> 16) & 0x1)
/** @} */

/** @name Queue register offsets.
 * @{ */
/** Start offset of the first queue in MMIO space. */
#define CCP_V5_Q_OFFSET                             _4K
/** Size of a single queue MMIO area in bytes. */
#define CCP_V5_Q_SIZE                               _4K
/** Control register. */
#define CCP_V5_Q_REG_CTRL                           0x0
/** The RUN bit, which makes the CCP process requests. */
# define CCP_V5_Q_REG_CTRL_RUN                      BIT(0)
/** The HALT bit, which indicates whether the queue is currently processing requests. */
# define CCP_V5_Q_REG_CTRL_HALT                     BIT(1)
/** Request queue head register. */
#define CCP_V5_Q_REG_HEAD                           0x4
/** Request queue tail register. */
#define CCP_V5_Q_REG_TAIL                           0x8
/** Status register. */
#define CCP_V5_Q_REG_STATUS                         0x100
/** Status register success indicator. */
# define CCP_V5_Q_REG_STATUS_SUCCESS                0
/** Status register error indicator. */
# define CCP_V5_Q_REG_STATUS_ERROR                  1
/** @} */

/** The CCP MMIO address. */
#define CCP_V5_MMIO_ADDRESS                         0x03000000


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/** Address type the CCP uses (created from low and high parts). */
typedef uint64_t CCPADDR;
/** Create a CCP address from the given low and high parts. */
#define CCP_ADDR_CREATE_FROM_HI_LO(a_High, a_Low) (((CCPADDR)(a_High) << 32) | (a_Low))


/**
 * Request descriptor.
 */
typedef struct CCP5REQ
{
    /** Control bits, function, engine. */
    uint32_t                        u32Dw0;
    /** Length of source data. */
    uint32_t                        cbSrc;
    /** Low 32bit of address of source data. */
    uint32_t                        u32AddrSrcLow;
    /** High 16bit of address of source data. */
    uint16_t                        u16AddrSrcHigh;
    /** Source memory type. */
    uint16_t                        u16SrcMemType;
    /** Operation dependent data. */
    union
    {
        /** Non SHA operation. */
        struct
        {
            /** Low 32bit of destination buffer address. */
            uint32_t                u32AddrDstLow;
            /** High 16bits of destination buffer address. */
            uint16_t                u16AddrDstHigh;
            /** Destination memory type. */
            uint16_t                u16DstMemType;
        } NonSha;
        /** SHA operation. */
        struct
        {
            /** Low 32bit of the message bitlength. */
            uint32_t                u32ShaBitsLow;
            /** High 32bit of the message bitlength. */
            uint32_t                u32ShaBitsHigh;
        } Sha;
    } Op;
    /** Low 32bit of address of key data. */
    uint32_t                        u32AddrKeyLow;
    /** High 16bit of address of key data. */
    uint16_t                        u16AddrKeyHigh;
    /** Key memory type. */
    uint16_t                        u16KeyMemType;
} CCP5REQ;
/** Pointer to a request descriptor. */
typedef CCP5REQ *PCCP5REQ;
/** Pointer to a const request descriptor. */
typedef const CCP5REQ *PCCCP5REQ;


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
        } aSlots[8];
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
    /** The single CCP queue we have. */
    CCPQUEUE                        Queue;
    /** The local storage buffer. */
    CCPLSB                          Lsb;
    /** The openssl sha256 context currently in use. This doesn't really belong here
     * as the state is contained in an LSB but for use with openssl and to support
     * multi-part messages we have to store it here, luckily the PSP is single threaded
     * so the code will only every process one SHA operation at a time.
     */
    EVP_MD_CTX                      *pOsslSha256Ctx;
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
    return PSPEmuIoMgrPspAddrWrite(pThis->pDev->hIoMgr, (uint32_t)CcpAddr, pvSrc, cbWrite);
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
static int pspDevCcpxXferCtxRead(PCCPXFERCTX pCtx, void *pvDst, size_t cbRead, size_t *pcbRead)
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
static int pspDevCcpxXferCtxWrite(PCCPXFERCTX pCtx, const void *pvSrc, size_t cbWrite, size_t *pcbWritten)
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
                rc = pCtx->pfnWrite(pCtx->pThis, pCtx->CcpAddrDst, pbSrc, 1);
                cbThisWrite--;
                pCtx->CcpAddrDst--;
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
 * @param   uFunc               The function part of dword 0.
 * @param   u32Dw0Raw           The raw dw0 value used for dumping.
 * @param   pszEngine           The used engine string.
 */
static void pspDevCcpReqDumpAesFunction(uint32_t uFunc, uint32_t u32Dw0Raw, const char *pszEngine)
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

    printf("    u32Dw0:             0x%08x (Engine: %s, AES Type: %s, Mode: %s, Encrypt: %u, Size: %u)\n",
                                    u32Dw0Raw, pszEngine, pszAesType, pszMode, fEncrypt, uSz);
}


/**
 * Extracts and dumps information about the given SHA function.
 *
 * @returns nothing.
 * @param   uFunc               The function part of dword 0.
 * @param   u32Dw0Raw           The raw dw0 value used for dumping.
 * @param   pszEngine           The used engine string.
 */
static void pspDevCcpReqDumpShaFunction(uint32_t uFunc, uint32_t u32Dw0Raw, const char *pszEngine)
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

    printf("    u32Dw0:             0x%08x (Engine: %s, SHA type: %s)\n", u32Dw0Raw, pszEngine, pszShaType);
}


/**
 * Extracts and dumps information about the given PASSTHRU function.
 *
 * @returns nothing.
 * @param   uFunc               The function part of dword 0.
 * @param   u32Dw0Raw           The raw dw0 value used for dumping.
 * @param   pszEngine           The used engine string.
 */
static void pspDevCcpReqDumpPassthruFunction(uint32_t uFunc, uint32_t u32Dw0Raw, const char *pszEngine)
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

    printf("    u32Dw0:             0x%08x (Engine: %s, ByteSwap: %s, Bitwise: %s, Reflect: %#x)\n",
                                    u32Dw0Raw, pszEngine, pszByteSwap, pszBitwise, uReflect);
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

    printf("CCP Request 0x%08x:\n", PspAddrReq);

    if (uEngine == CCP_V5_ENGINE_AES)
        pspDevCcpReqDumpAesFunction(uFunction, pReq->u32Dw0, pszEngine);
    else if (uEngine == CCP_V5_ENGINE_SHA)
        pspDevCcpReqDumpShaFunction(uFunction, pReq->u32Dw0, pszEngine);
    else if (uEngine == CCP_V5_ENGINE_PASSTHRU)
        pspDevCcpReqDumpPassthruFunction(uFunction, pReq->u32Dw0, pszEngine);
    else
        printf("    u32Dw0:             0x%08x (Engine: %s)\n", pReq->u32Dw0, pszEngine);

    printf("    cbSrc:              %u\n",     pReq->cbSrc);
    printf("    u32AddrSrcLow:      0x%08x\n", pReq->u32AddrSrcLow);
    printf("    u16AddrSrcHigh:     0x%08x\n", pReq->u16AddrSrcHigh);
    printf("    u16SrcMemType:      0x%08x (MemType: %u, LsbCtxId: %u, Fixed: %u)\n",
           pReq->u16SrcMemType, CCP_V5_MEM_TYPE_GET(pReq->u16SrcMemType),
           CCP_V5_MEM_LSB_CTX_ID_GET(pReq->u16SrcMemType), CCP_V5_MEM_LSB_FIXED_GET(pReq->u16SrcMemType));
    if (uEngine != CCP_V5_ENGINE_SHA)
    {
        printf("    u32AddrDstLow:      0x%08x\n", pReq->Op.NonSha.u32AddrDstLow);
        printf("    u16AddrDstHigh:     0x%08x\n", pReq->Op.NonSha.u16AddrDstHigh);
        printf("    u16DstMemType:      0x%08x (MemType: %u, Fixed: %u)\n",
               pReq->Op.NonSha.u16DstMemType, CCP_V5_MEM_TYPE_GET(pReq->Op.NonSha.u16DstMemType),
               CCP_V5_MEM_LSB_FIXED_GET(pReq->Op.NonSha.u16DstMemType));
    }
    else
    {
        printf("    u32ShaBitsLow:      0x%08x\n", pReq->Op.Sha.u32ShaBitsLow);
        printf("    u32ShaBitsHigh:     0x%08x\n", pReq->Op.Sha.u32ShaBitsHigh);
    }
    printf("    u32AddrKeyLow:      0x%08x\n", pReq->u32AddrKeyLow);
    printf("    u16AddrKeyHigh:     0x%08x\n", pReq->u16AddrKeyHigh);
    printf("    u16KeyMemType:      0x%08x\n", pReq->u16KeyMemType);
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
            uint8_t abData[32];
            while (   !rc
                   && cbLeft)
            {
                size_t cbThisProc = MIN(cbLeft, sizeof(abData));

                rc = pspDevCcpxXferCtxRead(&XferCtx, &abData[0], cbThisProc, NULL);
                if (!rc)
                    rc = pspDevCcpxXferCtxWrite(&XferCtx, &abData[0], cbThisProc, NULL);

                cbLeft -= cbThisProc;
            }
        }
    }
    else
    {
        printf("CCP: PASSTHRU ERROR uBitwise=%u, uByteSwap=%u and uReflect=%u not implemented yet!\n", uBitwise, uByteSwap, uReflect);
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
 */
static int pspDevCcpReqShaProcess(PPSPDEVCCP pThis, PCCCP5REQ pReq, uint32_t uFunc)
{
    int rc = 0;
    uint32_t uShaType = CCP_V5_ENGINE_SHA_TYPE_GET(uFunc);
    bool fInit = CCP_V5_ENGINE_INIT_GET(pReq->u32Dw0);
    bool fEom = CCP_V5_ENGINE_EOM_GET(pReq->u32Dw0);

    /* Only sha256 and single-part calculation implemented so far. */
    if (uShaType == CCP_V5_ENGINE_SHA_TYPE_256)
    {
        const EVP_MD *pOsslEvpSha256 = EVP_sha256();
        size_t cbLeft = pReq->cbSrc;
        CCPXFERCTX XferCtx;

        rc = pspDevCcpXferCtxInit(&XferCtx, pThis, pReq, true /*fSha*/, EVP_MD_size(pOsslEvpSha256),
                                  false /*fWriteRev*/);
        if (!rc)
        {
            /*
             * The storage buffer contains the initial sha256 state, which we will ignore
             * because that is already part of the openssl context.
             */
            if (fInit)
            {
                pThis->pOsslSha256Ctx = EVP_MD_CTX_new();
                if (!pThis->pOsslSha256Ctx)
                    rc = -1;

                if (EVP_DigestInit_ex(pThis->pOsslSha256Ctx, pOsslEvpSha256, NULL) != 1)
                    rc = -1;
            }

            while (   !rc
                   && cbLeft)
            {
                uint8_t abData[32];
                size_t cbThisProc = MIN(cbLeft, sizeof(abData));

                rc = pspDevCcpxXferCtxRead(&XferCtx, &abData[0], cbThisProc, NULL);
                if (!rc)
                {
                    if (EVP_DigestUpdate(pThis->pOsslSha256Ctx, &abData[0], cbThisProc) != 1)
                        rc = -1;
                }

                cbLeft -= cbThisProc;
            }

            if (   !rc
                && fEom)
            {
                /* Finalize state and write to the storage buffer. */
                uint8_t abHash[32]; /** @todo Hardcoding the digest size is meh... */
                if (EVP_DigestFinal_ex(pThis->pOsslSha256Ctx, &abHash[0], NULL) == 1)
                    rc = pspDevCcpxXferCtxWrite(&XferCtx, &abHash[0], sizeof(abHash), NULL);
                else
                    rc = -1;

                EVP_MD_CTX_free(pThis->pOsslSha256Ctx);
                pThis->pOsslSha256Ctx = NULL;
            }
        }
    }
    else
    {
        printf("CCP: SHA ERROR uShaType=%u fInit=%u fEom=%u u32ShaBitsHigh=%u u32ShaBitsLow=%u not implemented yet!\n",
               uShaType, fInit, fEom, pReq->Op.Sha.u32ShaBitsHigh, pReq->Op.Sha.u32ShaBitsLow);
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

    switch (uEngine)
    {
        case CCP_V5_ENGINE_PASSTHRU:
        {
            rc = pspDevCcpReqPassthruProcess(pThis, pReq, uFunction);
            break;
        }
        case CCP_V5_ENGINE_SHA:
        {
            rc = pspDevCcpReqShaProcess(pThis, pReq, uFunction);
            break;
        }
        case CCP_V5_ENGINE_AES:
        case CCP_V5_ENGINE_XTS_AES128:
        case CCP_V5_ENGINE_DES3:
        case CCP_V5_ENGINE_RSA:
        case CCP_V5_ENGINE_ZLIB_DECOMP:
        case CCP_V5_ENGINE_ECC:
            /** @todo */
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
 * @param   pQueue              The queue to read a register from.
 * @param   offRegQ             The register offset to read from.
 * @param   pu32Dst             Whereto store the register content.
 */
static void pspDevCcpMmioQueueRegRead(PCCPQUEUE pQueue, uint32_t offRegQ, uint32_t *pu32Dst)
{
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
            break;
        case CCP_V5_Q_REG_HEAD:
            pQueue->u32RegReqHead = u32Val;
            break;
        case CCP_V5_Q_REG_TAIL:
            pQueue->u32RegReqTail = u32Val;
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

        if (uQueue > 0)
            printf("%s: offMmio=%#x cbRead=%zu uQueue=%u -> Invalid queue\n", __FUNCTION__, offMmio, cbRead, uQueue);
        else
            pspDevCcpMmioQueueRegRead(&pThis->Queue, offRegQ, (uint32_t *)pvDst);
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

        if (uQueue > 0)
            printf("%s: offMmio=%#x cbWrite=%zu uQueue=%u -> Invalid queue\n", __FUNCTION__, offMmio, cbWrite, uQueue);
        else
            pspDevCcpMmioQueueRegWrite(pThis, &pThis->Queue, offRegQ, *(const uint32_t *)pvVal);
    }
    else
    {
        /** @todo Global register access. */
    }
}


static int pspDevCcpInit(PPSPDEV pDev)
{
    PPSPDEVCCP pThis = (PPSPDEVCCP)&pDev->abInstance[0];

    pThis->pDev             = pDev;
    pThis->Queue.u32RegCtrl = CCP_V5_Q_REG_CTRL_HALT; /* Halt bit set. */
    pThis->Queue.u32RegSts  = CCP_V5_Q_REG_STATUS_SUCCESS;
    pThis->pOsslSha256Ctx   = NULL;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, CCP_V5_MMIO_ADDRESS, CCP_V5_Q_OFFSET + CCP_V5_Q_SIZE,
                                     pspDevCcpMmioRead, pspDevCcpMmioWrite, pThis,
                                     &pThis->hMmio);
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
};

