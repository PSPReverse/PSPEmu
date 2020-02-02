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


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

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
            /** Low 32bit of the SHA length. */
            uint32_t                u32ShaLenLow;
            /** High 32bit of the SHA length. */
            uint32_t                u32ShaLenHigh;
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
    /** 32byte data. */
    uint8_t                         abData[32];
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
    /** The local storage buffers contained in the CCP. */
    CCPLSB                          aLsbs[8];
} PSPDEVCCP;
/** Pointer to the device instance data. */
typedef PSPDEVCCP *PPSPDEVCCP;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

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
    printf("    u16SrcMemType:      0x%08x\n", pReq->u16SrcMemType);
    if (uEngine != CCP_V5_ENGINE_SHA)
    {
        printf("    u32AddrDstLow:      0x%08x\n", pReq->Op.NonSha.u32AddrDstLow);
        printf("    u16AddrDstHigh:     0x%08x\n", pReq->Op.NonSha.u16AddrDstHigh);
        printf("    u16DstMemType:      0x%08x\n", pReq->Op.NonSha.u16DstMemType);
    }
    else
    {
        printf("    u32ShaLenLow:       0x%08x\n", pReq->Op.Sha.u32ShaLenLow);
        printf("    u32ShaLenHigh:      0x%08x\n", pReq->Op.Sha.u32ShaLenHigh);
    }
    printf("    u32AddrKeyLow:      0x%08x\n", pReq->u32AddrKeyLow);
    printf("    u16AddrKeyHigh:     0x%08x\n", pReq->u16AddrKeyHigh);
    printf("    u16KeyMemType:      0x%08x\n", pReq->u16KeyMemType);
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
        case 0:
            *pu32Dst = pQueue->u32RegCtrl;
            break;
        case 4:
            *pu32Dst = pQueue->u32RegReqHead;
            break;
        case 8:
            *pu32Dst = pQueue->u32RegReqTail;
            break;
        case 0x100:
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
        case 0:
            pQueue->u32RegCtrl = u32Val;
            if (pQueue->u32RegCtrl & 0x1) /* Running bit set? Process requests. */
            {
                /* Clear halt and running bit. */
                pQueue->u32RegCtrl &= ~0x3;

                uint32_t u32ReqTail = pQueue->u32RegReqTail;
                uint32_t u32ReqHead = pQueue->u32RegReqHead;

                while (u32ReqTail < u32ReqHead)
                {
                    CCP5REQ Req;

                    int rc = PSPEmuIoMgrPspAddrRead(pThis->pDev->hIoMgr, u32ReqTail, &Req, sizeof(Req));
                    if (!rc)
                    {
                        pspDevCcpDumpReq(&Req, u32ReqTail);
                        /** @todo */
                        pQueue->u32RegSts = 0;
                    }
                    else
                    {
                        printf("CCP: Failed to read request from 0x%08x with rc=%d\n", u32ReqTail, rc);
                        pQueue->u32RegSts = 1; /* Signal error. */
                        break;
                    }

                    u32ReqTail += sizeof(Req);
                }

                /* Set halt bit again. */
                pQueue->u32RegCtrl |= 0x2;
            }
            break;
        case 4:
            pQueue->u32RegReqHead = u32Val;
            break;
        case 8:
            pQueue->u32RegReqTail = u32Val;
            break;
        case 0x100:
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

    if (offMmio >= 0x1000)
    {
        /* Queue access. */
        offMmio -= 0x1000;
        uint32_t uQueue = offMmio / 0x1000;
        uint32_t offRegQ = offMmio % 0x1000;

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

    if (offMmio >= 0x1000)
    {
        /* Queue access. */
        offMmio -= 0x1000;
        uint32_t uQueue = offMmio / 0x1000;
        uint32_t offRegQ = offMmio % 0x1000;

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
    pThis->Queue.u32RegCtrl = 0x2; /* Halt bit set. */
    pThis->Queue.u32RegSts  = 0x0;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, 0x03000000, 2 * 4096,
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

