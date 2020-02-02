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

#include <stdio.h>

#include <psp-devs.h>


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
    uint32_t                        u32PhysAddrSrcLow;
    /** High 16bit of address of source data. */
    uint16_t                        u16PhysAddrSrcHigh;
    /** Source memory type. */
    uint16_t                        u16SrcMemType;
    /** Operation dependent data. */
    union
    {
        /** Non SHA operation. */
        struct
        {
            /** Low 32bit of destination buffer size. */
            uint32_t                u32DstLenLow;
            /** High 16bits of destination buffer size. */
            uint16_t                u16DstLenHigh;
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
    uint32_t                        u32PhysAddrKeyLow;
    /** High 16bit of address of key data. */
    uint16_t                        u16PhysAddrKeyHigh;
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
} PSPDEVCCP;
/** Pointer to the device instance data. */
typedef PSPDEVCCP *PPSPDEVCCP;



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
        case 0:
            return "AES";
        case 1:
            return "XTS_AES_128";
        case 2:
            return "DES3";
        case 3:
            return "SHA";
        case 4:
            return "RSA";
        case 5:
            return "PASSTHROUGH";
        case 6:
            return "ZLIB_DECOMPRESS";
        case 7:
            return "ECC";
    }

    return "<INVALID>";
}


static const char *pspDevCcpReqDumpAesFunction(uint32_t uFunc, uint32_t u32Dw0Raw, const char *pszEngine)
{
    printf("    u32Dw0:             0x%08x (Engine: %s)\n", u32Dw0Raw, pszEngine);
}


static const char *pspDevCcpReqDumpShaFunction(uint32_t uFunc, uint32_t u32Dw0Raw, const char *pszEngine)
{
    uint32_t uShaType = (uFunc >> 10) & 0xf;
    const char *pszShaType = "<INVALID>";

    switch (uShaType)
    {
        case 1:
            pszShaType = "SHA1";
            break;
        case 2:
            pszShaType = "SHA224";
            break;
        case 3:
            pszShaType = "SHA256";
            break;
        case 4:
            pszShaType = "SHA384";
            break;
        case 5:
            pszShaType = "SHA512";
            break;
    }

    printf("    u32Dw0:             0x%08x (Engine: %s, SHA type: %s)\n", u32Dw0Raw, pszEngine, pszShaType);
}


static const char *pspDevCcpReqDumpPassthruFunction(uint32_t uFunc, uint32_t u32Dw0Raw, const char *pszEngine)
{
    uint8_t uByteSwap = uFunc & 0x3;
    uint8_t uBitwise  = (uFunc >> 2) & 0x7;
    uint8_t uReflect  = (uFunc >> 5) & 0x3;

    const char *pszByteSwap = "<INVALID>";
    const char *pszBitwise  = "<INVALID>";

    switch (uByteSwap)
    {
        case 0:
            pszByteSwap = "NOOP";
            break;
        case 1:
            pszByteSwap = "32BIT";
            break;
        case 2:
            pszByteSwap = "256BIT";
            break;
    }

    switch (uBitwise)
    {
        case 0:
            pszBitwise = "NOOP";
            break;
        case 1:
            pszBitwise = "AND";
            break;
        case 2:
            pszBitwise = "OR";
            break;
        case 3:
            pszBitwise = "XOR";
            break;
        case 4:
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
    uint32_t uEngine   = (pReq->u32Dw0 >> 20) & 0xf;
    uint32_t uFunction = (pReq->u32Dw0 >> 5) & 0x7fff;
    const char *pszEngine   = pspDevCcpReqEngineToStr(uEngine);

    printf("CCP Request 0x%08x:\n", PspAddrReq);

    if (uEngine == 0)
        pspDevCcpReqDumpAesFunction(uFunction, pReq->u32Dw0, pszEngine);
    else if (uEngine == 3)
        pspDevCcpReqDumpShaFunction(uFunction, pReq->u32Dw0, pszEngine);
    else if (uEngine == 5)
        pspDevCcpReqDumpPassthruFunction(uFunction, pReq->u32Dw0, pszEngine);
    else
        printf("    u32Dw0:             0x%08x (Engine: %s)\n", pReq->u32Dw0, pszEngine);

    printf("    cbSrc:              %u\n",     pReq->cbSrc);
    printf("    u32PhysAddrSrcLow:  0x%08x\n", pReq->u32PhysAddrSrcLow);
    printf("    u16PhysAddrSrcHigh: 0x%08x\n", pReq->u16PhysAddrSrcHigh);
    printf("    u16SrcMemType:      0x%08x\n", pReq->u16SrcMemType);
    if (1) /** @todo */
    {
        printf("    u32DstLenLow:       0x%08x\n", pReq->Op.NonSha.u32DstLenLow);
        printf("    u16DstLenHigh:      0x%08x\n", pReq->Op.NonSha.u16DstLenHigh);
        printf("    u16DstMemType:      0x%08x\n", pReq->Op.NonSha.u16DstMemType);
    }
    else
    {
        printf("    u32ShaLenLow:       0x%08x\n", pReq->Op.Sha.u32ShaLenLow);
        printf("    u32ShaLenHigh:      0x%08x\n", pReq->Op.Sha.u32ShaLenHigh);
    }
    printf("    u32PhysAddrKeyLow:  0x%08x\n", pReq->u32PhysAddrKeyLow);
    printf("    u16PhysAddrKeyHigh: 0x%08x\n", pReq->u16PhysAddrKeyHigh);
    printf("    u16KeyMemType:      0x%08x\n", pReq->u16KeyMemType);
}


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


static void pspDevCcpMmioQueueRegWrite(PPSPDEVCCP pThis, PCCPQUEUE pQueue, uint32_t offRegQ, const uint32_t *pu32Val)
{
    switch (offRegQ)
    {
        case 0:
            pQueue->u32RegCtrl = *pu32Val;
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
            pQueue->u32RegReqHead = *pu32Val;
            break;
        case 8:
            pQueue->u32RegReqTail = *pu32Val;
            break;
        case 0x100:
            pQueue->u32RegSts = *pu32Val;
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
            pspDevCcpMmioQueueRegWrite(pThis, &pThis->Queue, offRegQ, (uint32_t *)pvVal);
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

