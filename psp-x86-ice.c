/** @file
 * PSP Emulator - API for the x86 ICE (In-circuit emulator) network interface.
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
/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#include <stdlib.h>

#include <common/cdefs.h>
#include <common/status.h>

#include <os/lock.h>
#include <os/thread.h>
#include <os/tcp.h>

#include <psp-x86-ice.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

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
 * The header for the binary transfer mode.
 */
typedef struct PSPX86SERIALICEBINHDR
{
    /** Flags for the transfer. */
    uint32_t                        fFlags;
    /** Size of the transfer in bytes. */
    uint32_t                        cbXfer;
    /** The start address */
    uint64_t                        u64AddrStart;
} PSPX86SERIALICEBINHDR;
/** Pointer to a binary transfer header. */
typedef PSPX86SERIALICEBINHDR *PPSPX86SERIALICEBINHDR;
/** Pointer to a const binary transfer header. */
typedef const PSPX86SERIALICEBINHDR *PCPSPX86SERIALICEBINHDR;

/** Indicates a write request, read if cleared. */
#define PSPX86ICE_BIN_REQ_HDR_F_WRITE           BIT(0)
/** Indicates an I/O port access, memory access if clear. */
#define PSPX86ICE_BIN_REQ_HDR_F_IOPORT          BIT(1)
/** Indicates a a RAM memory access, MMIO or unknown if clear. */
#define PSPX86ICE_BIN_REQ_HDR_F_MEM_RAM         BIT(2)
/** Indicates a a MMIO memory access, RAM or unknown if clear. */
#define PSPX86ICE_BIN_REQ_HDR_F_MEM_MMIO        BIT(3)


/**
 * The x86 ICE instance data.
 */
typedef struct PSPX86ICEINT
{
    /** The lock protecting the ICE instance. */
    OSLOCK                          hLock;
    /** The TCP server instance. */
    OSTCPSRV                        hTcpSrv;
    /** The network I/O thread. */
    OSTHREAD                        hThreadIo;
    /** Flag whether the thread should terminate. */
    volatile bool                   fThreadTerminate;
    /** I/O port read handler .*/
    PFNPSPX86ICEIOPORTREAD          pfnIoPortRead;
    /** I/O port write handler .*/
    PFNPSPX86ICEIOPORTWRITE         pfnIoPortWrite;
    /** Opaque user data to pass to the I/O port read/write handlers. */
    void                            *pvUserIoPortRw;
    /** Memory read handler. */
    PFNPSPX86ICEMEMREAD             pfnMemRead;
    /** Memory write handler. */
    PFNPSPX86ICEMEMWRITE            pfnMemWrite;
    /** Opaque user data to pass to the memory read/write handlers. */
    void                            *pvUserMemRw;
    /** MSR read handler. */
    PFNPSPX86ICEMSRREAD             pfnMsrRead;
    /** MSR write handler. */
    PFNPSPX86ICEMSRWRITE            pfnMsrWrite;
    /** Opaque user data to pass to the MSR read/write handlers. */
    void                            *pvUserMsrRw;
} PSPX86ICEINT;
/** Pointer to the internal x86 ICE instance data. */
typedef PSPX86ICEINT *PPSPX86ICEINT;
/** Pointer to a const internal x86 ICE instance data. */
typedef const PSPX86ICEINT *PCPSPX86ICEINT;


typedef enum PSPX86SERIALICERXSTATE
{
    PSPX86SERIALICERXSTATE_INVALID = 0,
    PSPX86SERIALICERXSTATE_CMD_MARKER_WAIT,
    PSPX86SERIALICERXSTATE_RW_WAIT,
    PSPX86SERIALICERXSTATE_TYPE,
    PSPX86SERIALICERXSTATE_ADDR,
    PSPX86SERIALICERXSTATE_DOT,
    PSPX86SERIALICERXSTATE_WIDTH,
    PSPX86SERIALICERXSTATE_EQUAL,
    PSPX86SERIALICERXSTATE_DATA,
    PSPX86SERIALICERXSTATE_32BIT_HACK = 0x7fffffff
} PSPX86SERIALICERXSTATE;


/**
 * Command receive state.
 */
typedef struct PSPX86SERIALICERX
{
    /** The receive state we are in. */
    PSPX86SERIALICERXSTATE          enmState;
    /** Flag whether to read or write. */
    bool                            fRead;
    /** Flag whether an I/O port or an MMIO address should be accessed. */
    bool                            fIoPort;
    /** The memory type. */
    PSPX86ICEMEMTYPE                enmMemType;
    /** Number if address bytes left. */
    size_t                          cbAddr;
    /** The address to access. */
    uint64_t                        uAddr;
    /** Access width. */
    size_t                          cb;
    /** Number of data bytes to receive for writes. */
    size_t                          cbData;
    /** Data to write during writes. */
    uint64_t                        u64Val;
} PSPX86SERIALICERX;
/** Pointer to a command receive state. */
typedef PSPX86SERIALICERX *PPSPX86SERIALICERX;
/** Pointer to a const command receive state. */
typedef const PSPX86SERIALICERX *PCPSPX86SERIALICERX;


/*********************************************************************************************************************************
*   Global Variables                                                                                                             *
*********************************************************************************************************************************/

static const uint8_t s_abHexToChr[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

/**
 * Converts a hex character to the appropriate nibble.
 *
 * @returns Nibble of the character.
 * @param   bVal                    The value to convert.
 */
static inline uint8_t pspX86IceSerialIceHexToNibble(uint8_t bVal)
{
    if (bVal >= '0' && bVal <= '9')
        return bVal - '0';
    else if (bVal >= 'a' && bVal <= 'f')
        return bVal - 'a' + 10;
    else if (bVal >= 'A' && bVal <= 'F')
        return bVal - 'A' + 10;

    return 0;
}


/**
 * Resets the SerialICE receive state machine.
 *
 * @returns nothing.
 * @param   pRx                     The receive state machine to reset.
 */
static void pspX86IceSerialIceRxReset(PPSPX86SERIALICERX pRx)
{
    pRx->enmState   = PSPX86SERIALICERXSTATE_CMD_MARKER_WAIT;
    pRx->fRead      = false;
    pRx->fIoPort    = false;
    pRx->enmMemType = PSPX86ICEMEMTYPE_UNKNOWN;
    pRx->cbAddr     = 0;
    pRx->uAddr      = 0;
    pRx->cb         = 0;
    pRx->cbData     = 0;
    pRx->u64Val     = 0;
}


/**
 * Encode the given value as an ASCII hexecimal number with the given number of bytes.
 *
 * @returns Nothing.
 * @param   pbDst                   Where to store the encoded number.
 * @param   u64Val                  The value to encode.
 * @param   cb                      Size of the value in bytes (maximum 8).
 */
static inline void pspX86IceSerialIceEncodeN(uint8_t *pbDst, uint64_t u64Val, size_t cb)
{
    uint8_t *pbCur = pbDst + cb * 2 - 1;

    for (uint32_t i = 0; i < cb; i++)
    {
        *pbCur-- = s_abHexToChr[u64Val & 0xf];
        *pbCur-- = s_abHexToChr[(u64Val >> 4) & 0xf];
        u64Val >>= 8;
    }
}


/**
 * Encodes a given 32bit binary as a hexadecimal ASCII number.
 *
 * @returns nothing.
 * @param   pbDst                   Where to store the encoded number.
 * @param   u32Val                  The value to encode.
 */
static inline void pspX86IceSerialIceEncodeU32(uint8_t *pbDst, uint32_t u32Val)
{
    pspX86IceSerialIceEncodeN(pbDst, u32Val, sizeof(u32Val));
}


/**
 * Receives a 32bit value encoded as ASCII from the given TCP connection.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection.
 * @param   pu32Val                 Where to store the 32bit value on success.
 */
static int pspX86IceSerialIceRecvU32(OSTCPCON hTcpCon, uint32_t *pu32Val)
{
    int rc = STS_INF_SUCCESS;

    *pu32Val = 0;

    for (uint32_t i = 0; i < sizeof(*pu32Val) && STS_SUCCESS(rc); i++)
    {
        uint8_t abByte[2] = { 0 };
        rc = OSTcpConnectionRead(hTcpCon, &abByte[0], sizeof(abByte), NULL /*pcbRead*/);
        if (STS_SUCCESS(rc))
        {
            *pu32Val <<= 8;
            *pu32Val |=   (pspX86IceSerialIceHexToNibble(abByte[0]) << 4)
                        | pspX86IceSerialIceHexToNibble(abByte[1]);
        }
    }

    return rc;
}


/**
 * Receives and skips an ASCII dot from the given TCP connection.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection.
 */
static int pspX86IceSerialIceRecvSkipDot(OSTCPCON hTcpCon)
{
    uint8_t bRx = 0;
    int rc = OSTcpConnectionRead(hTcpCon, &bRx, sizeof(bRx), NULL /*pcbRead*/);
    if (   STS_SUCCESS(rc)
        && bRx != '.')
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


/**
 * Receives and skips an ASCII equal sign from the given TCP connection.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection.
 */
static int pspX86IceSerialIceRecvSkipEqual(OSTCPCON hTcpCon)
{
    uint8_t bRx = 0;
    int rc = OSTcpConnectionRead(hTcpCon, &bRx, sizeof(bRx), NULL /*pcbRead*/);
    if (   STS_SUCCESS(rc)
        && bRx != '=')
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


/**
 * Sends the marker that the bridge is ready to accept a new command.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection to send to.
 */
static int pspX86IceSerialIceRdySend(OSTCPCON hTcpCon)
{
    uint8_t achReady[3] = { '\r', '\n', '>' };
    return OSTcpConnectionWrite(hTcpCon, &achReady[0], sizeof(achReady), NULL /*pcbWritten*/);
}


/**
 * Processes the fully received command.
 *
 * @returns Status code.
 * @param   pThis                   The x86 ICE instance.
 * @param   pRx                     Pointer to the command to process.
 * @param   hTcpCon                 The TCP connection to send the response to.
 */
static int pspX86IceSerialIceProcess(PPSPX86ICEINT pThis, PPSPX86SERIALICERX pRx, OSTCPCON hTcpCon)
{
    OSLockAcquire(pThis->hLock);
    PFNPSPX86ICEIOPORTREAD  pfnIoPortRead = pThis->pfnIoPortRead;
    PFNPSPX86ICEIOPORTWRITE pfnIoPortWrite = pThis->pfnIoPortWrite;
    void *pvUserIoPortRw = pThis->pvUserIoPortRw;

    PFNPSPX86ICEMEMREAD  pfnMemRead = pThis->pfnMemRead;
    PFNPSPX86ICEMEMWRITE pfnMemWrite = pThis->pfnMemWrite;
    void *pvUserMemRw = pThis->pvUserMemRw;
    OSLockRelease(pThis->hLock);

    int rc = STS_INF_SUCCESS;
    PSPDATUM Val;
    if (pRx->fIoPort)
    {
        if (pRx->fRead)
            rc = pfnIoPortRead(pThis, (uint16_t)pRx->uAddr, pRx->cb, &Val.ab[0], pvUserIoPortRw);
        else
        {
            switch (pRx->cb)
            {
                default: /* Should never happen. */
                case 1:
                    Val.u8 = (uint8_t)pRx->u64Val;
                    break;
                case 2:
                    Val.u16 = (uint16_t)pRx->u64Val;
                    break;
                case 4:
                    Val.u32 = (uint32_t)pRx->u64Val;
                    break;
            }

            rc = pfnIoPortWrite(pThis, (uint16_t)pRx->uAddr, pRx->cb, &Val.ab[0], pvUserIoPortRw);
        }
    }
    else
    {
        if (pRx->fRead)
            rc = pfnMemRead(pThis, pRx->uAddr, pRx->enmMemType, pRx->cb, &Val.ab[0], pvUserMemRw);
        else
        {
            switch (pRx->cb)
            {
                default: /* Should never happen. */
                case 1:
                    Val.u8 = (uint8_t)pRx->u64Val;
                    break;
                case 2:
                    Val.u16 = (uint16_t)pRx->u64Val;
                    break;
                case 4:
                    Val.u32 = (uint32_t)pRx->u64Val;
                    break;
                case 8:
                    Val.u64 = pRx->u64Val;
                    break;
            }

            rc = pfnMemWrite(pThis, pRx->uAddr, pRx->enmMemType, pRx->cb, &Val.ab[0], pvUserMemRw);
        }
    }

    if (   STS_SUCCESS(rc)
        && pRx->fRead)
    {
        /* Send response. */

        uint64_t u64Read = 0;
        switch (pRx->cb)
        {
            default: /* Should never happen. */
            case 1:
                u64Read = Val.u8;
                break;
            case 2:
                u64Read = Val.u16;
                break;
            case 4:
                u64Read = Val.u32;
                break;
            case 8:
                u64Read = Val.u64;
                break;
        }

        uint8_t abResp[16] = { 0 };
        pspX86IceSerialIceEncodeN(&abResp[0], u64Read, pRx->cb);
        rc = OSTcpConnectionWrite(hTcpCon, &abResp[0], pRx->cb * 2, NULL /*pcbWritten*/);
    }

    /* Send new readiness symbol. */
    if (STS_SUCCESS(rc))
        rc = pspX86IceSerialIceRdySend(hTcpCon);

    /* Reset state machine to start anew. */
    pspX86IceSerialIceRxReset(pRx);
    return rc;
}


/**
 * Processes a binary transfer request.
 *
 * @returns Status code.
 * @param   pThis                   The x86 ICE instance.
 * @param   hTcpCon                 The TCP connection to read from.
 */
static int pspX86IceSerialIceBinXfer(PPSPX86ICEINT pThis, OSTCPCON hTcpCon)
{
    OSLockAcquire(pThis->hLock);
    PFNPSPX86ICEIOPORTREAD  pfnIoPortRead = pThis->pfnIoPortRead;
    PFNPSPX86ICEIOPORTWRITE pfnIoPortWrite = pThis->pfnIoPortWrite;
    void *pvUserIoPortRw = pThis->pvUserIoPortRw;

    PFNPSPX86ICEMEMREAD  pfnMemRead = pThis->pfnMemRead;
    PFNPSPX86ICEMEMWRITE pfnMemWrite = pThis->pfnMemWrite;
    void *pvUserMemRw = pThis->pvUserMemRw;
    OSLockRelease(pThis->hLock);

    PSPX86SERIALICEBINHDR ReqHdr;
    int rc = OSTcpConnectionRead(hTcpCon, &ReqHdr, sizeof(ReqHdr), NULL /*pcbRead*/);
    if (STS_SUCCESS(rc))
    {
        if (ReqHdr.fFlags & PSPX86ICE_BIN_REQ_HDR_F_IOPORT)
        {
            uint8_t abData[4]; /* Maximum. */
            if (   ReqHdr.cbXfer == 1
                || ReqHdr.cbXfer == 2
                || ReqHdr.cbXfer == 4)
            {
                if (ReqHdr.fFlags & PSPX86ICE_BIN_REQ_HDR_F_WRITE)
                {
                    /* Receive the data to write. */
                    rc = OSTcpConnectionRead(hTcpCon, &abData[0], sizeof(abData), NULL /*pcbRead*/);
                    if (STS_SUCCESS(rc))
                        rc = pfnIoPortWrite(pThis, (uint16_t)ReqHdr.u64AddrStart, ReqHdr.cbXfer, &abData[0], pvUserIoPortRw);
                }
                else
                {
                    rc = pfnIoPortRead(pThis, (uint16_t)ReqHdr.u64AddrStart, ReqHdr.cbXfer, &abData[0], pvUserIoPortRw);
                    if (STS_SUCCESS(rc))
                        rc = OSTcpConnectionWrite(hTcpCon, &abData[0], sizeof(abData), NULL /*pcbWritten*/);
                }
            }
        }
        else
        {
            /* Memory. */
            uint8_t abData[32];
            PSPX86ICEMEMTYPE enmMemType = PSPX86ICEMEMTYPE_UNKNOWN;
            size_t cbXferLeft = ReqHdr.cbXfer;
            X86PADDR PhysX86Addr = ReqHdr.u64AddrStart;

            if (ReqHdr.fFlags & PSPX86ICE_BIN_REQ_HDR_F_MEM_RAM)
                enmMemType = PSPX86ICEMEMTYPE_RAM;
            else if (ReqHdr.fFlags & PSPX86ICE_BIN_REQ_HDR_F_MEM_MMIO)
                enmMemType = PSPX86ICEMEMTYPE_MMIO;

            /* Worker loop */
            while (   cbXferLeft
                   && STS_SUCCESS(rc))
            {
                size_t cbThisXfer = MIN(cbXferLeft, sizeof(abData));

                if (ReqHdr.fFlags & PSPX86ICE_BIN_REQ_HDR_F_WRITE)
                {
                    /* Receive the data to write. */
                    rc = OSTcpConnectionRead(hTcpCon, &abData[0], cbThisXfer, NULL /*pcbRead*/);
                    if (STS_SUCCESS(rc))
                        rc = pfnMemWrite(pThis, PhysX86Addr, enmMemType, cbThisXfer, &abData[0], pvUserMemRw);
                }
                else
                {
                    rc = pfnMemRead(pThis, PhysX86Addr, enmMemType, cbThisXfer, &abData[0], pvUserMemRw);
                    if (STS_SUCCESS(rc))
                        rc = OSTcpConnectionWrite(hTcpCon, &abData[0], cbThisXfer, NULL /*pcbWritten*/);
                }

                PhysX86Addr += cbThisXfer;
                cbXferLeft  -= cbThisXfer;
            }
        }

        rc = pspX86IceSerialIceRdySend(hTcpCon);
    }

    return rc;
}


/**
 * Processes a MSR request.
 *
 * @returns Status code.
 * @param   pThis                   The x86 ICE instance.
 * @param   hTcpCon                 The TCP connection to read from.
 * @param   pRx                     The receiving state (for reading the read/write flag and resetting the state).
 */
static int pspX86IceSerialIceMsrProcess(PPSPX86ICEINT pThis, OSTCPCON hTcpCon, PPSPX86SERIALICERX pRx)
{
    OSLockAcquire(pThis->hLock);
    PFNPSPX86ICEMSRREAD  pfnMsrRead = pThis->pfnMsrRead;
    PFNPSPX86ICEMSRWRITE pfnMsrWrite = pThis->pfnMsrWrite;
    void *pvUserMsrRw = pThis->pvUserMsrRw;
    OSLockRelease(pThis->hLock);

    /* Receive the MSR to access. */
    uint32_t idMsr = 0;
    uint32_t idKey = 0;
    int rc = pspX86IceSerialIceRecvU32(hTcpCon, &idMsr);
    if (STS_SUCCESS(rc))
        rc = pspX86IceSerialIceRecvSkipDot(hTcpCon);
    if (STS_SUCCESS(rc))
        rc = pspX86IceSerialIceRecvU32(hTcpCon, &idKey);
    if (STS_SUCCESS(rc))
    {
        if (pRx->fRead)
        {
            uint64_t u64Val = 0;

            /* Read and send data. */
            rc = pfnMsrRead(pThis, idMsr, idKey, &u64Val, pvUserMsrRw);
            if (STS_SUCCESS(rc))
            {
                uint8_t abResp[sizeof(u64Val) * 2 + 1] = { 0 };
                pspX86IceSerialIceEncodeU32(&abResp[0], (uint32_t)(u64Val >> 32));
                abResp[sizeof(uint32_t) * 2] = '.';
                pspX86IceSerialIceEncodeU32(&abResp[sizeof(uint32_t) * 2 + 1], (uint32_t)u64Val);
                rc = OSTcpConnectionWrite(hTcpCon, &abResp[0], sizeof(abResp), NULL /*pcbWritten*/);
            }
        }
        else
        {
            /* Receive the data. */
            rc = pspX86IceSerialIceRecvSkipEqual(hTcpCon);
            if (STS_SUCCESS(rc))
            {
                uint32_t u32ValHigh = 0;
                uint32_t u32ValLow = 0;

                rc = pspX86IceSerialIceRecvU32(hTcpCon, &u32ValHigh);
                if (STS_SUCCESS(rc))
                    rc = pspX86IceSerialIceRecvSkipDot(hTcpCon);
                if (STS_SUCCESS(rc))
                    rc = pspX86IceSerialIceRecvU32(hTcpCon, &u32ValLow);
                if (STS_SUCCESS(rc))
                    rc = pfnMsrWrite(pThis, idMsr, idKey, (((uint64_t)u32ValHigh) << 32) | u32ValLow, pvUserMsrRw);
            }
        }
    }

    /* Send new readiness symbol. */
    if (STS_SUCCESS(rc))
        rc = pspX86IceSerialIceRdySend(hTcpCon);

    /* Reset state machine to start anew. */
    pspX86IceSerialIceRxReset(pRx);
    return rc;
}


/**
 * Tries to receive as much as possible from the given TCP connection, advancing the state machine.
 *
 * @returns Status code.
 * @param   pThis                   The x86 ICE instance.
 * @param   pRx                     Pointer to the serialICE receive state machine.
 * @param   hTcpCon                 The TCP connection to read from.
 */
static int pspX86IceSerialIceRecv(PPSPX86ICEINT pThis, PPSPX86SERIALICERX pRx, OSTCPCON hTcpCon)
{
    int rc = STS_INF_SUCCESS;

    for (;;)
    {
        uint8_t bRx = 0;
        size_t cbRead = 0;
        rc = OSTcpConnectionRead(hTcpCon, &bRx, sizeof(bRx), &cbRead);
        if (   STS_SUCCESS(rc)
            && cbRead == 1)
        {
            /** @todo Assert cbRead == 1 */
            switch (pRx->enmState)
            {
                case PSPX86SERIALICERXSTATE_CMD_MARKER_WAIT:
                    if (bRx == '*')
                        pRx->enmState = PSPX86SERIALICERXSTATE_RW_WAIT;
                    else if (bRx == '?')
                    {
                        /* Query extended protocol available, return a 1. */
                        uint8_t bResp = '1';
                        rc = OSTcpConnectionWrite(hTcpCon, &bResp, sizeof(bResp), NULL /*pcbWritten*/);
                        if (STS_SUCCESS(rc))
                            rc = pspX86IceSerialIceRdySend(hTcpCon);

                        /* Reset state machine to start anew. */
                        pspX86IceSerialIceRxReset(pRx);
                    }
                    else if (bRx == '!')
                        rc = pspX86IceSerialIceBinXfer(pThis, hTcpCon);
                    break;
                case PSPX86SERIALICERXSTATE_RW_WAIT:
                    if (bRx == 'r')
                        pRx->fRead = true;
                    else if (bRx == 'w')
                        pRx->fRead = false;
                    else
                        rc = STS_ERR_INVALID_PARAMETER;
                    pRx->enmState = PSPX86SERIALICERXSTATE_TYPE; /* Doesn't matter in error case. */
                    break;
                case PSPX86SERIALICERXSTATE_TYPE:
                    pRx->enmState = PSPX86SERIALICERXSTATE_ADDR; /* Doesn't matter in error case. */

                    if (bRx == 'i')
                    {
                        pRx->fIoPort = true;
                        pRx->cbAddr  = 4;
                    }
                    else if (bRx == 'm')
                    {
                        pRx->fIoPort = false;
                        pRx->cbAddr  = 8;
                    }
                    else if (bRx == 'M')
                    {
                        pRx->enmMemType = PSPX86ICEMEMTYPE_MMIO;
                        pRx->fIoPort    = false;
                        pRx->cbAddr     = 16;
                    }
                    else if (bRx == 'R')
                    {
                        pRx->enmMemType = PSPX86ICEMEMTYPE_RAM;
                        pRx->fIoPort    = false;
                        pRx->cbAddr     = 16;
                    }
                    else if (bRx == 'c')
                        rc = pspX86IceSerialIceMsrProcess(pThis, hTcpCon, pRx);
                    else
                        rc = STS_ERR_INVALID_PARAMETER;
                    break;
                case PSPX86SERIALICERXSTATE_ADDR:
                {
                    pRx->uAddr <<= 4;
                    pRx->uAddr |= pspX86IceSerialIceHexToNibble(bRx);
                    pRx->cbAddr--;

                    if (!pRx->cbAddr)
                        pRx->enmState = PSPX86SERIALICERXSTATE_DOT;
                    break;
                }
                case PSPX86SERIALICERXSTATE_DOT:
                {
                    if (bRx != '.')
                        rc = STS_ERR_INVALID_PARAMETER;
                    pRx->enmState = PSPX86SERIALICERXSTATE_WIDTH;
                    break;
                }
                case PSPX86SERIALICERXSTATE_WIDTH:
                {
                    if (bRx == 'b')
                        pRx->cb = 1;
                    else if (bRx == 'w')
                        pRx->cb = 2;
                    else if (bRx == 'l')
                        pRx->cb = 4;
                    else if (   bRx == 'q'
                             && !pRx->fIoPort)
                        pRx->cb = 8;
                    else
                        rc = STS_ERR_INVALID_PARAMETER;

                    /* For read commands we are done now and can process the command. */
                    if (   STS_SUCCESS(rc)
                        && pRx->fRead)
                        rc = pspX86IceSerialIceProcess(pThis, pRx, hTcpCon);
                    else
                    {
                        pRx->cbData = pRx->cb * 2;
                        pRx->enmState = PSPX86SERIALICERXSTATE_EQUAL;
                    }
                    break;
                }
                case PSPX86SERIALICERXSTATE_EQUAL:
                    if (bRx != '=')
                        rc = STS_ERR_INVALID_PARAMETER;
                    pRx->enmState = PSPX86SERIALICERXSTATE_DATA;
                    break;
                case PSPX86SERIALICERXSTATE_DATA:
                {
                    pRx->u64Val <<= 4;
                    pRx->u64Val |= pspX86IceSerialIceHexToNibble(bRx);
                    pRx->cbData--;

                    if (!pRx->cbData)
                        rc = pspX86IceSerialIceProcess(pThis, pRx, hTcpCon);
                    break;
                }
                case PSPX86SERIALICERXSTATE_INVALID:
                case PSPX86SERIALICERXSTATE_32BIT_HACK:
                default:
                    rc = STS_ERR_INVALID_PARAMETER;
                    break;
            }
        }
        else
            break;
    }

    return rc;
}


/**
 * The network thread mainloop.
 *
 * @returns Status code.
 * @param   hThread                 The thread handler.
 * @param   pvUser                  Opaque user data passed during thread creation.
 */
static int pspX86IceNetIoThrd(OSTHREAD hThread, void *pvUser)
{
    PPSPX86ICEINT pThis = (PPSPX86ICEINT)pvUser;
    OSTCPCON hTcpCon = NULL;
    PSPX86SERIALICERX RxState;

    while (!pThis->fThreadTerminate)
    {
        if (!hTcpCon)
        {
            int rc = OSTcpServerConnectionWaitFor(pThis->hTcpSrv, &hTcpCon, 100 /*cMsWait*/);
            if (STS_SUCCESS(rc))
            {
                /* Disable Nagle. */
                rc = OSTcpConnectionSendCoalescingSet(hTcpCon, false);
                /** @todo Log error but continue. */

                /* Send the data to indicate readiness. */
                rc = pspX86IceSerialIceRdySend(hTcpCon);
                if (STS_FAILURE(rc))
                {
                    /* Log error, close connection and continue. */
                    OSTcpConnectionClose(hTcpCon, false /*fShutdown*/);
                    hTcpCon = NULL;
                }
                else
                    pspX86IceSerialIceRxReset(&RxState);
            }
            /** @todo Assert RC timeout */
        }
        else
        {
            /* Check if we can read something. */
            uint32_t fEvtsRecv = 0;
            int rc = OSTcpConnectionPoll(hTcpCon, OSTCP_POLL_F_READ, &fEvtsRecv, 100 /*cMsWait*/);
            if (STS_SUCCESS(rc))
            {
                rc = pspX86IceSerialIceRecv(pThis, &RxState, hTcpCon);
                if (STS_FAILURE(rc))
                {
                    /* Some error happened, close connection and continue. */
                    OSTcpConnectionClose(hTcpCon, false /*fShutdown*/);
                    hTcpCon = NULL;
                }
            }
            else if (rc != STS_ERR_NOT_FOUND)
            {
                /* Some error happened, close connection and continue. */
                OSTcpConnectionClose(hTcpCon, false /*fShutdown*/);
                hTcpCon = NULL;
            }
        }
    }

    if (hTcpCon)
        OSTcpConnectionClose(hTcpCon, true /*fShutdown*/);

    return STS_INF_SUCCESS;
}


int PSPX86IceCreate(PPSPX86ICE phX86Ice, uint16_t uPort)
{
    int rc = STS_INF_SUCCESS;
    PPSPX86ICEINT pThis = (PPSPX86ICEINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->fThreadTerminate = false;

        rc = OSLockCreate(&pThis->hLock);
        if (STS_SUCCESS(rc))
        {
            rc = OSTcpServerCreate(&pThis->hTcpSrv, uPort);
            if (STS_SUCCESS(rc))
            {
                rc = OSThreadCreate(&pThis->hThreadIo, pspX86IceNetIoThrd, pThis);
                if (STS_SUCCESS(rc))
                {
                    *phX86Ice = pThis;
                    return STS_INF_SUCCESS;
                }

                OSTcpServerDestroy(pThis->hTcpSrv);
            }

            OSLockDestroy(pThis->hLock);
        }

        free(pThis);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


void PSPX86IceDestroy(PSPX86ICE hX86Ice)
{
    PPSPX86ICEINT pThis = hX86Ice;

    pThis->fThreadTerminate = true;
    /** @todo Wakeup network thread. */
    OSThreadDestroy(pThis->hThreadIo, NULL /*prcThread*/);
    OSTcpServerDestroy(pThis->hTcpSrv);
    free(pThis);
}


int PSPX86IceIoPortRwHandlerSet(PSPX86ICE hX86Ice, PFNPSPX86ICEIOPORTREAD pfnIoPortRead, PFNPSPX86ICEIOPORTWRITE pfnIoPortWrite, void *pvUser)
{
    PPSPX86ICEINT pThis = hX86Ice;

    OSLockAcquire(pThis->hLock);
    pThis->pfnIoPortRead  = pfnIoPortRead;
    pThis->pfnIoPortWrite = pfnIoPortWrite;
    pThis->pvUserIoPortRw = pvUser;
    OSLockRelease(pThis->hLock);

    return STS_INF_SUCCESS;
}


int PSPX86IceMemRwHandlerSet(PSPX86ICE hX86Ice, PFNPSPX86ICEMEMREAD pfnMemRead, PFNPSPX86ICEMEMWRITE pfnMemWrite, void *pvUser)
{
    PPSPX86ICEINT pThis = hX86Ice;

    OSLockAcquire(pThis->hLock);
    pThis->pfnMemRead   = pfnMemRead;
    pThis->pfnMemWrite  = pfnMemWrite;
    pThis->pvUserMemRw  = pvUser;
    OSLockRelease(pThis->hLock);

    return STS_INF_SUCCESS;
}


int PSPX86IceMsrRwHandlerSet(PSPX86ICE hX86Ice, PFNPSPX86ICEMSRREAD pfnMsrRead, PFNPSPX86ICEMSRWRITE pfnMsrWrite, void *pvUser)
{
    PPSPX86ICEINT pThis = hX86Ice;

    OSLockAcquire(pThis->hLock);
    pThis->pfnMsrRead   = pfnMsrRead;
    pThis->pfnMsrWrite  = pfnMsrWrite;
    pThis->pvUserMsrRw  = pvUser;
    OSLockRelease(pThis->hLock);

    return STS_INF_SUCCESS;
}

