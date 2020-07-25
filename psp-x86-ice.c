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
    /** Flag whether the thread should temrinate. */
    volatile bool                   fThreadTerminate;
    /** I/O port read handler .*/
    PFNPSPX86ICEIOPORTREAD          pfnIoPortRead;
    /** I/O port write handler .*/
    PFNPSPX86ICEIOPORTWRITE         pfnIoPortWrite;
    /** Opaque user data to pass to the I/O port read/write handlers. */
    void                            *pvUserIoPortRw;
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
    PSPX86SERIALICERXSTATE           enmState;
    /** Flag whether to read or write. */
    bool                            fRead;
    /** Flag whether an I/O port or an MMIO address should be accessed. */
    bool                            fIoPort;
    /** Number if address bytes left. */
    size_t                          cbAddr;
    /** The address to access. */
    uint32_t                        uAddr;
    /** Access width. */
    size_t                          cb;
    /** Number of data bytes to receive for writes. */
    size_t                          cbData;
    /** Data to write during writes. */
    uint32_t                        u32Val;
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
        return bVal - 'a';
    else if (bVal >= 'A' && bVal <= 'F')
        return bVal - 'A';

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
    pRx->enmState = PSPX86SERIALICERXSTATE_CMD_MARKER_WAIT;
    pRx->fRead    = false;
    pRx->fIoPort  = false;
    pRx->cbAddr   = 0;
    pRx->uAddr    = 0;
    pRx->cb       = 0;
    pRx->cbData   = 0;
    pRx->u32Val   = 0;
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
                    Val.u8 = (uint8_t)pRx->u32Val;
                    break;
                case 2:
                    Val.u16 = (uint16_t)pRx->u32Val;
                    break;
                case 4:
                    Val.u32 = pRx->u32Val;
                    break;
            }

            rc = pfnIoPortWrite(pThis, (uint16_t)pRx->uAddr, pRx->cb, &Val.ab[0], pvUserIoPortRw);
        }
    }
    else /** @todo Memory */
        rc = STS_ERR_NOT_FOUND;

    if (   STS_SUCCESS(rc)
        && pRx->fRead)
    {
        /* Send response. */

        uint32_t u32Read = 0;
        switch (pRx->cb)
        {
            default: /* Should never happen. */
            case 1:
                u32Read = Val.u8;
                break;
            case 2:
                u32Read = Val.u16;
                break;
            case 4:
                u32Read = Val.u32;
                break;
        }

        uint8_t abResp[8] = { 0 };
        for (uint32_t i = 0; i < pRx->cb * 2; i += 2)
        {
            abResp[i]     = s_abHexToChr[(u32Read >> 4) & 0xf];
            abResp[i + 1] = s_abHexToChr[u32Read & 0xf];
            u32Read >>= 8;
        }

        rc = OSTcpConnectionWrite(hTcpCon, &abResp[0], pRx->cb * 2, NULL /*pcbWritten*/);
    }

    /* Send new readiness symbol. */
    if (STS_SUCCESS(rc))
    {
        uint8_t achReady[3] = { '>', '\r', '\n' };
        rc = OSTcpConnectionWrite(hTcpCon, &achReady[0], sizeof(achReady), NULL /*pcbWritten*/);
    }

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
        if (STS_SUCCESS(rc))
        {
            /** @todo Assert cbRead == 1 */
            switch (pRx->enmState)
            {
                case PSPX86SERIALICERXSTATE_CMD_MARKER_WAIT:
                    if (bRx == '*')
                        pRx->enmState = PSPX86SERIALICERXSTATE_RW_WAIT;
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
                    else
                        rc = STS_ERR_INVALID_PARAMETER;
                    pRx->enmState = PSPX86SERIALICERXSTATE_ADDR; /* Doesn't matter in error case. */
                case PSPX86SERIALICERXSTATE_ADDR:
                {
                    pRx->uAddr <<= 4;
                    pRx->uAddr |= pspX86IceSerialIceHexToNibble(bRx);
                    pRx->cbAddr--;

                    if (!pRx->cbAddr)
                        pRx->enmState = PSPX86SERIALICERXSTATE_DOT;
                }
                case PSPX86SERIALICERXSTATE_DOT:
                {
                    if (bRx != '.')
                        rc = STS_ERR_INVALID_PARAMETER;
                    pRx->enmState = PSPX86SERIALICERXSTATE_WIDTH;
                }
                case PSPX86SERIALICERXSTATE_WIDTH:
                {
                    if (bRx == 'b')
                        pRx->cb = 1;
                    else if (bRx == 'w')
                        pRx->cb = 2;
                    else if (bRx == 'l')
                        pRx->cb = 4;
                    else
                        rc = STS_ERR_INVALID_PARAMETER;

                    /* For read commands we are done now and can process the command. */
                    if (   STS_SUCCESS(rc)
                        && pRx->fRead)
                        rc = pspX86IceSerialIceProcess(pThis, pRx, hTcpCon);
                    else
                    {
                        pRx->cbData *= 2;
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
                    pRx->u32Val <<= 4;
                    pRx->u32Val |= pspX86IceSerialIceHexToNibble(bRx);
                    pRx->cbData--;

                    if (!pRx->cbData)
                        rc = pspX86IceSerialIceProcess(pThis, pRx, hTcpCon);
                    break;
                }
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
                uint8_t achReady[3] = { '>', '\r', '\n' };
                rc = OSTcpConnectionWrite(hTcpCon, &achReady[0], sizeof(achReady), NULL /*pcbWritten*/);
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
                if (STS_SUCCESS(rc))
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

