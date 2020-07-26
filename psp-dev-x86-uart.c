/** @file
 * PSP Emulator - UART like device living at 0xfffdfc0003f8 (on Ryzen Pro so far).
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <common/cdefs.h>
#include <common/status.h>
#include <x86/uart.h>

#include <os/tcp.h>

#include <psp-devs.h>
#include <psp-trace.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/**
 * Unknown device instance data.
 */
typedef struct PSPDEVUART
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE      hMmio;
    /** LCR register value. */
    uint8_t                 u8RegLcr;
    /** RBR register value. */
    uint8_t                 u8RegRbr;
    /** Divisor determining the baud rate. */
    uint16_t                u16Divisor;
    /** Flag whether socket mode is configured. */
    bool                    fSocket;
    /** Mode dependent data. */
    union
    {
        /** Normal logging to the trace log. */
        struct
        {
            /** Temporary char buffer. */
            uint8_t         achBuf[512];
            /** Where to write next. */
            uint32_t        offWrite;
        } Log;
        /** Socket mode related members. */
        struct
        {
            /** Flag whether this is server mode. */
            bool            fSrv;
            /** Flag whether there is data to read on the socket. */
            bool            fDataRdy;
            /** The server socket if in server mode. */
            OSTCPSRV        hTcpSrv;
            /** The socket for the current connection. */
            OSTCPCON        hTcpCon;
        } Sock;
    } u;
} PSPDEVUART;
/** Pointer to the device instance data. */
typedef PSPDEVUART *PPSPDEVUART;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

static void pspDevX86UartRead(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVUART pThis = (PPSPDEVUART)pvUser;

    if (cbRead != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    uint8_t *pbVal = (uint8_t *)pvVal;
    switch (offMmio)
    {
        case X86_UART_REG_RBR_OFF:
        {
            if (pThis->u.Sock.fDataRdy)
                pThis->u.Sock.fDataRdy = false;
            *pbVal = pThis->u8RegRbr;
            break;
        }
        case X86_UART_REG_LSR_OFF:
        {
            uint8_t uRegLsr = X86_UART_REG_LSR_THRE | X86_UART_REG_LSR_TEMT; /* We can always take data. */

            /* Check whether there is data available in socket mode. */
            if (pThis->fSocket)
            {
                if (!pThis->u.Sock.fDataRdy)
                {
                    if (pThis->u.Sock.hTcpCon)
                    {
                        uint32_t fEvtsRecv = 0;
                        int rc = OSTcpConnectionPoll(pThis->u.Sock.hTcpCon, OSTCP_POLL_F_READ | OSTCP_POLL_F_ERROR, &fEvtsRecv, 0 /*cMsWait*/);
                        if (STS_SUCCESS(rc))
                        {
                            if (fEvtsRecv & OSTCP_POLL_F_READ)
                            {
                                rc = OSTcpConnectionRead(pThis->u.Sock.hTcpCon, &pThis->u8RegRbr, 1, NULL /*pcbRead*/);
                                if (STS_SUCCESS(rc))
                                    pThis->u.Sock.fDataRdy = true;
                                else
                                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                                            "Error reading data from socket: %d", rc);
                            }
                        }
                    }
                }
                else
                    uRegLsr |= X86_UART_REG_LSR_DR;
            }

            *pbVal = uRegLsr;
            break;
        }
        case X86_UART_REG_IER_OFF:
        {
            *pbVal = X86_UART_REG_IIR_NOT_PENDING; /* Required for the UART detection logic. */
            break;
        }
        case X86_UART_REG_LCR_OFF:
        {
            *pbVal = pThis->u8RegLcr;
            break;
        }
        default:
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                    "Register %u not implemented", offMmio);
    }
}

static void pspDevX86UartWrite(X86PADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVUART pThis = (PPSPDEVUART)pvUser;

    if (cbWrite != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        return;
    }

    uint8_t bVal = *(const uint8_t *)pvVal;
    switch (offMmio)
    {
        case X86_UART_REG_THR_OFF:
        /*case X86_UART_REG_DL_MSB_OFF:*/
        {
            /* Set divisor if DLAB is set. */
            if (pThis->u8RegLcr & X86_UART_REG_LCR_DLAB)
            {
                pThis->u16Divisor = (pThis->u16Divisor & 0xff00) | (uint16_t)bVal;

                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_X86_UART,
                                        "Line parameters set to %u %u%s%u",
                                        115200 / (pThis->u16Divisor ? pThis->u16Divisor : 115200),
                                        (pThis->u8RegLcr & 0x3) + 5,
                                        pThis->u8RegLcr & X86_UART_REG_LCR_PEN ? "O" : "N", /** @todo Not correct as even bit is not checked. */
                                        pThis->u8RegLcr & X86_UART_REG_LCR_STB ? 2 : 1);
            }
            else if (pThis->fSocket)
            {
                /* Socket mode, send data as is. */
                if (pThis->u.Sock.hTcpCon)
                {
                    int rc = OSTcpConnectionWrite(pThis->u.Sock.hTcpCon, &bVal, 1, NULL /*pcbWritten*/);
                    if (STS_FAILURE(rc))
                        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                                "Failed to send data over socket: %d", rc);
                }
            }
            else if (bVal != '\r') /* Ignore carriage return. */
            {
                /* Store character. */
                if (pThis->u.Log.offWrite < sizeof(pThis->u.Log.achBuf))
                {
                    pThis->u.Log.achBuf[pThis->u.Log.offWrite] = bVal;
                    if (bVal == '\n')
                    {
                        pThis->u.Log.achBuf[pThis->u.Log.offWrite] = '\0';
                        /* Dump to the trace log and reset the buffer. */
                        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_X86_UART,
                                                "%s", &pThis->u.Log.achBuf[0]);
                        pThis->u.Log.offWrite = 0;
                    }
                    else
                        pThis->u.Log.offWrite++;
                }
                else
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                            "Buffer too small");
            }
            break;
        }
        case X86_UART_REG_LCR_OFF:
        {
            pThis->u8RegLcr = bVal;
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_X86_UART,
                                    "Line parameters set to %u %u%s%u",
                                    115200 / pThis->u16Divisor,
                                        (pThis->u8RegLcr & 0x3) + 5,
                                    pThis->u8RegLcr & X86_UART_REG_LCR_PEN ? "O" : "N", /** @todo Not correct as even bit is not checked. */
                                    pThis->u8RegLcr & X86_UART_REG_LCR_STB ? 2 : 1);
            break;
        }
        case X86_UART_REG_DL_MSB_OFF:
        /*case X86_UART_REG_IER_OFF:*/
        {
            /* Set divisor if DLAB is set. */
            if (pThis->u8RegLcr & X86_UART_REG_LCR_DLAB)
            {
                pThis->u16Divisor = (pThis->u16Divisor & 0xff) | ((uint16_t)bVal << 8);

                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_X86_UART,
                                        "Line parameters set to %u %u%s%u",
                                        115200 / pThis->u16Divisor,
                                        (pThis->u8RegLcr & 0x3) + 5,
                                        pThis->u8RegLcr & X86_UART_REG_LCR_PEN ? "O" : "N", /** @todo Not correct as even bit is not checked. */
                                        pThis->u8RegLcr & X86_UART_REG_LCR_STB ? 2 : 1);
            }
            /* else Ignore access to IER. */

            break;
        }
        case X86_UART_REG_LSR_OFF:
            break; /* Ignore. */
        default:
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                    "Register %u not implemented", offMmio);
    }
}

static int pspDevX86UartInit(PPSPDEV pDev)
{
    PPSPDEVUART pThis = (PPSPDEVUART)&pDev->abInstance[0];

    pThis->pDev           = pDev;
    pThis->fSocket        = false;
    pThis->u.Log.offWrite = 0;
    pThis->u8RegRbr       = 1; /* Required for the detection logic. */
    pThis->u8RegLcr       = 0;
    pThis->u16Divisor     = 1; /* 115200 baud */
    X86_UART_REG_LCR_WLS_SET(pThis->u8RegLcr, X86_UART_REG_LCR_WLS_8); /* Required for the UART detection logic. */

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfffdfc0003f8, 8,
                                        pspDevX86UartRead, pspDevX86UartWrite, pThis,
                                        "X86Uart", &pThis->hMmio);
    if (   !rc
        && pDev->pCfg->pszUartRemoteAddr)
    {
        pThis->fSocket         = true;
        pThis->u.Sock.fDataRdy = false;
        pThis->u.Sock.hTcpSrv  = NULL;
        pThis->u.Sock.hTcpCon  = NULL;

        /* Check for server mode. */
        char *pszSep = strchr(pDev->pCfg->pszUartRemoteAddr, ':');
        if (pszSep)
        {
            /* Client mode with hostname:port. */
            pThis->u.Sock.fSrv = false;
            *pszSep++ = '\0';
            int rc = OSTcpClientConnect(&pThis->u.Sock.hTcpCon, pDev->pCfg->pszUartRemoteAddr, atoi(pszSep));
            if (STS_FAILURE(rc))
                printf("UART: Failed to connect to %s:%s\n", pDev->pCfg->pszUartRemoteAddr, pszSep);
        }
        else
        {
            pThis->u.Sock.fSrv         = true;

            /* Server mode, create sockets and wait for an incoming connection before continuing. */
            int rc  = OSTcpServerCreate(&pThis->u.Sock.hTcpSrv, atoi(pDev->pCfg->pszUartRemoteAddr));
            if (STS_SUCCESS(rc))
            {
                printf("UART: Waiting for incoming connection...\n");
                rc = OSTcpServerConnectionWaitFor(pThis->u.Sock.hTcpSrv, &pThis->u.Sock.hTcpCon, UINT32_MAX /*cMsWait*/);
                if (STS_FAILURE(rc))
                {
                    printf("UART: Waiting for incoming connection failed with %d\n", rc);
                    OSTcpServerDestroy(pThis->u.Sock.hTcpSrv);
                    pThis->u.Sock.hTcpSrv = NULL;
                }
            }
            else
                printf("UART: Creating server on port %u failed with %d\n", pDev->pCfg->pszUartRemoteAddr, rc);
        }
    }

    return rc;
}


static void pspDevX86UartDestruct(PPSPDEV pDev)
{
    PPSPDEVUART pThis = (PPSPDEVUART)&pDev->abInstance[0];

    if (pThis->u.Sock.fSrv)
    {
        if (pThis->u.Sock.hTcpCon)
            OSTcpConnectionClose(pThis->u.Sock.hTcpCon, true /*fShutdown*/);
        if (pThis->u.Sock.hTcpSrv)
            OSTcpServerDestroy(pThis->u.Sock.hTcpSrv);

        pThis->u.Sock.hTcpCon = NULL;
        pThis->u.Sock.hTcpSrv = NULL;
    }
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegX86Uart =
{
    /** pszName */
    "x86-uart",
    /** pszDesc */
    "Standard x86 UART",
    /** cbInstance */
    sizeof(PSPDEVUART),
    /** pfnInit */
    pspDevX86UartInit,
    /** pfnDestruct */
    pspDevX86UartDestruct,
    /** pfnReset */
    NULL
};

