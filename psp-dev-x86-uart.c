/** @file
 * PSP Emulator - UART like device living at 0xfffdfc0003f8 (on Ryzen Pro so far).
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <poll.h>
#include <sys/ioctl.h>

#include <common/cdefs.h>
#include <x86/uart.h>

#include <psp-devs.h>
#include <psp-trace.h>


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
            /** The listening socket. */
            int             iFdListening;
            /** The socket for the current connection. */
            int             iFdCon;
        } Sock;
    } u;
} PSPDEVUART;
/** Pointer to the device instance data. */
typedef PSPDEVUART *PPSPDEVUART;

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
                    struct pollfd PollFd;

                    PollFd.fd      = pThis->u.Sock.iFdCon;
                    PollFd.events  = POLLIN | POLLHUP | POLLERR;
                    PollFd.revents = 0;

                    int rcPsx = poll(&PollFd, 1, 0);
                    if (rcPsx == 1)
                    {
                        uRegLsr |= X86_UART_REG_LSR_DR;
                        ssize_t cbRet = recv(pThis->u.Sock.iFdCon, &pThis->u8RegRbr, 1, MSG_DONTWAIT);
                        if (cbRet != 1)
                            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                                    "Error reading data from socket: %zd", cbRet);
                        else
                            pThis->u.Sock.fDataRdy = true;
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
                                        115200 / pThis->u16Divisor,
                                        (pThis->u8RegLcr & 0x3) + 5,
                                        pThis->u8RegLcr & X86_UART_REG_LCR_PEN ? "O" : "N", /** @todo Not correct as even bit is not checked. */
                                        pThis->u8RegLcr & X86_UART_REG_LCR_STB ? 2 : 1);
            }
            else if (pThis->fSocket)
            {
                /* Socket mode, send data as is. */
                ssize_t cbSent = send(pThis->u.Sock.iFdCon, &bVal, 1, 0);
                if (cbSent != 1)
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                            "Failed to send data over socket: %zd", cbSent);
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
                                        &pThis->hMmio);
    if (   !rc
        && pDev->pCfg->pszUartRemoteAddr)
    {
        pThis->fSocket         = true;
        pThis->u.Sock.fDataRdy = false;

        /* Check for server mode. */
        char *pszSep = strchr(pDev->pCfg->pszUartRemoteAddr, ':');
        if (pszSep)
        {
            /* Client mode with hostname:port. */
            pThis->u.Sock.fSrv = false;
            *pszSep++ = '\0';
            struct hostent *pSrv = gethostbyname(pDev->pCfg->pszUartRemoteAddr);
            if (pSrv)
            {
                struct sockaddr_in SrvAddr;
                memset(&SrvAddr, 0, sizeof(SrvAddr));
                SrvAddr.sin_family = AF_INET;
                memcpy(&SrvAddr.sin_addr.s_addr, pSrv->h_addr, pSrv->h_length);
                SrvAddr.sin_port = htons(atoi(pszSep));

                pThis->u.Sock.iFdCon = socket(AF_INET, SOCK_STREAM, 0);
                if (pThis->u.Sock.iFdCon > -1)
                {
                    int rcPsx = connect(pThis->u.Sock.iFdCon,(struct sockaddr *)&SrvAddr,sizeof(SrvAddr));
                    if (rcPsx < 0)
                    {
                        printf("UART: Failed to connect to %s:%s\n", pDev->pCfg->pszUartRemoteAddr, pszSep);
                        close(pThis->u.Sock.iFdCon);
                        rc = -1;
                    }
                }
                else
                    rc = -1;
            }
            else
            {
                printf("UART: Error resolving %s\n", pDev->pCfg->pszUartRemoteAddr);
                rc = -1;
            }
        }
        else
        {
            /* Server mode, create sockets and wait for an incoming connection before continuing. */
            struct sockaddr_in SockAddr;

            pThis->u.Sock.fSrv         = true;
            pThis->u.Sock.iFdListening = socket(AF_INET, SOCK_STREAM, 0);
            if (pThis->u.Sock.iFdListening > -1)
            {
                memset(&SockAddr, 0, sizeof(SockAddr));

                SockAddr.sin_family      = AF_INET;
                SockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
                SockAddr.sin_port        = htons(atoi(pDev->pCfg->pszUartRemoteAddr));
                int rcPsx = bind(pThis->u.Sock.iFdListening, (struct sockaddr *)&SockAddr, sizeof(SockAddr));
                if (!rcPsx)
                {
                    printf("UART: Waiting for incoming connection...\n");
                    rcPsx = listen(pThis->u.Sock.iFdListening, 1);
                    if (!rcPsx)
                    {
                        pThis->u.Sock.iFdCon = accept(pThis->u.Sock.iFdListening, (struct sockaddr *)NULL, NULL);
                        if (pThis->u.Sock.iFdCon == -1)
                        {
                            pThis->u.Sock.iFdCon = 0;
                            rc = -1;
                        }
                    }
                    else
                        rc = -1;
                }
                else
                    rc = -1;

                close(pThis->u.Sock.iFdListening);
            }
            else
                rc = -1;
        }
    }

    return rc;
}


static void pspDevX86UartDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
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

