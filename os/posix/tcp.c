/** @file
 * PSP Emulator - OS abstraction for TCP server/client connections, Posix implementation.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>

#include <common/status.h>
#include <common/cdefs.h>

#include <os/tcp.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/**
 * Internal TCP connection state.
 */
typedef struct OSTCPCONINT
{
    /** Socket descriptor. */
    int                             iFdSock;
} OSTCPCONINT;
/** Pointer to the internal TCP connection state. */
typedef OSTCPCONINT *POSTCPCONINT;
/** Pointer to a const internal TCP connection state. */
typedef const OSTCPCONINT *PCOSTCPCONINT;


/**
 * Internal TCP server state.
 */
typedef struct OSTCPSRVINT
{
    /** Server socket descriptor. */
    int                             iFdSrv;
} OSTCPSRVINT;
/** Pointer to the internal TCP connection state. */
typedef OSTCPSRVINT *POSTCPSRVINT;
/** Pointer to a const internal TCP connection state. */
typedef const OSTCPSRVINT *PCOSTCPSRVINT;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

int OSTcpClientConnect(POSTCPCON phTcpCon, const char *pszHostname, uint16_t uPort)
{
    int rc = STS_INF_SUCCESS;

    struct hostent *pSrv = gethostbyname(pszHostname);
    if (pSrv)
    {
        struct sockaddr_in SrvAddr;
        memset(&SrvAddr, 0, sizeof(SrvAddr));
        SrvAddr.sin_family = AF_INET;
        SrvAddr.sin_port = htons(uPort);
        memcpy(&SrvAddr.sin_addr.s_addr, pSrv->h_addr, pSrv->h_length);

        POSTCPCONINT pThis = (POSTCPCONINT)calloc(1, sizeof(*pThis));
        if (pThis)
        {
            pThis->iFdSock = socket(AF_INET, SOCK_STREAM, 0);
            if (pThis->iFdSock > -1)
            {
                int rcPsx = connect(pThis->iFdSock, (struct sockaddr *)&SrvAddr, sizeof(SrvAddr));
                if (!rcPsx)
                {
                    *phTcpCon = pThis;
                    return STS_INF_SUCCESS;
                }
                else
                    rc = STS_ERR_INVALID_PARAMETER; /** @todo Status code. */

                close(pThis->iFdSock);
            }
            else
                rc = STS_ERR_INVALID_PARAMETER; /** @todo Status code. */

            free(pThis);
        }
        else
            rc = STS_ERR_NO_MEMORY;
    }
    else
        rc = STS_ERR_NOT_FOUND;

    return rc;
}


int OSTcpConnectionClose(OSTCPCON hTcpCon, bool fShutdown)
{
    POSTCPCONINT pThis = hTcpCon;

    if (fShutdown)
        shutdown(pThis->iFdSock, SHUT_RDWR); /* Ignore any errors here. */
    close(pThis->iFdSock);
    free(pThis);
    return STS_INF_SUCCESS;
}


int OSTcpConnectionSendCoalescingSet(OSTCPCON hTcpCon, bool fEnable)
{
    int rc = STS_INF_SUCCESS;
    POSTCPCONINT pThis = hTcpCon;
    int iFlag = fEnable ? 1 : 0;

    int rcPsx = setsockopt(pThis->iFdSock, IPPROTO_TCP, TCP_NODELAY, &iFlag, sizeof(iFlag));
    if (rcPsx)
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


int OSTcpConnectionRead(OSTCPCON hTcpCon, void *pvBuf, size_t cbRead, size_t *pcbRead)
{
    int rc = STS_INF_SUCCESS;
    POSTCPCONINT pThis = hTcpCon;
    int fRecvFlags = pcbRead == NULL ? 0 : MSG_DONTWAIT;

    ssize_t rcPsx = recv(pThis->iFdSock, pvBuf, cbRead, fRecvFlags);
    if (rcPsx > 0)
    {
        if (pcbRead)
            *pcbRead = rcPsx;
    }
    else if (!rcPsx) /* Client disconnected. */
        rc = STS_ERR_NOT_FOUND; /** @todo Better status code. */
    else if (   (errno == EAGAIN || errno == EWOULDBLOCK)
             && pcbRead)
        *pcbRead = 0;
    else
        rc = STS_ERR_INVALID_PARAMETER; /** @todo Status code. */

    return rc;
}


int OSTcpConnectionWrite(OSTCPCON hTcpCon, const void *pvBuf, size_t cbWrite, size_t *pcbWritten)
{
    int rc = STS_INF_SUCCESS;
    POSTCPCONINT pThis = hTcpCon;
    int fSendFlags = pcbWritten == NULL ? 0 : MSG_DONTWAIT;

    ssize_t rcPsx = send(pThis->iFdSock, pvBuf, cbWrite, fSendFlags);
    if (rcPsx >= 0)
    {
        if (pcbWritten)
            *pcbWritten = rcPsx;
    }
    else if (   (errno == EAGAIN || errno == EWOULDBLOCK)
             && pcbWritten)
        *pcbWritten = 0;
    else
        rc = STS_ERR_INVALID_PARAMETER; /** @todo Status code. */

    return rc;
}


int OSTcpConnectionPoll(OSTCPCON hTcpCon, uint32_t fEvt, uint32_t *pfEvtsRecv, uint32_t cMsWait)
{
    POSTCPCONINT pThis = hTcpCon;

    struct pollfd PollFd;
    PollFd.fd      = pThis->iFdSock;
    PollFd.events  = 0;
    PollFd.revents = 0;

    if (fEvt & OSTCP_POLL_F_READ)
        PollFd.events |= POLLIN;
    if (fEvt & OSTCP_POLL_F_WRITE)
        PollFd.events |= POLLOUT;
    if (fEvt & OSTCP_POLL_F_ERROR)
        PollFd.events |= POLLHUP | POLLERR;

    int rc = STS_INF_SUCCESS;
    int rcPsx = poll(&PollFd, 1, cMsWait < UINT32_MAX ? cMsWait : -1);
    if (rcPsx == 1)
    {
        if (PollFd.revents & POLLIN)
            *pfEvtsRecv |= OSTCP_POLL_F_READ;
        if (PollFd.revents & POLLOUT)
            *pfEvtsRecv |= OSTCP_POLL_F_WRITE;
        if (PollFd.revents & POLLERR)
            *pfEvtsRecv |= OSTCP_POLL_F_ERROR;
    }
    else if (!rcPsx)
        rc = STS_ERR_NOT_FOUND; /** @todo Better status code. */
    else
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


int OSTcpConnectionPeek(OSTCPCON hTcpCon, size_t *pcbRead)
{
    POSTCPCONINT pThis = hTcpCon;

    int cbAvail = 0;
    int rc = STS_INF_SUCCESS;
    int rcPsx = ioctl(hTcpCon->iFdSock, FIONREAD, &cbAvail);
    if (rcPsx)
        rc = STS_ERR_NOT_FOUND; /** @todo Better status code. */

    *pcbRead = cbAvail;
    return rc;
}


int OSTcpServerCreate(POSTCPSRV phTcpSrv, uint16_t uPort)
{
    int rc = STS_INF_SUCCESS;
    POSTCPSRVINT pThis = (POSTCPSRVINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->iFdSrv = socket(AF_INET, SOCK_STREAM, 0);
        if (pThis->iFdSrv > -1)
        {
            struct sockaddr_in SockAddr;

            memset(&SockAddr, 0, sizeof(SockAddr));
            SockAddr.sin_family      = AF_INET;
            SockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
            SockAddr.sin_port        = htons(uPort);
            int rcPsx = bind(pThis->iFdSrv, (struct sockaddr *)&SockAddr, sizeof(SockAddr));
            if (!rcPsx)
            {
                rcPsx = listen(pThis->iFdSrv, 1);
                if (!rcPsx)
                {
                    *phTcpSrv = pThis;
                    return STS_INF_SUCCESS;
                }
                else
                    rc = STS_ERR_INVALID_PARAMETER; /** @todo Status code. */
            }
            else
                rc = STS_ERR_INVALID_PARAMETER; /** @todo Status code. */

            close(pThis->iFdSrv);
        }
        else
            rc = STS_ERR_INVALID_PARAMETER; /** @todo Status code. */

        free(pThis);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


int OSTcpServerDestroy(OSTCPSRV hTcpSrv)
{
    POSTCPSRVINT pThis = hTcpSrv;

    close(pThis->iFdSrv);
    free(pThis);
    return STS_INF_SUCCESS;
}


int OSTcpServerConnectionWaitFor(OSTCPSRV hTcpSrv, POSTCPCON phTcpCon, uint32_t cMsWait)
{
    int rc = STS_INF_SUCCESS;
    POSTCPSRVINT pThis = hTcpSrv;

    /* Poll on the server socket so we can time out. */
    struct pollfd PollFd;

    PollFd.fd      = pThis->iFdSrv;
    PollFd.events  = POLLIN;
    PollFd.revents = 0;
    int rcPsx = poll(&PollFd, 1, cMsWait < UINT32_MAX ? cMsWait : -1);
    if (rcPsx == 1)
    {
        int iFdCon = accept(pThis->iFdSrv, (struct sockaddr *)NULL, NULL);
        if (iFdCon > -1)
        {
            POSTCPCONINT pTcpCon = (POSTCPCONINT)calloc(1, sizeof(*pTcpCon));
            if (pThis)
            {
                pTcpCon->iFdSock = iFdCon;
                *phTcpCon = pTcpCon;
                return STS_INF_SUCCESS;
            }
            else
                rc = STS_ERR_NO_MEMORY;

            close(iFdCon);
        }
        else
            rc = STS_ERR_INVALID_PARAMETER;
    }
    else if (!rcPsx)
        rc = STS_ERR_NOT_FOUND; /** @todo Better status code. */
    else
        rc = STS_ERR_INVALID_PARAMETER; /** @todo Better status code. */

    return rc;
}

