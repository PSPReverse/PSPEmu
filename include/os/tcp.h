/** @file
 * PSP Emulator - OS abstraction for TCP server/client connections.
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
#ifndef INCLUDED_os_tcp_h
#define INCLUDED_os_tcp_h

#include <common/types.h>

/** Opaque TCP connection handle. */
typedef struct OSTCPCONINT *OSTCPCON;
/** Pointer to a TCP connection handle. */
typedef OSTCPCON *POSTCPCON;


/** Opaque TCP server handle. */
typedef struct OSTCPSRVINT *OSTCPSRV;
/** Pointer to a TCP server handle. */
typedef OSTCPSRV *POSTCPSRV;


/** Wait until data can be read from the connection. */
#define OSTCP_POLL_F_READ           BIT(0)
/** Wait until data can be written to the connection. */
#define OSTCP_POLL_F_WRITE          BIT(1)
/** Wait until an error occurred. */
#define OSTCP_POLL_F_ERROR          BIT(2)


/**
 * Tries to connect to the given remote server and returns a TCP client connection.
 *
 * @returns Status code.
 * @param   phThread                Where to store the handle to the thread on success.
 * @param   pfnMain                 The handler to call on the created thread.
 * @param   pvUser                  Opaque user data to pass to the thread handler.
 */
int OSTcpClientConnect(POSTCPCON phTcpCon, const char *pszHostname, uint16_t uPort);


/**
 * Close the given TCP connection.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection to close.
 * @param   fShutdown               Flag whether to do an orderly shutdown of the connection.
 */
int OSTcpConnectionClose(OSTCPCON hTcpCon, bool fShutdown);


/**
 * Enabled or disable send coalescing aka. Nagles algorithm.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection to configure.
 * @param   fEnable                 Flag whether to enable or disable send coalescing.
 */
int OSTcpConnectionSendCoalescingSet(OSTCPCON hTcpCon, bool fEnable);


/**
 * Tries to read the given number of bytes from the given client connection.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection.
 * @param   pvBuf                   Where to store the read data.
 * @param   cbRead                  How much to read.
 * @param   pcbRead                 Where to store the actual number of bytes read, optional.
 *                                  If NULL the call will block until either the given number of bytes
 *                                  where read or an error occured.
 */
int OSTcpConnectionRead(OSTCPCON hTcpCon, void *pvBuf, size_t cbRead, size_t *pcbRead);


/**
 * Tries to write the given number of bytes to the given client connection.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection.
 * @param   pvBuf                   The data to write.
 * @param   cbWrite                 How much to write.
 * @param   pcbWritten              Where to store the actual number of bytes written, optional.
 *                                  If NULL the call will block until either the given number of bytes
 *                                  where written or an error occured.
 */
int OSTcpConnectionWrite(OSTCPCON hTcpCon, const void *pvBuf, size_t cbWrite, size_t *pcbWritten);


/**
 * Polls the given TCP connection until one of the given events occurs.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection.
 * @param   fEvt                    Combination of events to wait for, see OSTCP_POLL_F_XXX.
 * @param   pfEvtsRecv              Where to store the mask of events received upon success.
 * @param   cMsWait                 How many milliseconds to wait, UINT32_MAX for indefinite wait.
 */
int OSTcpConnectionPoll(OSTCPCON hTcpCon, uint32_t fEvt, uint32_t *pfEvtsRecv, uint32_t cMsWait);


/**
 * Peeks for the amount of data available for immediate reading.
 *
 * @returns Status code.
 * @param   hTcpCon                 The TCP connection.
 * @param   pcbRead                 Where to store the amount of bytes available for reading.
 */
int OSTcpConnectionPeek(OSTCPCON hTcpCon, size_t *pcbRead);


/**
 * Creates a TCP server instance listening on the given port.
 *
 * @returns Status code.
 * @param   phTcpSrv                Where to store the handle to the TCP server instance on success.
 * @param   uPort                   The port to listen on.
 */
int OSTcpServerCreate(POSTCPSRV phTcpSrv, uint16_t uPort);


/**
 * Destroys the given TCP server handle.
 *
 * @returns Status code.
 * @param   hTcpSrv                 The TCP server handle to destroy.
 */
int OSTcpServerDestroy(OSTCPSRV hTcpSrv);


/**
 * Waits for a new connection on the given TCP server instance.
 *
 * @returns Status code.
 * @param   hTcpSrv                 The TCP server instance to wait on.
 * @param   phTcpCon                Where to store the handle to the new connection upon success.
 * @param   cMsWait                 How many milliseconds to wait before timing out.
 */
int OSTcpServerConnectionWaitFor(OSTCPSRV hTcpSrv, POSTCPCON phTcpCon, uint32_t cMsWait);

#endif /* !INCLUDED_os_tcp_h */
