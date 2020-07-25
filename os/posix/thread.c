/** @file
 * PSP Emulator - OS abstraction for threads, Posix implementation.
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
#include <pthread.h>
#include <stdlib.h>

#include <common/status.h>
#include <common/cdefs.h>

#include <os/thread.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/**
 * Internal POSIX thread instance based on pthreads implementation.
 */
typedef struct OSTHREADINT
{
    /** The pthread handle. */
    pthread_t                       hPThrd;
    /** The handler to call. */
    PFNOSTHREADMAIN                 pfnMain;
    /** Opaque user data to pass. */
    void                            *pvUser;
    /** Status code upon exit. */
    int                             rcExit;
} OSTHREADINT;
/** Pointer to a the thread instance. */
typedef OSTHREADINT *POSTHREADINT;
/** Pointer to a const thread instance. */
typedef const OSTHREADINT *PCOSTHREADINT;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

/**
 * Posix thread entry point.
 *
 * @returns Opaque return value.
 * @param   pvArg                   Opaque user data.
 */
static void *osThreadPosixMain(void *pvArg)
{
    POSTHREADINT pThis = (POSTHREADINT)pvArg;

    int rc = pThis->pfnMain(pThis, pThis->pvUser);
    pThis->rcExit = rc;

    return NULL;
}


int OSThreadCreate(POSTHREAD phThread, PFNOSTHREADMAIN pfnMain, void *pvUser)
{
    int rc = STS_INF_SUCCESS;
    POSTHREADINT pThis = (POSTHREADINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->pfnMain = pfnMain;
        pThis->pvUser  = pvUser;

        int rcPsx = pthread_create(&pThis->hPThrd, NULL /*attr*/, osThreadPosixMain, pThis);
        if (!rcPsx)
        {
            *phThread = pThis;
            return STS_INF_SUCCESS;
        }
        else
            rc = STS_ERR_INVALID_PARAMETER; /** @todo Status codes. */

        free(pThis);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


int OSThreadDestroy(OSTHREAD hThread, int *prcThread)
{
    POSTHREADINT pThis = hThread;

    int rc = STS_INF_SUCCESS;
    int rcPsx = pthread_join(pThis->hPThrd, NULL);
    if (!rcPsx)
    {
        if (prcThread)
            *prcThread = pThis->rcExit;
        free(pThis);
    }
    else
        rc = STS_ERR_INVALID_PARAMETER; /** @todo Status code. */

    return rc;
}

