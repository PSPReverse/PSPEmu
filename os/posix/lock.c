/** @file
 * PSP Emulator - OS abstraction for lock related APIs, Posix implementation.
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

#include <os/lock.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/**
 * Internal POSIX lock instance based on pthreads mutex implementation.
 */
typedef struct OSLOCKINT
{
    /** The pthread mutex handle. */
    pthread_mutex_t                 hMtx;
} OSLOCKINT;
/** Pointer to a the lock instance. */
typedef OSLOCKINT *POSLOCKINT;
/** Pointer to a const lock instance. */
typedef const OSLOCKINT *PCOSLOCKINT;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

int OSLockCreate(POSLOCK phLock)
{
    int rc = STS_INF_SUCCESS;
    POSLOCKINT pThis = (POSLOCKINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        int rcPsx = pthread_mutex_init(&pThis->hMtx, NULL /*attr*/);
        if (!rcPsx)
        {
            *phLock = pThis;
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


int OSLockDestroy(OSLOCK hLock)
{
    POSLOCKINT pThis = hLock;
    int rc = STS_INF_SUCCESS;
    int rcPsx = pthread_mutex_destroy(&pThis->hMtx);
    if (!rcPsx)
        free(pThis);
    else
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


int OSLockAcquire(OSLOCK hLock)
{
    POSLOCKINT pThis = hLock;
    int rc = STS_INF_SUCCESS;
    int rcPsx = pthread_mutex_lock(&pThis->hMtx);
    if (rcPsx)
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


int OSLockRelease(OSLOCK hLock)
{
    POSLOCKINT pThis = hLock;
    int rc = STS_INF_SUCCESS;
    int rcPsx = pthread_mutex_unlock(&pThis->hMtx);
    if (rcPsx)
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}

