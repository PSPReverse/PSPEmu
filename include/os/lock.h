/** @file
 * PSP Emulator - OS abstraction for semaphores, mutexes, etc.
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
#ifndef INCLUDED_os_lock_h
#define INCLUDED_os_lock_h

#include <common/types.h>

/** Opaque lock handle. */
typedef struct OSLOCKINT *OSLOCK;
/** Pointer to a lock handle. */
typedef OSLOCK *POSLOCK;


/**
 * Creates a default lock.
 *
 * @returns Status code.
 * @param   phLock                  Where to store the handle to the lock on success.
 */
int OSLockCreate(POSLOCK phLock);


/**
 * Destroys the given lock.
 *
 * @returns Status code.
 * @param   hLock                   The lock to destroy.
 */
int OSLockDestroy(OSLOCK hLock);


/**
 * Acquires the given lock, waiting for it to become free if already acquired.
 *
 * @returns Status code.
 * @param   hLock                   The lock to acquire.
 */
int OSLockAcquire(OSLOCK hLock);


/**
 * Releases a previously acquired lock.
 *
 * @returns Status code.
 * @param   hLock                   The lock to release.
 */
int OSLockRelease(OSLOCK hLock);

#endif /* !INCLUDED_os_lock_h */
