/** @file
 * PSP Emulator - OS abstraction for threads.
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
#ifndef INCLUDED_os_thread_h
#define INCLUDED_os_thread_h

#include <common/types.h>

/** Opaque thread handle. */
typedef struct OSTHREADINT *OSTHREAD;
/** Pointer to a thread handle. */
typedef OSTHREAD *POSTHREAD;


/**
 * The main thread handler.
 *
 * @returns Status code.
 * @param   hThread                 The thread handle this method is called from.
 * @param   pvUser                  Opaque user data passed during thread creation.
 */
typedef int (FNOSTHREADMAIN)(OSTHREAD hThread, void *pvUser);
/** Thread handler pointer. */
typedef FNOSTHREADMAIN *PFNOSTHREADMAIN;


/**
 * Creates a thread with default parameters for the running host.
 *
 * @returns Status code.
 * @param   phThread                Where to store the handle to the thread on success.
 * @param   pfnMain                 The handler to call on the created thread.
 * @param   pvUser                  Opaque user data to pass to the thread handler.
 */
int OSThreadCreate(POSTHREAD phThread, PFNOSTHREADMAIN pfnMain, void *pvUser);


/**
 * Destroys the given thread handle.
 *
 * @returns Status code.
 * @param   hThread                 The thread handle to destroy (the thread handler must have returned already).
 * @param   prcThread               Where to store the thread return status upon success, optional.
 */
int OSThreadDestroy(OSTHREAD hThread, int *prcThread);


#endif /* !INCLUDED_os_thread_h */
