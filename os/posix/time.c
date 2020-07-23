/** @file
 * PSP Emulator - OS abstraction for timing related APIs, Posix implementation.
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
#include <time.h>

#include <os/time.h>


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

uint64_t OSTimeTsGetNano(void)
{
    struct timespec Tp;
    int rcPsx = clock_gettime(CLOCK_MONOTONIC, &Tp);
    if (!rcPsx)
        return ((uint64_t)Tp.tv_sec * 1000ULL * 1000ULL * 1000ULL) + Tp.tv_nsec;

    return 0;
}

