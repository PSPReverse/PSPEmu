/** @file
 * PSP Emulator - OS abstraction for timing related APIs.
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
#ifndef INCLUDED_os_time_h
#define INCLUDED_os_time_h

#include <common/types.h>


/**
 * Returns monotonically increasing nano second precision timestamp from an arbitrary starting point in time.
 *
 * @returns Nano second precision timestamp.
 */
uint64_t OSTimeTsGetNano(void);

#endif /* !INCLUDED_os_time_h */
