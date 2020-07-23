/** @file
 * PSP Emulator - API for manipulating the Boot ROM Service Page.
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
#ifndef INCLUDED_psp_brsp_h
#define INCLUDED_psp_brsp_h

#include <common/types.h>

#include <psp-fw/boot-rom-svc-page.h>

#include <psp-cfg.h>


/**
 * Generates a boot ROM service page from the given emulator config.
 *
 * @returns Status code.
 * @param   pBrsp                   The Boot ROM Service Page to initialize.
 * @param   pCfg                    The emulator config to generate from.
 * @param   idCcd                   The CCD ID to generate for.
 * @param   idSocket                The socket ID to generate for.
 */
int PSPBrspGenerate(PPSPROMSVCPG pBrsp, PCPSPEMUCFG pCfg, uint32_t idCcd, uint32_t idSocket);

#endif /* !INCLUDED_psp_brsp_h */
