/** @file
 * PSP Emulator - PSP profile management.
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

#include <string.h>

#include <common/cdefs.h>

#include <psp-profile.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/** Ranges block in proxy mode get included here. */
#include "profiles/proxy-blocked-range-std.h"


/* PSP profiles get included here first. */
#include "profiles/amd-psp-zen.h"
#include "profiles/amd-psp-zen-plus.h"
#include "profiles/amd-psp-zen-2.h"


/* CPU profiles get included here.*/
#include "profiles/amd-cpu-ryzen7-1800x.h"


/*********************************************************************************************************************************
*   Global Variables                                                                                                             *
*********************************************************************************************************************************/

/**
 * Supported PSP profiles.
 */
static PCPSPPROFILE g_aPspProfiles[] =
{
    &g_PspProfileZen,
    &g_PspProfileZenPlus,
    &g_PspProfileZen2
};


/**
 * Supported CPU profiles.
 */
static PCPSPAMDCPUPROFILE g_aCpuProfiles[] =
{
    &g_AmdCpu_Ryzen7_1800X
};


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

PCPSPPROFILE PSPProfilePspGetById(const char *pszId)
{
    for (uint32_t i = 0; i < ELEMENTS(g_aPspProfiles); i++)
    {
        if (!strcmp(g_aPspProfiles[i]->pszId, pszId))
            return g_aPspProfiles[i];
    }

    return NULL;
}


PCPSPAMDCPUPROFILE PSPProfileAmdCpuGetById(const char *pszId)
{
    for (uint32_t i = 0; i < ELEMENTS(g_aCpuProfiles); i++)
    {
        if (!strcmp(g_aCpuProfiles[i]->pszId, pszId))
            return g_aCpuProfiles[i];
    }

    return NULL;
}

