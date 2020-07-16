/** @file
 * PSP Emulator - Profile definitions for PSPs and specific AMD CPUs.
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
#ifndef INCLUDED_psp_profile_h
#define INCLUDED_psp_profile_h

#include <common/types.h>


/**
 * Micro architecture of the CPU.
 */
typedef enum PSPEMUMICROARCH
{
    /** Invalid value. */
    PSPEMUMICROARCH_INVALID = 0,
    /** Original Zen. */
    PSPEMUMICROARCH_ZEN,
    /* Zen+ */
    PSPEMUMICROARCH_ZEN_PLUS,
    /* Zen2 */
    PSPEMUMICROARCH_ZEN2,
    /** 32bit hack. */
    PSPEMUMICROARCH_32BIT_HACK = 0x7fffffff
} PSPEMUMICROARCH;


/**
 * AMD CPU segment.
 */
typedef enum PSPEMUAMDCPUSEGMENT
{
    /** Invalid segment. */
    PSPEMUAMDCPUSEGMENT_INVALID = 0,
    /** Ryzen (Consumer). */
    PSPEMUAMDCPUSEGMENT_RYZEN,
    /** Ryzen Pro (Business). */
    PSPEMUAMDCPUSEGMENT_RYZEN_PRO,
    /** Threadripper (HEDT). */
    PSPEMUAMDCPUSEGMENT_THREADRIPPER,
    /** Epyc (Server). */
    PSPEMUAMDCPUSEGMENT_EPYC,
    /** 32bit hack. */
    PSPEMUAMDCPUSEGMENT_32BIT_HACK = 0x7fffffff
} PSPEMUAMDCPUSEGMENT;


/**
 * PSP profile.
 */
typedef struct PSPPROFILE
{
    /** PSP profile identifier. */
    const char                      *pszId;
    /** PSP profile description. */
    const char                      *pszDesc;
    /** The micro architecture we are emulating. */
    PSPEMUMICROARCH                 enmMicroArch;
    /** SRAM size in bytes. */
    size_t                          cbSram;
    /** Physical address of the BRSP in SRAM. */
    PSPPADDR                        PspAddrBrsp;
    /** Location of the status port. */
    PSPPADDR                        PspAddrMmioSts;
    /** Location where the flash starts in SMN. */
    SMNADDR                         SmnAddrFlashStart;
} PSPPROFILE;
/** Pointer to a PSP profile. */
typedef PSPPROFILE *PPSPPROFILE;
/** Pointer to a const PSP profile. */
typedef const PSPPROFILE *PCPSPPROFILE;


/**
 * AMD CPU profile.
 */
typedef struct PSPAMDCPUPROFILE
{
    /** CPU profile identifier. */
    const char                      *pszId;
    /** CPU profile description. */
    const char                      *pszDesc;
    /** The micro architecture we are emulating. */
    PSPEMUMICROARCH                 enmMicroArch;
    /** The CPU segment we are emulating. */
    PSPEMUAMDCPUSEGMENT             enmCpuSegment;
    /** Number of CCDs per socket. */
    uint32_t                        cCcdsPerSocket;
    /** Maximum number of sockets supported by the CPU. */
    uint32_t                        cSocketsMax;
    /** Pointer to the assigned PSP profile for the CPU entry. */
    PCPSPPROFILE                    pPspProfile;
} PSPAMDCPUPROFILE;
/** Pointer to an AMD CPU profile. */
typedef PSPAMDCPUPROFILE *PPSPAMDCPUPROFILE;
/** Pointer to a const AMD CPU profile. */
typedef const PSPAMDCPUPROFILE *PCPSPAMDCPUPROFILE;



/**
 * Gets the PSP profile with the given ID.
 *
 * @returns Pointer to the PSP profile if found, NULL if not found.
 * @param   pszId                   The ID to look for.
 */
PCPSPPROFILE PSPProfilePspGetById(const char *pszId);


/**
 * Gets the AMD CPU profile with the given ID.
 *
 * @returns Pointer to the AMD CPU profile if found, NULL if not found.
 * @param   pszId                   The ID to look for.
 */
PCPSPAMDCPUPROFILE PSPProfileAmdCpuGetById(const char *pszId);

#endif /* !INCLUDED_psp_profile_h */

