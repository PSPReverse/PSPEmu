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
 * Bootloader stage.
 */
typedef enum PSPBLSTAGE
{
    /** Invalid bootloader stage. */
    PSPBLSTAGE_INVALID = 0,
    /** on-chip BL stage. */
    PSPBLSTAGE_ON_CHIP,
    /** off-chip BL stage. */
    PSPBLSTAGE_OFF_CHIP,
    /** @todo ABL stages. */
    /** Any stage. */
    PSPBLSTAGE_ANY,
    /** Unknown stage. */
    PSPBLSTAGE_UNKNOWN,
    /** 32bit hack. */
    PSPBLSTAGE_32BIT_HACK = 0x7fffffff
} PSPBLSTAGE;


/**
 * PSP address descriptor.
 */
typedef struct PSPADDRDESC
{
    /** The address space. */
    PSPADDRSPACE                    enmAddrSpace;
    /** The address. */
    union
    {
        /** Raw value (used for the initialization macros). */
        uint64_t                    u64Raw;
        /** PSP physical address. */
        PSPPADDR                    PspAddr;
        /** SMN address. */
        SMNADDR                     SmnAddr;
        /** X86 address. */
        X86PADDR                    PhysX86Addr;
    } u;
} PSPADDRDESC;
/** Pointer to a PSP proxy address. */
typedef PSPADDRDESC *PPSPADDRDESC;
/** Pointer to a const PSP proxy address. */
typedef const PSPADDRDESC *PCPSPADDRDESC;


/**
 * PSP blocked address range descriptor for proxy mode.
 */
typedef struct PSPPROXYADDRBLOCKEDDESC
{
    /** Name of the blocked region. */
    const char                      *pszRegion;
    /** The bootloader stage. */
    PSPBLSTAGE                      enmBlStage;
    /** Start address being blocked. */
    PSPADDRDESC                     AddrStart;
    /** Size of the region in bytes being blocked. */
    size_t                          cbRegion;
    /** Access size being blocked, 0 means size doesn't matter. */
    size_t                          cbAcc;
    /** Access related flags controlling when it is being blocked. */
    uint32_t                        fAccess;
    /** Proxy feature related flags. */
    uint32_t                        fProxyFeat;
    /** Value to return on reads if blocked. */
    uint32_t                        u32ValRead;
} PSPPROXYADDRBLOCKEDDESC;
/** Pointer to a blocked range descriptor. */
typedef PSPPROXYADDRBLOCKEDDESC *PPSPPROXYADDRBLOCKEDDESC;
/** Pointer to a const blocked range descriptor. */
typedef const PSPPROXYADDRBLOCKEDDESC *PCPSPPROXYADDRBLOCKEDDESC;


/** Read accesses are blocked. */
#define PSPPROXY_ADDR_BLOCKED_ACCESS_F_READ         BIT(0)
/** Write accesses are blocked. */
#define PSPPROXY_ADDR_BLOCKED_ACCESS_F_WRITE        BIT(1)


/** The range is blocked when the proxy uses the SPI communication channel. */
#define PSPPROXY_ADDR_BLOCKED_FEAT_F_SPI            BIT(0)
/** The range is blocked when the proxy uses the x86 UART communication channel. */
#define PSPPROXY_ADDR_BLOCKED_FEAT_F_X86_UART       BIT(1)
/** The range is blocked when the proxy is instructed to not release the x86 cores. */
#define PSPPROXY_ADDR_BLOCKED_FEAT_F_NO_X86_RELEASE BIT(2)


/** Initializes a non writeable PSP MMIO range for every BL stage no matter the access size. */
#define PSPPROXY_ADDR_BLOCKED_MMIO_INIT_WR(a_pszName, a_AddrMmio, a_cbRegion) \
    { (a_pszName), PSPBLSTAGE_ANY, { PSPADDRSPACE_PSP_MMIO, .u = { (a_AddrMmio) } }, (a_cbRegion), 0, PSPPROXY_ADDR_BLOCKED_ACCESS_F_WRITE, 0, 0}
/** Initializes a non accessible SMN range for every BL stage no matter the access size for a specific proxy feature. */
#define PSPPROXY_ADDR_BLOCKED_SMN_INIT_ALL_FEAT(a_pszName, a_AddrSmn, a_cbRegion, a_u32ValRead, a_fProxyFeat) \
    { (a_pszName), PSPBLSTAGE_ANY, { PSPADDRSPACE_SMN, .u = { (a_AddrSmn) } }, (a_cbRegion), 0, PSPPROXY_ADDR_BLOCKED_ACCESS_F_WRITE | PSPPROXY_ADDR_BLOCKED_ACCESS_F_READ, (a_fProxyFeat), (a_u32ValRead) }
/** Initializes a non accessible x86 range for every BL stage no matter the access size for a specific proxy feature. */
#define PSPPROXY_ADDR_BLOCKED_X86_INIT_ALL_FEAT(a_pszName, a_PhysX86Addr, a_cbRegion, a_u32ValRead, a_fProxyFeat) \
    { (a_pszName), PSPBLSTAGE_ANY, { PSPADDRSPACE_X86, .u = { (a_PhysX86Addr) } }, (a_cbRegion), 0, PSPPROXY_ADDR_BLOCKED_ACCESS_F_WRITE | PSPPROXY_ADDR_BLOCKED_ACCESS_F_READ, (a_fProxyFeat), (a_u32ValRead) }
/** @todo More macros as the need arises. */


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
    /** Array of blocked MMIO ranges for proxy mode. */
    PCPSPPROXYADDRBLOCKEDDESC       paAddrProxyBlockedMmio;
    /** Number of entries in the blocked MMIO range array. */
    uint32_t                        cAddrProxyBlockedMmio;
    /** Array of blocked SMN ranges for proxy mode. */
    PCPSPPROXYADDRBLOCKEDDESC       paAddrProxyBlockedSmn;
    /** Number of entries in the blocked SMN range array. */
    uint32_t                        cAddrProxyBlockedSmn;
    /** Array of blocked x86 ranges for proxy mode. */
    PCPSPPROXYADDRBLOCKEDDESC       paAddrProxyBlockedX86;
    /** Number of entries in the blocked x86 range array. */
    uint32_t                        cAddrProxyBlockedX86;
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
    /** Number of cores per CCX. */
    uint32_t                        cCoresPerCcx;
    /** Number of CCXs enabled/available for the CPU model. */
    uint32_t                        cCcxs;
    /** Number of total cores enabled on the CCD. */
    uint32_t                        cCoresPerCcd;
    /** Pointer to the assigned PSP profile for the CPU entry. */
    PCPSPPROFILE                    pPspProfile;
    /** Array of blocked SMN ranges for proxy mode specific for the selected CPU profile. */
    PCPSPPROXYADDRBLOCKEDDESC       paAddrProxyBlockedSmn;
    /** Number of entries in the blocked SMN range array. */
    uint32_t                        cAddrProxyBlockedSmn;
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

