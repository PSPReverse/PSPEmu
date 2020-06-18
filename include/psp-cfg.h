/** @file
 * PSP Emulator - PSP system config descriptor.
 */

/*
 * Copyright (C) 2020 Alexander Eichner <alexander.eichner@campus.tu-berlin.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __psp_cfg_h
#define __psp_cfg_h

#include <common/types.h>

#include <psp-dbg-hlp.h>

/**
 * Emulation mode.
 */
typedef enum PSPEMUMODE
{
    /** Invalid mode, do not use. */
    PSPEMUMODE_INVALID = 0,
    /** A single usermode application is executed and the svc interface is emulated. */
    PSPEMUMODE_APP,
    /** Full system emulation mode with the supervisor code being executed as well. */
    PSPEMUMODE_SYSTEM,
    /** Full system emulation mode with the supervisor and on chip bootloader code being executed as well. */
    PSPEMUMODE_SYSTEM_ON_CHIP_BL,
    /** Run only a given trusted OS binary. */
    PSPEMUMODE_TRUSTED_OS
} PSPEMUMODE;


/**
 * Micro architecture the PSP emulated for.
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
 * ACPI sleep state.
 */
typedef enum PSPEMUACPISTATE
{
    /** Invalid sleep state. */
    PSPEMUACPISTATE_INVALID = 0,
    /** S0 state: Working. */
    PSPEMUACPISTATE_S0,
    /** S1 state: Sleeping with Processor context maintained. */
    PSPEMUACPISTATE_S1,
    /** S2 state: */
    PSPEMUACPISTATE_S2,
    /** S3 state: */
    PSPEMUACPISTATE_S3,
    /** S4 state: */
    PSPEMUACPISTATE_S4,
    /** S5 state: Soft off */
    PSPEMUACPISTATE_S5,
    /** 32bit hack. */
    PSPEMUACPISTATE_32BIT_HACK = 0x7fffffff
} PSPEMUACPISTATE;


/** Pointer to a const CCP proxy callback table. */
typedef const struct CCPPROXY *PCCCPPROXY;

/**
 * CCP proxy callback table.
 */
typedef struct CCPPROXY
{

    /**
     * Passthrough an AES operation which uses a key in one of the protected LSBs.
     *
     * @returns Status code.
     * @param   pCcpProxyIf         Pointer to this table.
     * @param   u32Dw0              The first dword of the CCP AES request.
     * @param   cbSrc               Number of bytes to process.
     * @param   pvSrc               The source data.
     * @param   pvDst               Where to store the processed data.
     * @param   uKeyLsb             The LSB to use for the key.
     * @param   pvIv                The initialization vector data.
     * @param   cbIv                Size of the initialization vector.
     * @param   pu32CcpSts          WHere to store the status code returned by the CCP on success.
     */
    int (*pfnAesDo)(PCCCPPROXY pCcpProxyIf, uint32_t u32Dw0, size_t cbSrc, const void *pvSrc, void *pvDst,
                    uint32_t uKeyLsb, const void *pvIv, size_t cbIv, uint32_t *pu32CcpSts);

} CCPPROXY;
/** Pointer to a CCP proxy callback table. */
typedef CCPPROXY *PCCPPROXY;


/**
 * Create memory region descriptor.
 */
typedef struct PSPEMUCFGMEMREGIONCREATE
{
    /** Address space to create the region in. */
    PSPADDRSPACE            enmAddrSpace;
    /** Size of the region to create. */
    size_t                  cbRegion;
    /** Address in the address space to preload. */
    union
    {
        /** Physical PSP address of the region. */
        PSPPADDR            PspAddr;
        /** SMN address of the region. */
        SMNADDR             SmnAddr;
        /** Physical x86 address of the region. */
        X86PADDR            PhysX86Addr;
    } u;
} PSPEMUCFGMEMREGIONCREATE;
/** Pointer to a create memory region descriptor. */
typedef PSPEMUCFGMEMREGIONCREATE *PPSPEMUCFGMEMREGIONCREATE;
/** Pointer to a const create memory region descriptor. */
typedef const PSPEMUCFGMEMREGIONCREATE *PCPSPEMUCFGMEMREGIONCREATE;


/**
 * Preload memory descriptor.
 */
typedef struct PSPEMUCFGMEMPRELOAD
{
    /** Address space to pre load. */
    PSPADDRSPACE            enmAddrSpace;
    /** Address in the address space to preload. */
    union
    {
        /** Physical PSP address to pre load. */
        PSPPADDR            PspAddr;
        /** SMN address to pre load. */
        SMNADDR             SmnAddr;
        /** Physical x86 address to pre load. */
        X86PADDR            PhysX86Addr;
    } u;
    /** The file to preload. */
    const char              *pszFilePreload;
} PSPEMUCFGMEMPRELOAD;
/** Pointer to a memory preload descriptor. */
typedef PSPEMUCFGMEMPRELOAD *PPSPEMUCFGMEMPRELOAD;
/** Pointer to a const memory preload descriptor. */
typedef const PSPEMUCFGMEMPRELOAD *PCPSPEMUCFGMEMPRELOAD;


/**
 * PSP emulator config.
 */
typedef struct PSPEMUCFG
{
    /** Emulation mode. */
    PSPEMUMODE              enmMode;
    /** The micro architecture we are emulating. */
    PSPEMUMICROARCH         enmMicroArch;
    /** The CPU segment we are emulating. */
    PSPEMUAMDCPUSEGMENT     enmCpuSegment;
    /** ACPI system state the emulator starts from. */
    PSPEMUACPISTATE         enmAcpiState;
    /** The flash ROM path. */
    const char              *pszPathFlashRom;
    /** Path to the on chip bootloader if in appropriate mode. */
    const char              *pszPathOnChipBl;
    /** Binary to load, if NULL we get one from the flash image depending on the mode. */
    const char              *pszPathBinLoad;
    /** Path to the boot rom service page to inject (for system and app emulation mode). */
    const char              *pszPathBootRomSvcPage;
    /** Flag whether overwritten binaries have the 256 byte header prepended (affects the load address). */
    bool                    fBinContainsHdr;
    /** Flag whether to load the PSP directory from the flash image into the boot rom service page. */
    bool                    fLoadPspDir;
    /** Flag whether to enable the debug mode inside the PSP firmware disabling signature checks etc. */
    bool                    fPspDbgMode;
    /** Flag whether to intercept svc 6 in on chip bootloader and system mode. */
    bool                    fIncptSvc6;
    /** Flag whether to to trace all svc calls in on chip bootloader and system mode. */
    bool                    fTraceSvcs;
    /** Flag whether the timer should tick in real time. */
    bool                    fTimerRealtime;
    /** Flag whether any loaded boot ROM sevrice page should be taken as is or modified to match the CCD
     * it is implanted on. */
    bool                    fBootRomSvcPageModify;
    /** Flag whether the i/O manager should log all I/O accesses to all regions. */
    bool                    fIomLogAllAccesses;
    /** Flag whether the proxy should try to buffer certain writes to speed up data transfers. */
    bool                    fProxyWrBuffer;
    /** Flag whether to proxy certain CCP requests - requires the proxy to be enabled of course. */
    bool                    fCcpProxy;
    /** Flag whether to do single step execution with dumping the core state after each instruction. */
    bool                    fSingleStepDumpCoreState;
    /** Debugger port to listen on, 0 means debugger is disabled. */
    uint16_t                uDbgPort;
    /** Maximum number of instructions to execute in one round, used to workaround a unicorn sync sate issue. */
    uint32_t                cDbgInsnStep;
    /** Address to run up to before dropping into the debugger. */
    PSPADDR                 PspAddrDbgRunUpTo;
    /** Pointer to the read flash rom content. */
    void                    *pvFlashRom;
    /** Size of the flash ROM in bytes. */
    size_t                  cbFlashRom;
    /** Pointer to the on chip bootloader ROM content. */
    void                    *pvOnChipBl;
    /** Size of the on chip bootloader ROM in bytes. */
    size_t                  cbOnChipBl;
    /** Pointer to the binary content if pszPathBinLoad is not NULL. */
    void                    *pvBinLoad;
    /** Number of bytes of the binary loaded. */
    size_t                  cbBinLoad;
    /** Pointer to the boot ROM service page if pszPathBootRomSvcPage is not NULL. */
    void                    *pvBootRomSvcPage;
    /** Number of bytes of the loaded boot ROM service page. */
    size_t                  cbBootRomSvcPage;
    /** The proxy address if configured. */
    const char              *pszPspProxyAddr;
    /** PSP code address where the off chip BL jumps to the trusted OS.
     * If not 0 and in proxy mode the emulator will do the same on the real hardware. */
    PSPPADDR                PspAddrProxyTrustedOsHandover;
    /** Path to the trace log to write if enabled. */
    const char              *pszTraceLog;
    /** UART remtoe address. */
    const char              *pszUartRemoteAddr;
    /** SPI flash trace file to write. */
    const char              *pszSpiFlashTrace;
    /** Pointer to the I/O log file to write. */
    const char              *pszIoLog;
    /** Pointer to the I/O log file to replay. */
    const char              *pszIoLogReplay;
    /** Coverage tracing filename if enabled. */
    const char              *pszCovTrace;
    /** Number of sockets in the system to emulate. */
    uint32_t                cSockets;
    /** Number of CCDs per socket to emulate. */
    uint32_t                cCcdsPerSocket;
    /** Array of memory region descriptors to create on demand. */
    PCPSPEMUCFGMEMREGIONCREATE paMemCreate;
    /** Number of entries in the create memory region descriptor array. */
    uint32_t                cMemCreate;
    /** Array of memory descriptors to pre load with data. */
    PCPSPEMUCFGMEMPRELOAD   paMemPreload;
    /** Number of entries in the memory preload descriptor array. */
    uint32_t                cMemPreload;
    /** Pointer to an array of strings for devices which should be instantiated, temrinated by a NULL entry.
     *NULL means default with everything emulated. */
    const char              **papszDevs;
    /** Pointer to a CCP proxy callback table if enabled. */
    PCCCPPROXY              pCcpProxyIf;
    /** Debug helper module handle if a debugger is enabled so other components can register custom commands
     * for use by the debugger. */
    PSPDBGHLP               hDbgHlp;
} PSPEMUCFG;
/** Pointer to a PSPEmu config. */
typedef PSPEMUCFG *PPSPEMUCFG;
/** Pointer to a const PSPEmu config. */
typedef const PSPEMUCFG *PCPSPEMUCFG;

#endif /* __psp_cfg_h */

