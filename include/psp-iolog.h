/** @file
 * PSP Emulator - I/O log.
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
#ifndef __psp_iolog_h
#define __psp_iolog_h

#include <common/types.h>
#include <common/cdefs.h>

/** Opaque PSP I/O log writer handle. */
typedef struct PSPIOLOGWRINT *PSPIOLOGWR;
/** Pointer to a PSP I/O log writer handle. */
typedef PSPIOLOGWR *PPSPIOLOGWR;

/** Opaque PSP I/O log reader handle. */
typedef struct PSPIOLOGRDRINT *PSPIOLOGRDR;
/** Pointer to a PSP I/O log reader handle. */
typedef PSPIOLOGRDR *PPSPIOLOGRDR;


/**
 * I/O log reader event.
 */
typedef struct PSPIOLOGRDREVT
{
    /** The address space being accessed. */
    PSPADDRSPACE                enmAddrSpace;
    /** Size of the access in bytes. */
    size_t                      cbAcc;
    /** Flag whether the access was a read or write. */
    bool                        fWrite;
    /** Pointer to the data being read or written. */
    const void                  *pvData;
    /** Address space dependent address. */
    union
    {
        /** SMN address. */
        SMNADDR                 SmnAddr;
        /** PSP MMIO address. */
        PSPADDR                 PspAddrMmio;
        /** x86 address. */
        X86PADDR                PhysX86Addr;
    } u;
} PSPIOLOGRDREVT;
/** Pointer to a I/O log reader event. */
typedef PSPIOLOGRDREVT *PPSPIOLOGRDREVT;
/** Pointer to a const I/O log reader event. */
typedef const PSPIOLOGRDREVT *PCPSPIOLOGRDREVT;


/**
 * Creates a new I/O log writer instance.
 *
 * @returns Status code.
 * @param   phIoLogWr               Where to store the I/O log writer handle on success.
 * @param   fFlags                  Flags controlling the behavior, MBZ.
 * @param   pszFilename             The filename of the I/O log.
 */
int PSPEmuIoLogWrCreate(PPSPIOLOGWR phIoLogWr, uint32_t fFlags, const char *pszFilename);


/**
 * Destroys a given I/O log handle.
 *
 * @returns nothing.
 * @param   hIoLogWr                The I/O log writer handle to destroy.
 */
void PSPEmuIoLogWrDestroy(PSPIOLOGWR hIoLogWr);


/**
 * Add a SMN access to the I/O log.
 *
 * @returns Status code.
 * @param   hIoLogWr                The I/O log writer handle.
 * @param   idCcd                   The CCD id the access originates from.
 * @param   SmnAddr                 The SMN address the access started at.
 * @param   fWrite                  Flag whether this access is a write.
 * @param   cb                      Size of the access in bytes.
 * @param   pv                      Data being read or written depending on the write flag.
 */
int PSPEmuIoLogWrSmnAccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, SMNADDR SmnAddr, bool fWrite, size_t cb, const void *pv);


/**
 * Add a PSP MMIO access to the I/O log.
 *
 * @returns Status code.
 * @param   hIoLogWr                The I/O log writer handle.
 * @param   idCcd                   The CCD id the access originates from.
 * @param   PspAddrMmio             The MMIO address the access started at.
 * @param   fWrite                  Flag whether this access is a write.
 * @param   cb                      Size of the access in bytes.
 * @param   pv                      Data being read or written depending on the write flag.
 */
int PSPEmuIoLogWrMmioAccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, PSPADDR PspAddrMmio, bool fWrite, size_t cb, const void *pv);


/**
 * Add a PSP x86 access to the I/O log.
 *
 * @returns Status code.
 * @param   hIoLogWr                The I/O log writer handle.
 * @param   idCcd                   The CCD id the access originates from.
 * @param   PhysX86Addr             The physical x86 address the access started at.
 * @param   fWrite                  Flag whether this access is a write.
 * @param   cb                      Size of the access in bytes.
 * @param   pv                      Data being read or written depending on the write flag.
 */
int PSPEmuIoLogWrX86AccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, X86PADDR PhysX86Addr, bool fWrite, size_t cb, const void *pv);


/**
 * Create a new I/O log reader instance.
 *
 * @returns Status code.
 * @param   phIoLogRdr              Where to store the handle to the reader instance on success.
 * @param   pszFilename             The I/O log file to open.
 */
int PSPEmuIoLogRdrCreate(PPSPIOLOGRDR phIoLogRdr, const char *pszFilename);


/**
 * Destroys the given I/O log reader instance.
 *
 * @returns nothing.
 * @param   hIoLogRdr               The I/O log reader instance to destroy.
 */
void PSPEmuIoLogRdrDestroy(PSPIOLOGRDR hIoLogRdr);


/**
 * Queries the next I/O event from the given I/O log reader instance.
 *
 * @returns Status code.
 * @param   hIoLogRdr               The I/O log reader instance.
 * @param   ppIoLogEvt              Where to store the pointer to the next event on success.
 *
 * @note Call PSPEmuIoLogRdrEvtFree() when done to free allocated resources for the given event.
 */
int PSPEmuIoLogRdrEvtQueryNext(PSPIOLOGRDR hIoLogRdr, PCPSPIOLOGRDREVT *ppIoLogEvt);


/**
 * Frees the given I/O log event returned from a previous PSPEmuIoLogRdrEvtQueryNext() call.
 *
 * @returns Status code.
 * @param   hIoLogRdr               The I/O log reader instance.
 * @param   pIoLogEvt               The I/O event to free.
 */
int PSPEmuIoLogRdrEvtFree(PSPIOLOGRDR hIoLogRdr, PCPSPIOLOGRDREVT pIoLogEvt);

#endif /* __psp_iolog_h */
