/** @file
 * PSP Emulator - I/O log writer/reader.
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <common/status.h>

#include <psp-iolog.h>


/*********************************************************************************************************************************
*   Defined Constants And Macros                                                                                                 *
*********************************************************************************************************************************/

/** PSP I/O log header magic (sans the zero terminator). */
#define PSP_IOLOG_HDR_MAGIC                 "PSPIOLOG"
/** This defines the endianess of the log. */
#define PSP_IO_LOG_HDR_ENDIANESS            0xdeadc0de
/** I/O log file format version (1.0 currently). */
#define PSP_IO_LOG_HDR_VERSION              0x00010000;


/** SMN address space was accessed. */
#define PSP_IO_LOG_EVT_ADDR_SPACE_SMN       0x0001
/** PSP MMIO address space was accessed. */
#define PSP_IO_LOG_EVT_ADDR_SPACE_MMIO      0x0002
/** x86 address space was accessed. */
#define PSP_IO_LOG_EVT_ADDR_SPACE_X86       0x0003


/** The event describes a read. */
#define PSP_IO_LOG_EVT_F_READ               0
/** The event describes a write. */
#define PSP_IO_LOG_EVT_F_WRITE              BIT(0)


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/**
 * I/O log header.
 */
typedef struct PSPIOLOGHDR
{
    /** Magic identifying the I/O log (PSPIOLOG). */
    uint8_t                         achMagic[8];
    /** Endianess of the I/O log. */
    uint32_t                        u32Endianess;
    /** I/O log format version. */
    uint32_t                        u32Version;
    /** Start timestamp of the I/O log. */
    uint64_t                        u64TsStart;
    /** Padding to 32byte. */
    uint64_t                        u64Rsvd0;
} PSPIOLOGHDR;
/** Pointer to a I/O log header. */
typedef PSPIOLOGHDR *PPSPIOLOGHDR;
/** Pointer to a const I/O log header. */
typedef const PSPIOLOGHDR *PCPSPIOLOGHDR;


/**
 * I/O log event.
 */
typedef struct PSPIOLOGEVT
{
    /** The accessed address space. */
    uint16_t                        u16AddrSpace;
    /** Flags for this event. */
    uint16_t                        fFlags;
    /** CCD ID the event orignated from. */
    uint32_t                        idCcd;
    /** The adress being accessed. */
    uint64_t                        u64Addr;
    /** Number of bytes being accessed, this defines the number of bytes following the event header. */
    uint64_t                        cbAcc;
    /** Timestamp of the event relative to the start timestamp. */
    uint64_t                        u64TsEvt;             
} PSPIOLOGEVT;
/** Pointer to an I/O log event. */
typedef PSPIOLOGEVT *PPSPIOLOGEVT;
/** Pointer to a const I/O log event. */
typedef const PSPIOLOGEVT *PCPSPIOLOGEVT;


/**
 * Internal I/O log writer instance data.
 */
typedef struct PSPIOLOGWRINT
{
    /** File handle to write to. */
    FILE                            *pFile;
    /** Start timestamp. */
    uint64_t                        u64TsStart;
} PSPIOLOGWRINT;
/** Pointer to the internal I/O log writer instance data. */
typedef PSPIOLOGWRINT *PPSPIOLOGWRINT;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

/**
 * Gets the nanosecond timestamp.
 *
 * @returns Nanoseconds elapsed (monotonic increasing).
 */
static uint64_t pspEmuIoLogGetTimeNs(void)
{
    struct timespec Tp;
    int rcPsx = clock_gettime(CLOCK_MONOTONIC, &Tp);
    if (!rcPsx)
        return ((uint64_t)Tp.tv_sec * 1000ULL * 1000ULL * 1000ULL) + Tp.tv_nsec;

    return 0;
}


/**
 * Writes the given event to the I/O log writer.
 *
 * @returns Status code.
 * @param   pThis                   The I/O log writer instance.
 * @param   pEvt                    The event to add.
 * @param   pvData                  The data following the event header.
 * @param   cbData                  Size of the data following.
 */
static int pspEmuIoLogWrEvtAdd(PPSPIOLOGWRINT pThis, PCPSPIOLOGEVT pEvt, const void *pvData, size_t cbData)
{
    int rc = STS_INF_SUCCESS;
    size_t cbWritten = fwrite(pEvt, sizeof(*pEvt), 1, pThis->pFile);
    if (cbWritten == 1)
    {
        cbWritten == fwrite(pvData, cbData, 1, pThis->pFile);
        if (cbWritten != 1)
            rc = STS_ERR_GENERAL_ERROR;
    }
    else
        rc = STS_ERR_GENERAL_ERROR;

    return rc;
}


int PSPEmuIoLogWrCreate(PPSPIOLOGWR phIoLogWr, uint32_t fFlags, const char *pszFilename)
{
    if (fFlags)
        return STS_ERR_INVALID_PARAMETER;

    int rc = STS_ERR_GENERAL_ERROR;
    FILE *pIoLogFile = fopen(pszFilename, "wb");
    if (pIoLogFile)
    {
        PPSPIOLOGWRINT pThis = (PPSPIOLOGWRINT)calloc(1, sizeof(*pThis));
        if (pThis)
        {
            pThis->pFile      = pIoLogFile;
            pThis->u64TsStart = pspEmuIoLogGetTimeNs();

            /* Write the header. */
            PSPIOLOGHDR Hdr;
            memcpy(&Hdr.achMagic[0], PSP_IOLOG_HDR_MAGIC, sizeof(Hdr.achMagic));
            Hdr.u32Endianess = PSP_IO_LOG_HDR_ENDIANESS;
            Hdr.u32Version   = PSP_IO_LOG_HDR_VERSION;
            Hdr.u64TsStart   = pThis->u64TsStart;
            Hdr.u64Rsvd0     = 0;
            size_t cbWritten = fwrite(&Hdr, sizeof(Hdr), 1, pThis->pFile);
            if (cbWritten == 1)
            {
                *phIoLogWr = pThis;
                return STS_INF_SUCCESS;
            }
            else
                rc = STS_ERR_GENERAL_ERROR;

            free(pThis);
        }
        else
            rc = STS_ERR_NO_MEMORY;

        fclose(pIoLogFile);
    }

    return rc;
}


void PSPEmuIoLogWrDestroy(PSPIOLOGWR hIoLogWr)
{
    PPSPIOLOGWRINT pThis = hIoLogWr;

    fflush(pThis->pFile);
    fclose(pThis->pFile);
    free(pThis);
}


int PSPEmuIoLogWrSmnAccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, SMNADDR SmnAddr, bool fWrite, size_t cb, const void *pv)
{
    PPSPIOLOGWRINT pThis = hIoLogWr;

    PSPIOLOGEVT Evt;
    Evt.u16AddrSpace = PSP_IO_LOG_EVT_ADDR_SPACE_SMN;
    Evt.fFlags       = fWrite ? PSP_IO_LOG_EVT_F_WRITE : PSP_IO_LOG_EVT_F_READ;
    Evt.idCcd        = idCcd;
    Evt.u64Addr      = SmnAddr;
    Evt.cbAcc        = cb;
    Evt.u64TsEvt     = pspEmuIoLogGetTimeNs() - pThis->u64TsStart;
    return pspEmuIoLogWrEvtAdd(pThis, &Evt, pv, cb);
}


int PSPEmuIoLogWrMmioAccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, PSPADDR PspAddrMmio, bool fWrite, size_t cb, const void *pv)
{
    PPSPIOLOGWRINT pThis = hIoLogWr;

    PSPIOLOGEVT Evt;
    Evt.u16AddrSpace = PSP_IO_LOG_EVT_ADDR_SPACE_MMIO;
    Evt.fFlags       = fWrite ? PSP_IO_LOG_EVT_F_WRITE : PSP_IO_LOG_EVT_F_READ;
    Evt.idCcd        = idCcd;
    Evt.u64Addr      = PspAddrMmio;
    Evt.cbAcc        = cb;
    Evt.u64TsEvt     = pspEmuIoLogGetTimeNs() - pThis->u64TsStart;
    return pspEmuIoLogWrEvtAdd(pThis, &Evt, pv, cb);
}


int PSPEmuIoLogWrX86AccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, X86PADDR PhysX86Addr, bool fWrite, size_t cb, const void *pv)
{
    PPSPIOLOGWRINT pThis = hIoLogWr;

    PSPIOLOGEVT Evt;
    Evt.u16AddrSpace = PSP_IO_LOG_EVT_ADDR_SPACE_X86;
    Evt.fFlags       = fWrite ? PSP_IO_LOG_EVT_F_WRITE : PSP_IO_LOG_EVT_F_READ;
    Evt.idCcd        = idCcd;
    Evt.u64Addr      = PhysX86Addr;
    Evt.cbAcc        = cb;
    Evt.u64TsEvt     = pspEmuIoLogGetTimeNs() - pThis->u64TsStart;
    return pspEmuIoLogWrEvtAdd(pThis, &Evt, pv, cb);
}


int PSPEmuIoLogRdrCreate(PPSPIOLOGRDR phIoLogRdr, const char *pszFilename)
{
    (void)phIoLogRdr;
    (void)pszFilename;

    return STS_ERR_GENERAL_ERROR;
}


void PSPEmuIoLogRdrDestroy(PSPIOLOGRDR hIoLogRdr)
{
    (void)hIoLogRdr;
}


int PSPEmuIoLogRdrEvtQueryNext(PSPIOLOGRDR hIoLogRdr, PCPSPIOLOGRDREVT *ppIoLogEvt)
{
    (void)hIoLogRdr;
    (void)ppIoLogEvt;

    return STS_ERR_GENERAL_ERROR;
}


int PSPEmuIoLogRdrEvtFree(PSPIOLOGRDR hIoLogRdr, PCPSPIOLOGRDREVT pIoLogEvt)
{
    (void)hIoLogRdr;
    (void)pIoLogEvt;

    return STS_ERR_GENERAL_ERROR;
}
