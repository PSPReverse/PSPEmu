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
#define PSP_IO_LOG_HDR_MAGIC                "PSPIOLOG"
/** This defines the endianess of the log. */
#define PSP_IO_LOG_HDR_ENDIANESS            0xdeadc0de
/** I/O log file format version (1.0 currently). */
#define PSP_IO_LOG_HDR_VERSION              0x00010000


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
    /** The PC causing the access. */
    uint32_t                        uAddrPc;
    /** Number of bytes being accessed, this defines the number of bytes following the event header. */
    uint32_t                        cbAcc;
    /** The adress being accessed. */
    uint64_t                        u64Addr;
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


/**
 * Internal I/O log reader instance data.
 */
typedef struct PSPIOLOGRDRINT
{
    /** The file handle. */
    FILE                            *pFile;
    /** The start timestamp read from the log header. */
    uint64_t                        u64TsStart;
    /** Current amount of data in the buffer. */
    size_t                          cbData;
    /** Where to read next from the buffer. */
    uint32_t                        offBuf;
    /** Error flag. */
    bool                            fError;
    /** Eos flag. */
    bool                            fEos;
    /** Buffered data. */
    uint8_t                         abBuf[64 * 1024];
} PSPIOLOGRDRINT;
/** Pointer to a file buffered reader. */
typedef PSPIOLOGRDRINT *PPSPIOLOGRDRINT;
/** Pointer to a const file buffered reader. */
typedef const PSPIOLOGRDRINT *PCPSPIOLOGRDRINT;


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


/**
 * Fill the data buffer with data from the file.
 *
 * @returns Status code.
 * @param   pThis                   The I/O log reader instance.
 */
static int pspEmuIoLogRdrBufFill(PPSPIOLOGRDRINT pThis)
{
    /* Try reading in more data. */
    size_t cbRead = fread(&pThis->abBuf[0], 1, sizeof(pThis->abBuf), pThis->pFile);
    pThis->cbData = cbRead;
    pThis->offBuf = 0;
    if (!cbRead)
        pThis->fEos = 1;

    return STS_INF_SUCCESS;
}


/**
 * Reads the given amount of data from the I/O log.
 *
 * @returns Status code.
 * @param   pThis                   The I/O log reader instance.
 * @param   pv                      Where to store the read data.
 * @param   cbRead                  Amount of bytes to read.
 */
static int pspEmuIoLogRdrRead(PPSPIOLOGRDRINT pThis, void *pv, size_t cbRead)
{
    int rc = STS_INF_SUCCESS;
    uint8_t *pb = (uint8_t *)pv;
    size_t cbReadLeft = cbRead;

    /* Try filling up the buffer first. */
    if (   pThis->offBuf == pThis->cbData
        && !pThis->fEos)
        rc = pspEmuIoLogRdrBufFill(pThis);

    while (   cbReadLeft
           && STS_SUCCESS(rc)
           && pThis->cbData)
    {
        size_t cbThisRead = MIN(cbReadLeft, pThis->cbData - pThis->offBuf);
        memcpy(pb, &pThis->abBuf[pThis->offBuf], cbThisRead);

        pb            += cbThisRead;
        cbReadLeft    -= cbThisRead;
        pThis->offBuf += cbThisRead;

        if (   pThis->offBuf == pThis->cbData
            && !pThis->fEos)
            rc = pspEmuIoLogRdrBufFill(pThis);
    }

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
            memcpy(&Hdr.achMagic[0], PSP_IO_LOG_HDR_MAGIC, sizeof(Hdr.achMagic));
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


int PSPEmuIoLogWrSmnAccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, PSPADDR PspAddrPc, SMNADDR SmnAddr, bool fWrite, size_t cb, const void *pv)
{
    PPSPIOLOGWRINT pThis = hIoLogWr;

    PSPIOLOGEVT Evt;
    Evt.u16AddrSpace = PSP_IO_LOG_EVT_ADDR_SPACE_SMN;
    Evt.fFlags       = fWrite ? PSP_IO_LOG_EVT_F_WRITE : PSP_IO_LOG_EVT_F_READ;
    Evt.idCcd        = idCcd;
    Evt.uAddrPc      = PspAddrPc;
    Evt.u64Addr      = SmnAddr;
    Evt.cbAcc        = (uint32_t)cb;
    Evt.u64TsEvt     = pspEmuIoLogGetTimeNs() - pThis->u64TsStart;
    return pspEmuIoLogWrEvtAdd(pThis, &Evt, pv, cb);
}


int PSPEmuIoLogWrMmioAccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, PSPADDR PspAddrPc, PSPADDR PspAddrMmio, bool fWrite, size_t cb, const void *pv)
{
    PPSPIOLOGWRINT pThis = hIoLogWr;

    PSPIOLOGEVT Evt;
    Evt.u16AddrSpace = PSP_IO_LOG_EVT_ADDR_SPACE_MMIO;
    Evt.fFlags       = fWrite ? PSP_IO_LOG_EVT_F_WRITE : PSP_IO_LOG_EVT_F_READ;
    Evt.idCcd        = idCcd;
    Evt.uAddrPc      = PspAddrPc;
    Evt.u64Addr      = PspAddrMmio;
    Evt.cbAcc        = (uint32_t)cb;
    Evt.u64TsEvt     = pspEmuIoLogGetTimeNs() - pThis->u64TsStart;
    return pspEmuIoLogWrEvtAdd(pThis, &Evt, pv, cb);
}


int PSPEmuIoLogWrX86AccAdd(PSPIOLOGWR hIoLogWr, uint32_t idCcd, PSPADDR PspAddrPc, X86PADDR PhysX86Addr, bool fWrite, size_t cb, const void *pv)
{
    PPSPIOLOGWRINT pThis = hIoLogWr;

    PSPIOLOGEVT Evt;
    Evt.u16AddrSpace = PSP_IO_LOG_EVT_ADDR_SPACE_X86;
    Evt.fFlags       = fWrite ? PSP_IO_LOG_EVT_F_WRITE : PSP_IO_LOG_EVT_F_READ;
    Evt.idCcd        = idCcd;
    Evt.uAddrPc      = PspAddrPc;
    Evt.u64Addr      = PhysX86Addr;
    Evt.cbAcc        = (uint32_t)cb;
    Evt.u64TsEvt     = pspEmuIoLogGetTimeNs() - pThis->u64TsStart;
    return pspEmuIoLogWrEvtAdd(pThis, &Evt, pv, cb);
}


int PSPEmuIoLogRdrCreate(PPSPIOLOGRDR phIoLogRdr, const char *pszFilename)
{
    int rc = STS_ERR_GENERAL_ERROR;
    FILE *pIoLogFile = fopen(pszFilename, "rb");
    if (pIoLogFile)
    {
        PSPIOLOGHDR Hdr;
        size_t cbRead = fread(&Hdr, sizeof(Hdr), 1, pIoLogFile);
        if (cbRead == 1)
        {
            /* Verify header. */
            if (   !memcmp(&Hdr.achMagic[0], PSP_IO_LOG_HDR_MAGIC, sizeof(Hdr.achMagic))
                && Hdr.u32Endianess == PSP_IO_LOG_HDR_ENDIANESS
                && Hdr.u32Version == PSP_IO_LOG_HDR_VERSION
                && Hdr.u64Rsvd0 == 0)
            {
                PPSPIOLOGRDRINT pThis = (PPSPIOLOGRDRINT)calloc(1, sizeof(*pThis));
                if (pThis)
                {
                    pThis->pFile      = pIoLogFile;
                    pThis->u64TsStart = Hdr.u64TsStart;
                    pThis->cbData     = 0;
                    pThis->offBuf     = 0;
                    pThis->fError     = false;
                    pThis->fEos       = false;
                    *phIoLogRdr = pThis;
                    return STS_INF_SUCCESS;
                }
                else
                    rc = STS_ERR_NO_MEMORY;
            }
            else /** @todo You might be the lucky one having to implement endianess handling. */
                rc = STS_ERR_GENERAL_ERROR;
        }
        else
            rc = STS_ERR_GENERAL_ERROR;

        fclose(pIoLogFile);
    }

    return rc;
}


void PSPEmuIoLogRdrDestroy(PSPIOLOGRDR hIoLogRdr)
{
    PPSPIOLOGRDRINT pThis = hIoLogRdr;

    fclose(pThis->pFile);
    free(pThis);
}


int PSPEmuIoLogRdrEvtQueryNext(PSPIOLOGRDR hIoLogRdr, PCPSPIOLOGRDREVT *ppIoLogEvt)
{
    (void)ppIoLogEvt;

    PPSPIOLOGRDRINT pThis = hIoLogRdr;
    if (   pThis->fEos
        && pThis->cbData == pThis->offBuf)
        return STS_ERR_GENERAL_ERROR; /** @todo Proper status code. */

    PSPIOLOGEVT EvtHdr;
    int rc = pspEmuIoLogRdrRead(pThis, &EvtHdr, sizeof(EvtHdr));
    if (STS_SUCCESS(rc))
    {
        if (   (   EvtHdr.u16AddrSpace == PSP_IO_LOG_EVT_ADDR_SPACE_SMN
                || EvtHdr.u16AddrSpace == PSP_IO_LOG_EVT_ADDR_SPACE_MMIO
                || EvtHdr.u16AddrSpace == PSP_IO_LOG_EVT_ADDR_SPACE_X86)
            && (EvtHdr.cbAcc < 16 * 1024 * 1024)) /* Arbitrary limit. */
        {
            PPSPIOLOGRDREVT pEvt = (PPSPIOLOGRDREVT)calloc(1, sizeof(*pEvt) + EvtHdr.cbAcc);
            if (pEvt)
            {
                pEvt->idCcd     = EvtHdr.idCcd;
                pEvt->PspAddrPc = EvtHdr.uAddrPc;
                pEvt->cbAcc     = (size_t)EvtHdr.cbAcc;
                pEvt->fWrite    = (EvtHdr.fFlags & PSP_IO_LOG_EVT_F_WRITE) ? true : false;
                pEvt->pvData    = (pEvt + 1);

                switch (EvtHdr.u16AddrSpace)
                {
                    case PSP_IO_LOG_EVT_ADDR_SPACE_SMN:
                    {
                        pEvt->enmAddrSpace = PSPADDRSPACE_SMN;
                        pEvt->u.SmnAddr    = (SMNADDR)EvtHdr.u64Addr;
                        break;
                    }
                    case PSP_IO_LOG_EVT_ADDR_SPACE_MMIO:
                    {
                        pEvt->enmAddrSpace  = PSPADDRSPACE_PSP;
                        pEvt->u.PspAddrMmio = (PSPADDR)EvtHdr.u64Addr;
                        break;
                    }
                    case PSP_IO_LOG_EVT_ADDR_SPACE_X86:
                    {
                        pEvt->enmAddrSpace  = PSPADDRSPACE_X86;
                        pEvt->u.PhysX86Addr = EvtHdr.u64Addr;
                        break;
                    }
                    default:
                        rc = STS_ERR_GENERAL_ERROR;
                        break;
                }

                rc = pspEmuIoLogRdrRead(pThis, pEvt + 1, pEvt->cbAcc);
                if (STS_SUCCESS(rc))
                    *ppIoLogEvt = pEvt;
                else
                    free(pEvt);
            }
            else
                rc = STS_ERR_NO_MEMORY;
        }
        else
            rc = STS_ERR_INVALID_PARAMETER;
    }

    return rc;
}


int PSPEmuIoLogRdrEvtFree(PSPIOLOGRDR hIoLogRdr, PCPSPIOLOGRDREVT pIoLogEvt)
{
    (void)hIoLogRdr;

    free((void *)pIoLogEvt); /* Keep it simple for now */
    return STS_INF_SUCCESS;
}
