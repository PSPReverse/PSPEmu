/** @file
 * PSP Emulator - Tracing framework.
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <psp-trace.h>


/**
 * Trace event content type.
 */
typedef enum PSPTRACEEVTCONTENTTYPE
{
    /** Invalid content type - do not use. */
    PSPTRACEEVTCONTENTTYPE_INVALID = 0,
    /** Content is a raw zero terminated string. */
    PSPTRACEEVTCONTENTTYPE_STRING,
    /** Content is a memory transfer. */
    PSPTRACEEVTCONTENTTYPE_XFER,
    /** Content is a device read/write event. */
    PSPTRACEEVTCONTENTTYPE_DEV_XFER,
    /** Content is a SVC descriptor. */
    PSPTRACEEVTCONTENTTYPE_SVC,
    /** 32bit hack. */
    PSPTRACEEVTCONTENTTYPE_32BIT_HACK = 0x7fffffff
} PSPTRACEEVTCONTENTTYPE;


/**
 * Data transfer descriptor.
 */
typedef struct PSPTRACEEVTXFER
{
    /** The source address read from. */
    uint64_t                        uAddrSrc;
    /** The destination address begin written to. */
    uint64_t                        uAddrDst;
    /** Size of the transfer in bytes. */
    size_t                          cbXfer;
    /** Data being transfered. */
    uint8_t                         abXfer[1];
} PSPTRACEEVTXFER;
/** Pointer to a data transfer descriptor. */
typedef PSPTRACEEVTXFER *PPSPTRACEEVTXFER;
/** Pointer to a const data transfer descriptor. */
typedef const PSPTRACEEVTXFER *PCPSPTRACEEVTXFER;


/**
 * Device read/write descriptor.
 */
typedef struct PSPTRACEEVTDEVXFER
{
    /** The device address being accessed. */
    uint64_t                        uAddrDev;
    /** Number of bytes being transfered. */
    size_t                          cbXfer;
    /** Flag whether this is a read or write. */
    bool                            fRead;
    /** Pointer to the device ID string. */
    const char                      *pszDevId;
    /** Data being read/written. */
    uint8_t                         abXfer[1];
} PSPTRACEEVTDEVXFER;
/** Pointer to a device read/write descriptor. */
typedef PSPTRACEEVTDEVXFER *PPSPTRACEEVTDEVXFER;
/** Pointer to a const device /read/write descriptor. */
typedef const PSPTRACEEVTDEVXFER *PCPSPTRACEEVTDEVXFER;


/**
 * SVC event.
 */
typedef struct PSPTRACEEVTSVC
{
    /** Flag whether this an entry or exit event. */
    bool                            fEntry;
    /** The SVC number. */
    uint32_t                        idxSvc;
    /** Arguments for entry, return value for exit event. */
    uint32_t                        au32ArgsRet[4];
    /** Message logged - vairable in size. */
    char                            szMsg[1];
} PSPTRACEEVTSVC;
/** Pointer to a SVC event descriptor. */
typedef PSPTRACEEVTSVC *PPSPTRACEEVTSVC;
/** Pointer to a const SVC event descriptor. */
typedef const PSPTRACEEVTSVC *PCPSPTRACEEVTSVC;


/**
 * A trace event.
 */
typedef struct PSPTRACEEVT
{
    /** Trace event ID. */
    uint64_t                        idTraceEvt;
    /** Event timestamp in nanoseconds since creation of the owning tracer if configured. */
    uint64_t                        tsTraceEvtNs;
    /** The event severity. */
    PSPTRACEEVTSEVERITY             enmSeverity;
    /** The event origin. */
    PSPTRACEEVTORIGIN               enmOrigin;
    /** The content type. */
    PSPTRACEEVTCONTENTTYPE          enmContent;
    /** The PSP core context when this event happened. */
    uint32_t                        au32CoreRegs[PSPCOREREG_SPSR + 1];
    /** Number of bytes allocated for this event in the array below. */
    size_t                          cbAlloc;
    /** Array holding the content depending on the content type - variable in size. */
    uint8_t                         abContent[1];
} PSPTRACEEVT;
/** Pointer to a trace event. */
typedef PSPTRACEEVT *PPSPTRACEEVT;
/** Pointer to a const trace event. */
typedef const PSPTRACEEVT *PCPSPTRACEEVT;


/**
 * The tracer instance data.
 */
typedef struct PSPTRACEINT
{
    /** The next trace event ID to use. */
    uint64_t                        uTraceEvtIdNext;
    /** The nanosecond timestamp when the tracer was created. */
    uint64_t                        tsTraceCreatedNs;
    /** Pointer to the PSP core. */
    PSPCORE                         hPspCore;
    /** Flags controlling the trace behavior given during creation. */
    uint32_t                        fFlags;
    /** Array of event severities what kind of events are logged for each event origin. */
    PSPTRACEEVTSEVERITY             aenmEvtTypesSeverity[PSPTRACEEVTORIGIN_LAST];
    /** Number of bytes currently allocated for all stored trace events. */
    size_t                          cbEvtAlloc;
    /** Maximum number of trace events the array below can hold. */
    uint64_t                        cTraceEvtsMax;
    /** Current number of trace events being stored in the array below. */
    uint64_t                        cTraceEvts;
    /** Pointer to the array holding the pointers to the individual trace events. */
    PCPSPTRACEEVT                   *papTraceEvts;
} PSPTRACEINT;
/** Pointer to the tracer instance data. */
typedef PSPTRACEINT *PPSPTRACEINT;
/** Pointer to a const tracer instance. */
typedef const PSPTRACEINT *PCPSPTRACEINT;


/** Global default tracer instance used. */
static PPSPTRACEINT g_pTraceDef = NULL;


/**
 * Returns the tracer to use.
 *
 * @returns Tracer instance to use or NULL if nothing is configured.
 * @param   hTrace                  The tracer handle to use, if NULL the default one is returned.
 */
static inline PPSPTRACEINT pspEmuTraceGetInstance(PSPTRACE hTrace)
{
    return hTrace == NULL ? g_pTraceDef : hTrace;
}


/**
 * Returns the tracer to use accounting the given event type.
 *
 * @returns Tracer instance to use or NULL if nothing is configured.
 * @param   hTrace                  The tracer handle to use, if NULL the default one is returned.
 * @param   enmEvtType              The event type to check if the tracer has the event type disabled NULL is returned.
 */
static inline PPSPTRACEINT pspEmuTraceGetInstanceForEvtSeverityAndOrigin(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity,
                                                                         PSPTRACEEVTORIGIN enmOrigin)
{
    PPSPTRACEINT pThis = pspEmuTraceGetInstance(hTrace);
    if (   pThis
        && pThis->aenmEvtTypesSeverity[enmOrigin] <= enmSeverity)
        return pThis;

    return NULL;
}


/**
 * Returns a human readable string for the given event origin.
 *
 * @returns Pointer to const human readable string.
 * @param   enmOrigin               The event origin.
 */
static const char *pspEmuTraceGetEvtOriginStr(PSPTRACEEVTORIGIN enmOrigin)
{
    switch (enmOrigin)
    {
        case PSPTRACEEVTORIGIN_INVALID:     return "INVALID";
        case PSPTRACEEVTORIGIN_MMIO:        return "MMIO";
        case PSPTRACEEVTORIGIN_SMN:         return "SMN";
        case PSPTRACEEVTORIGIN_X86:         return "X86";
        case PSPTRACEEVTORIGIN_X86_MMIO:    return "X86_MMIO";
        case PSPTRACEEVTORIGIN_X86_MEM:     return "X86_MEM";
        case PSPTRACEEVTORIGIN_SVC:         return "SVC";
        case PSPTRACEEVTORIGIN_CCP:         return "CCP";
        case PSPTRACEEVTORIGIN_X86_UART:    return "X86_UART";
    }

    return "<UNKNOWN>";
}


/**
 * Returns a human readable string for the given event severity.
 *
 * @returns Pointer to const human readable string.
 * @param   enmSeverity             The event severity.
 */
static const char *pspEmuTraceGetEvtSeverityStr(PSPTRACEEVTSEVERITY enmSeverity)
{
    switch (enmSeverity)
    {
        case PSPTRACEEVTSEVERITY_INVALID:     return "INVALID";
        case PSPTRACEEVTSEVERITY_DEBUG:       return "DEBUG";
        case PSPTRACEEVTSEVERITY_INFO:        return "INFO";
        case PSPTRACEEVTSEVERITY_WARNING:     return "WARNING";
        case PSPTRACEEVTSEVERITY_ERROR:       return "ERROR";
        case PSPTRACEEVTSEVERITY_FATAL_ERROR: return "FATAL_ERROR";
    }

    return "<UNKNOWN>";
}


/**
 * Links the event to the given tracer, assigning an event ID on success.
 *
 * @returns Status code.
 * @param   pThis                   The tracer instance.
 * @param   pEvt                    The event to link.
 */
static int pspEmuTraceEvtLink(PPSPTRACEINT pThis, PPSPTRACEEVT pEvt)
{
    int rc = 0;
    if (pThis->cTraceEvts == pThis->cTraceEvtsMax)
    {
        /* Grow the array. */
        PCPSPTRACEEVT *papTraceEvtsNew = (PCPSPTRACEEVT *)realloc(pThis->papTraceEvts, (pThis->cTraceEvtsMax + _4K) * sizeof(PCPSPTRACEEVT));
        if (papTraceEvtsNew)
        {
            pThis->papTraceEvts  = papTraceEvtsNew;
            pThis->cTraceEvtsMax += _4K;
        }
        else
            rc = -1;
    }

    if (!rc)
    {
        pEvt->idTraceEvt  = pThis->uTraceEvtIdNext++;
        pThis->cbEvtAlloc += sizeof(*pEvt) + pEvt->cbAlloc;
        pThis->papTraceEvts[pThis->cTraceEvts++] = pEvt;
    }

    return rc;
}


/**
 * Creates a new trace event and links it into the tracer on success..
 *
 * @returns Status code.
 * @param   pThis                   The tracer instance.
 * @param   enmSeverity             The event severity.
 * @param   enmOrigin               The event origin.
 * @param   enmContent              Content type for the event.
 * @param   cbAlloc                 Number of bytes to allocate for additional data.
 * @param   ppEvt                   Where to store the pointer to the created event on success.
 *
 * @note This method assigns the timestamps and event ID and adds the event record to the given tracer.
 *       Don't do anything which might fail and leave the event record in an invalid state after this succeeded.
 */
static int pspEmuTraceEvtCreateAndLink(PPSPTRACEINT pThis, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmOrigin,
                                       PSPTRACEEVTCONTENTTYPE enmContent, size_t cbAlloc, PPSPTRACEEVT *ppEvt)
{
    int rc = 0;
    PPSPTRACEEVT pEvt = (PPSPTRACEEVT)calloc(1, sizeof(*pEvt) + cbAlloc);
    if (pEvt)
    {
        pEvt->idTraceEvt     = 0;
        /*pEvt->tsTraceEvtNs = ...; */ /** @todo */
        pEvt->enmSeverity    = enmSeverity;
        pEvt->enmOrigin      = enmOrigin;
        pEvt->enmContent     = enmContent;
        pEvt->cbAlloc        = cbAlloc;

        /* Gather the PSP core context. */
        if (pThis->fFlags & PSPEMU_TRACE_F_FULL_CORE_CTX)
        {
            /** @todo Need a batch query for the core API. */
        }
        else
            rc = PSPEmuCoreQueryReg(pThis->hPspCore, PSPCOREREG_PC, &pEvt->au32CoreRegs[PSPCOREREG_PC]);

        if (!rc)
        {
            rc = pspEmuTraceEvtLink(pThis, pEvt);
            if (!rc)
            {
                *ppEvt = pEvt;
                return 0;
            }
        }

        free(pEvt);
    }
    else
        rc = -1;

    return rc;
}


/**
 * Worker for the add device read/write event methods.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmSeverity             The event severity.
 * @param   enmOrigin               The event origin.
 * @param   pszDevId                The device identifier of the device being accessed.
 * @param   uAddr                   The context specific device address the transfer started at.
 * @param   pvData                  The data being read or written.
 * @param   cbXfer                  Number of bytes being transfered.
 * @param   fRead                   Flag whether this was a read or write event.
 */
static int pspEmuTraceEvtAddDevReadWriteWorker(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmOrigin,
                                               const char *pszDevId, uint64_t uAddr, const void *pvData, size_t cbXfer, bool fRead)
{
    int rc = 0;
    PPSPTRACEINT pThis = pspEmuTraceGetInstanceForEvtSeverityAndOrigin(hTrace, enmSeverity, enmOrigin);
    if (pThis)
    {
        PPSPTRACEEVT pEvt;
        size_t cchDevId = strlen(pszDevId) + 1; /* Include terminator */
        size_t cbAlloc = sizeof(PSPTRACEEVTDEVXFER) + cbXfer + cchDevId;
        rc = pspEmuTraceEvtCreateAndLink(pThis, enmSeverity, enmOrigin, PSPTRACEEVTCONTENTTYPE_DEV_XFER, cbAlloc, &pEvt);
        if (!rc)
        {
            PPSPTRACEEVTDEVXFER pDevXfer = (PPSPTRACEEVTDEVXFER)&pEvt->abContent[0];

            pDevXfer->uAddrDev = uAddr;
            pDevXfer->cbXfer   = cbXfer;
            pDevXfer->fRead    = fRead;
            pDevXfer->pszDevId = (const char *)&pDevXfer->abXfer[cbXfer];
            memcpy(&pDevXfer->abXfer[0], pvData, cbXfer);
            memcpy(&pDevXfer->abXfer[cbXfer], pszDevId, cchDevId);
        }
    }

    return rc;
}


/**
 * Dumps the given trace event to the given file.
 *
 * @returns Status code.
 * @param   pTraceFile              The file to dump the event to.
 * @param   fFlags                  The flags controlling what gets dumped.
 * @param   pEvt                    The trace event to dump.
 */
static int pspEmuTraceEvtDumpToFile(FILE *pTraceFile, uint32_t fFlags, PCPSPTRACEEVT pEvt)
{
    char achBuf[_4K];
    char *pszCur = &achBuf[0];
    size_t cchLeft = sizeof(achBuf);
    void *pvData = NULL;
    size_t cbData = 0;
    const char *pszEvtSeverity = pspEmuTraceGetEvtSeverityStr(pEvt->enmSeverity);
    const char *pszEvtOrigin = pspEmuTraceGetEvtOriginStr(pEvt->enmOrigin);

    /** @todo This should probably be redone properly someday... */
    /* Trace ID. */
    int rcStr = snprintf(pszCur, cchLeft, "%08u ", pEvt->idTraceEvt);
    if (   rcStr < 0
        || rcStr >= cchLeft)
        return -1;

    pszCur  += rcStr;
    cchLeft -= rcStr;

    /* Timestamp if configured. */
    if (fFlags & PSPEMU_TRACE_F_TIMESTAMPS)
    {
        rcStr = snprintf(pszCur, cchLeft, "%16u ", pEvt->tsTraceEvtNs);
        if (   rcStr < 0
            || rcStr >= cchLeft)
            return -1;

        pszCur  += rcStr;
        cchLeft -= rcStr;
    }

    /* The event severity. */
    rcStr = snprintf(pszCur, cchLeft, "%16s ", pszEvtSeverity);
    if (   rcStr < 0
        || rcStr >= cchLeft)
        return -1;

    pszCur  += rcStr;
    cchLeft -= rcStr;

    /* The event origin. */
    rcStr = snprintf(pszCur, cchLeft, "%16s ", pszEvtOrigin);
    if (   rcStr < 0
        || rcStr >= cchLeft)
        return -1;

    pszCur  += rcStr;
    cchLeft -= rcStr;

    /* The PC if we don't have a full CPU context. */
    if (!(fFlags & PSPEMU_TRACE_F_FULL_CORE_CTX))
    {
        rcStr = snprintf(pszCur, cchLeft, "0x%08x ", pEvt->au32CoreRegs[PSPCOREREG_PC]);
        if (   rcStr < 0
            || rcStr >= cchLeft)
            return -1;

        pszCur  += rcStr;
        cchLeft -= rcStr;
    }

    /* Now the content specific data. */
    switch (pEvt->enmContent)
    {
        case PSPTRACEEVTCONTENTTYPE_STRING:
        {
            rcStr = snprintf(pszCur, cchLeft, "STRING \"%s\"", (const char *)&pEvt->abContent[0]);
            if (   rcStr < 0
                || rcStr >= cchLeft)
                return -1;

            pszCur  += rcStr;
            cchLeft -= rcStr;
            break;
        }
        case PSPTRACEEVTCONTENTTYPE_XFER:
        {
            PPSPTRACEEVTXFER pXfer = (PPSPTRACEEVTXFER)&pEvt->abContent[0];
            break;
        }
        case PSPTRACEEVTCONTENTTYPE_DEV_XFER:
        {
            PPSPTRACEEVTDEVXFER pDevXfer = (PPSPTRACEEVTDEVXFER)&pEvt->abContent[0];

            rcStr = snprintf(pszCur, cchLeft, "DEV %s %s %#16lx %u",
                             pDevXfer->fRead ? "READ " : "WRITE",
                             pDevXfer->pszDevId,
                             pDevXfer->uAddrDev,
                             pDevXfer->cbXfer);
            if (   rcStr < 0
                || rcStr >= cchLeft)
                return -1;

            pszCur  += rcStr;
            cchLeft -= rcStr;

            if (   pDevXfer->cbXfer == 1
                || pDevXfer->cbXfer == 2
                || pDevXfer->cbXfer == 4
                || pDevXfer->cbXfer == 8)
            {
                uint64_t uVal = 0;

                switch (pDevXfer->cbXfer)
                {
                    case 1:
                        uVal = *(uint8_t *)&pDevXfer->abXfer[0];
                        break;
                    case 2:
                        uVal = *(uint16_t *)&pDevXfer->abXfer[0];
                        break;
                    case 4:
                        uVal = *(uint32_t *)&pDevXfer->abXfer[0];
                        break;
                    case 8:
                        uVal = *(uint64_t *)&pDevXfer->abXfer[0];
                        break;
                    default: /* Paranoia */
                        return -1;
                }

                rcStr = snprintf(pszCur, cchLeft, " 0x%.*lx", pDevXfer->cbXfer * 2, uVal);
                if (   rcStr < 0
                    || rcStr >= cchLeft)
                    return -1;

                pszCur  += rcStr;
                cchLeft -= rcStr;
            }
            else
            {
                /* Dump big data below. */
                pvData = &pDevXfer->abXfer[0];
                cbData = pDevXfer->cbXfer;
            }
            break;
        }
        case PSPTRACEEVTCONTENTTYPE_SVC:
        {
            PPSPTRACEEVTSVC pSvc = (PPSPTRACEEVTSVC)&pEvt->abContent[0];

            rcStr = snprintf(pszCur, cchLeft, "SVC %s %#x ",
                             pSvc->fEntry ? "ENTRY" : "EXIT ",
                             pSvc->idxSvc);
            if (   rcStr < 0
                || rcStr >= cchLeft)
                return -1;

            pszCur  += rcStr;
            cchLeft -= rcStr;

            if (pSvc->fEntry)
                rcStr = snprintf(pszCur, cchLeft, "%#.8x %#.8x %#.8x %#.8x",
                                 pSvc->au32ArgsRet[0],
                                 pSvc->au32ArgsRet[1],
                                 pSvc->au32ArgsRet[2],
                                 pSvc->au32ArgsRet[3]);
            else
                rcStr = snprintf(pszCur, cchLeft, "%#.8x",
                                 pSvc->au32ArgsRet[0]);

            if (   rcStr < 0
                || rcStr >= cchLeft)
                return -1;

            pszCur  += rcStr;
            cchLeft -= rcStr;

            if (pSvc->szMsg[0] != '\0')
            {
                rcStr = snprintf(pszCur, cchLeft, " %s",
                                 &pSvc->szMsg[0]);

                if (   rcStr < 0
                    || rcStr >= cchLeft)
                    return -1;

                pszCur  += rcStr;
                cchLeft -= rcStr;
            }
            break;
        }
        default: /* Should not happen */
            return -1;
    }

    if (!cchLeft)
        return -1;

    /* Convert zero terminator to newline. */
    *pszCur = '\n';
    pszCur++;
    cchLeft--;

    /* Now the full CPU context if available. */
    if (fFlags & PSPEMU_TRACE_F_FULL_CORE_CTX)
    {
        /** @todo */
    }

    /* Write to file. */
    size_t cbWritten = fwrite(&achBuf[0], sizeof(achBuf) - cchLeft, 1, pTraceFile);
    if (cbWritten != 1)
        return -1;

    /* Now dump any larger data blobs. */
    if (pvData && cbData)
    {
        /** @todo */
    }

    return 0;
}


int PSPEmuTraceCreate(PPSPTRACE phTrace, uint32_t fFlags, PSPCORE hPspCore)
{
    int rc = 0;
    PPSPTRACEINT pThis = (PPSPTRACEINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->uTraceEvtIdNext  = 0;
        pThis->tsTraceCreatedNs = 0;
        pThis->hPspCore         = hPspCore;
        pThis->fFlags           = fFlags;
        pThis->cbEvtAlloc       = 0;
        pThis->cTraceEvtsMax    = 0;
        pThis->cTraceEvts       = 0;
        pThis->papTraceEvts     = NULL;

        if (fFlags &PSPEMU_TRACE_F_ALL_EVENTS)
        {
            for (uint32_t i = 0; i < ELEMENTS(pThis->aenmEvtTypesSeverity); i++)
                pThis->aenmEvtTypesSeverity[i] = PSPTRACEEVTSEVERITY_DEBUG;
        }

        /** @todo Timestamping. */

        *phTrace = pThis;
    }
    else
        rc = -1;

    return rc;
}


void PSPEmuTraceDestroy(PSPTRACE hTrace)
{
    PPSPTRACEINT pThis = hTrace;

    /* Unset as default. */
    if (g_pTraceDef == pThis)
        g_pTraceDef = NULL;

    /* Free all trace events. */
    if (pThis->papTraceEvts)
    {
        for (uint32_t i = 0; i < pThis->cTraceEvts; i++)
            free((void *)pThis->papTraceEvts[i]);
        free(pThis->papTraceEvts);
    }
    free(pThis);
}


int PSPEmuTraceSetDefault(PSPTRACE hTrace)
{
    g_pTraceDef = hTrace;
    return 0;
}


int PSPEmuTraceEvtEnable(PSPTRACE hTrace, PSPTRACEEVTORIGIN *paEvtOrigins, PSPTRACEEVTSEVERITY *paEvtSeverities, uint32_t cEvts)
{
    int rc = 0;
    PPSPTRACEINT pThis = pspEmuTraceGetInstance(hTrace);

    if (pThis)
    {
        for (uint32_t i = 0; i < cEvts; i++)
        {
            PSPTRACEEVTORIGIN enmOrigin = paEvtOrigins[i];
            if (enmOrigin < PSPTRACEEVTORIGIN_LAST)
                pThis->aenmEvtTypesSeverity[enmOrigin] = paEvtSeverities[i];
            else
                return -1;
        }
    }

    return rc;
}


int PSPEmuTraceDumpToFile(PSPTRACE hTrace, const char *pszFilename)
{
    int rc = 0;
    PPSPTRACEINT pThis = pspEmuTraceGetInstance(hTrace);
    FILE *pTraceFile = fopen(pszFilename, "wb");
    if (pTraceFile)
    {
        /* Walk the trace events and dump one by one. */
        for (uint64_t i = 0; i < pThis->cTraceEvts && !rc; i++)
            rc = pspEmuTraceEvtDumpToFile(pTraceFile, pThis->fFlags, pThis->papTraceEvts[i]);
        fclose(pTraceFile);
    }
    else
        rc = -1;

    return rc;
}


int PSPEmuTraceEvtAddStringV(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                             const char *pszFmt, va_list hArgs)
{
    int rc = 0;
    PPSPTRACEINT pThis = pspEmuTraceGetInstanceForEvtSeverityAndOrigin(hTrace, enmSeverity, enmEvtOrigin);
    if (pThis)
    {
        uint8_t szTmp[_4K]; /** @todo Maybe allocate scratch buffer if this turns to be too small (or fix your damn log strings...). */
        int rcStr = vsnprintf(&szTmp[0], sizeof(szTmp), pszFmt, hArgs);

        if (rcStr > 0)
        {
            PPSPTRACEEVT pEvt;
            size_t cbAlloc = rcStr + 1; /* Include terminator. */
            rc = pspEmuTraceEvtCreateAndLink(pThis, enmSeverity, enmEvtOrigin, PSPTRACEEVTCONTENTTYPE_STRING, cbAlloc, &pEvt);
            if (!rc)
                memcpy(&pEvt->abContent[0], &szTmp[0], cbAlloc);
        }
        else
            rc = -1;
    }

    return rc;
}


int PSPEmuTraceEvtAddString(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                            const char *pszFmt, ...)
{
    va_list hArgs;

    va_start(hArgs, pszFmt);
    int rc = PSPEmuTraceEvtAddStringV(hTrace, enmSeverity, enmEvtOrigin, pszFmt, hArgs);
    va_end(hArgs);

    return rc;
}


int PSPEmuTraceEvtAddXfer(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                          uint64_t uAddrSrc, uint64_t uAddrDst, const void *pvBuf, size_t cbXfer)
{
    int rc = 0;
    PPSPTRACEINT pThis = pspEmuTraceGetInstanceForEvtSeverityAndOrigin(hTrace, enmSeverity, enmEvtOrigin);
    if (pThis)
    {
        PPSPTRACEEVT pEvt;
        size_t cbAlloc = sizeof(PSPTRACEEVTXFER) + cbXfer;
        rc = pspEmuTraceEvtCreateAndLink(pThis, enmSeverity, enmEvtOrigin, PSPTRACEEVTCONTENTTYPE_XFER, cbAlloc, &pEvt);
        if (!rc)
        {
            PPSPTRACEEVTXFER pXfer = (PPSPTRACEEVTXFER)&pEvt->abContent[0];
            pXfer->uAddrSrc = uAddrSrc;
            pXfer->uAddrDst = uAddrDst;
            pXfer->cbXfer   = cbXfer;
            memcpy(&pXfer->abXfer[0], pvBuf, cbXfer);
        }
    }

    return rc;
}


int PSPEmuTraceEvtAddDevRead(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                             const char *pszDevId, uint64_t uAddr, const void *pvData, size_t cbRead)
{
    return pspEmuTraceEvtAddDevReadWriteWorker(hTrace, enmSeverity, enmEvtOrigin, pszDevId, uAddr, pvData, cbRead, true /*fRead*/);
}


int PSPEmuTraceEvtAddDevWrite(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                              const char *pszDevId, uint64_t uAddr, const void *pvData, size_t cbWrite)
{
    return pspEmuTraceEvtAddDevReadWriteWorker(hTrace, enmSeverity, enmEvtOrigin, pszDevId, uAddr, pvData, cbWrite, false /*fRead*/);
}

int PSPEmuTraceEvtAddSvc(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                         uint32_t idxSvc, bool fEntry, const char *pszMsg)
{
    int rc = 0;
    PPSPTRACEINT pThis = pspEmuTraceGetInstanceForEvtSeverityAndOrigin(hTrace, enmSeverity, enmEvtOrigin);
    if (pThis)
    {
        PPSPTRACEEVT pEvt;
        size_t cchMsg = pszMsg ? strlen(pszMsg) + 1 : 0;
        size_t cbAlloc = sizeof(PSPTRACEEVTSVC) + cchMsg;
        rc = pspEmuTraceEvtCreateAndLink(pThis, enmSeverity, enmEvtOrigin, PSPTRACEEVTCONTENTTYPE_SVC, cbAlloc, &pEvt);
        if (!rc)
        {
            PPSPTRACEEVTSVC pSvc = (PPSPTRACEEVTSVC)&pEvt->abContent[0];
            pSvc->fEntry = fEntry;
            pSvc->idxSvc = idxSvc;

            /* Query the arguments from the core. */
            static const PSPCOREREG s_aSvcRegQuery[] =
            {
                PSPCOREREG_R0,
                PSPCOREREG_R1,
                PSPCOREREG_R2,
                PSPCOREREG_R3
            };
            PSPEmuCoreQueryRegBatch(pThis->hPspCore, &s_aSvcRegQuery[0], ELEMENTS(s_aSvcRegQuery), &pSvc->au32ArgsRet[0]);
            if (pszMsg)
                memcpy(&pSvc->szMsg[0], pszMsg, cchMsg);
            else
                pSvc->szMsg[0] = '\0'; /* Make sure it is terminated. */
        }
    }

    return rc;
}
