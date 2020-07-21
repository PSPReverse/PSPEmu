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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <common/status.h>

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
    /** Content is a SMC descriptor. */
    PSPTRACEEVTCONTENTTYPE_SMC,
    /** 32bit hack. */
    PSPTRACEEVTCONTENTTYPE_32BIT_HACK = 0x7fffffff
} PSPTRACEEVTCONTENTTYPE;


/**
 * String descriptor.
 */
typedef struct PSPTRACEEVTSTR
{
    /** Number of lines encoded in the following.string array. */
    uint32_t                        cLines;
    /** String content. */
    char                            achStr[1];
} PSPTRACEEVTSTR;
/** Pointer to a string descriptor. */
typedef PSPTRACEEVTSTR *PPSPTRACEEVTSTR;
/** Pointer to a const string descriptor. */
typedef const PSPTRACEEVTSTR *PCPSPTRACEEVTSTR;


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
 * SVC/SMC event.
 */
typedef struct PSPTRACEEVTSVMC
{
    /** Flag whether this an entry or exit event. */
    bool                            fEntry;
    /** The SVC/SMC number. */
    uint32_t                        idxSvmc;
    /** Arguments for entry, return value for exit event. */
    uint32_t                        au32ArgsRet[5];
    /** Message logged - vairable in size. */
    char                            szMsg[1];
} PSPTRACEEVTSVMC;
/** Pointer to a SVC event descriptor. */
typedef PSPTRACEEVTSVMC *PPSPTRACEEVTSVMC;
/** Pointer to a const SVC event descriptor. */
typedef const PSPTRACEEVTSVMC *PCPSPTRACEEVTSVMC;


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
    /** PSP core state. */
    PSPCORESTATE                    CoreState;
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
    /** Number of events to buffer before flushing. */
    uint32_t                        cEvtsBuffer;
    /** Flush callback. */
    PFNPSPTRACEFLUSH                pfnFlush;
    /** Opaque user data to pass to the flush callback. */
    void                            *pvUser;
    /** Array of event severities what kind of events are logged for each event origin. */
    PSPTRACEEVTSEVERITY             aenmEvtTypesSeverity[PSPTRACEEVTORIGIN_LAST + 1];
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
 * Severity enum to string translation.
 */
static const char *g_apszSeverity2Str[] =
{
    "INVALID",
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "FATAL_ERROR"
};


/**
 * Origin enum to string translation.
 */
static const char *g_apszOrigin2Str[] =
{
    "INVALID",
    "MMIO",
    "SMN",
    "X86",
    "X86_MMIO",
    "X86_MEM",
    "SVC",
    "SMC",
    "CCP",
    "STS",
    "GPIO",
    "IOMUX",
    "RTC",
    "LPC",
    "X86_UART",
    "PROXY",
    "DBG",
    "CORE",
    "IRQ"
};


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
    if (enmOrigin < ELEMENTS(g_apszOrigin2Str))
        return g_apszOrigin2Str[enmOrigin];

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
    if (enmSeverity < ELEMENTS(g_apszSeverity2Str))
        return g_apszSeverity2Str[enmSeverity];

    return "<UNKNOWN>";
}


/**
 * Compares two strings for equality ignoring case and, - and _ mismatches.
 *
 * @returns Flag whether both strings are considered equal.
 * @param   pszStr1                 The first string to compare.
 * @param   pszStr2                 The string to compare with.
 */
static bool pspEmuTraceStrAreEqual(const char *pszStr1, const char *pszStr2)
{
    for (; *pszStr1 || *pszStr2; pszStr1++, pszStr2++)
    {
        if (   tolower(*pszStr1) != tolower(*pszStr2)
            && !(   (*pszStr1 == '-' || *pszStr1 == '_')
                 && (*pszStr2 == '-' || *pszStr2 == '_')))
            return false;
    }

    return true;
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
            rc = PSPEmuCoreQueryState(pThis->hPspCore, &pEvt->CoreState);

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
 * Creates the common prefix for a single given event.
 *
 * @returns Pointer to the start of the prefix on success or NULL if buffer is too small.
 * @param   pThis                   The trace log instance data.
 * @param   pszBuf                  The buffer to store the prefix in.
 * @param   cbBuf                   Size of the buffer in bytes.
 * @param   fFlags                  The flags controlling what gets dumped.
 * @param   pEvt                    The trace event to dump.
 */
static const char *pspEmuTraceEvtDumpPrefixCreate(PPSPTRACEINT pThis, char *pszBuf, size_t cbBuf,
                                                  uint32_t fFlags, PCPSPTRACEEVT pEvt)
{
    char *pszCur = pszBuf;
    size_t cchLeft = cbBuf;
    const char *pszEvtSeverity = pspEmuTraceGetEvtSeverityStr(pEvt->enmSeverity);
    const char *pszEvtOrigin = pspEmuTraceGetEvtOriginStr(pEvt->enmOrigin);

    /** @todo This should probably be redone properly someday... */
    /* Trace ID. */
    int rcStr = snprintf(pszCur, cchLeft, "%08u ", pEvt->idTraceEvt);
    if (   rcStr < 0
        || rcStr >= cchLeft)
        return NULL;

    pszCur  += rcStr;
    cchLeft -= rcStr;

    /* Timestamp if configured. */
    if (fFlags & PSPEMU_TRACE_F_TIMESTAMPS)
    {
        rcStr = snprintf(pszCur, cchLeft, "%16u ", pEvt->tsTraceEvtNs);
        if (   rcStr < 0
            || rcStr >= cchLeft)
            return NULL;

        pszCur  += rcStr;
        cchLeft -= rcStr;
    }

    /* The event severity. */
    rcStr = snprintf(pszCur, cchLeft, "%16s ", pszEvtSeverity);
    if (   rcStr < 0
        || rcStr >= cchLeft)
        return NULL;

    pszCur  += rcStr;
    cchLeft -= rcStr;

    /* The event origin. */
    rcStr = snprintf(pszCur, cchLeft, "%16s ", pszEvtOrigin);
    if (   rcStr < 0
        || rcStr >= cchLeft)
        return NULL;

    pszCur  += rcStr;
    cchLeft -= rcStr;

    /* The PC if we don't have a full CPU context. */
    if (!(fFlags & PSPEMU_TRACE_F_FULL_CORE_CTX))
    {
        rcStr = snprintf(pszCur, cchLeft, "0x%08x[0x%08x][%5s,%s,%s,%s,%s,0x%08x] ",
                         pEvt->CoreState.PspAddrPc,
                         pEvt->CoreState.PspAddrLr,
                         PSPEmuCoreModeToStr(pEvt->CoreState.enmCoreMode),
                         pEvt->CoreState.fSecureWorld ? " S" : "NS",
                         pEvt->CoreState.fMmuEnabled  ? " M" : "NM",
                         pEvt->CoreState.fIrqMasked   ? "NI" : " I",
                         pEvt->CoreState.fFiqMasked   ? "NF" : " F",
                         pEvt->CoreState.PspPAddrPgTblRoot);
        if (   rcStr < 0
            || rcStr >= cchLeft)
            return NULL;

        pszCur  += rcStr;
        cchLeft -= rcStr;
    }

    return pszBuf;
}


/**
 * Dumps the given trace event to the given file.
 *
 * @returns Status code.
 * @param   pThis                   The trace log instance data.
 * @param   fFlags                  The flags controlling what gets dumped.
 * @param   pEvt                    The trace event to dump.
 */
static int pspEmuTraceEvtDump(PPSPTRACEINT pThis, uint32_t fFlags, PCPSPTRACEEVT pEvt)
{
    char achPrefix[512];
    char achPrefixSpace[512];
    char achBuf[_4K];
    char *pszCur = &achBuf[0];
    size_t cchLeft = sizeof(achBuf);
    void *pvData = NULL;
    size_t cbData = 0;
    int rcStr = 0;

    const char *pszPrefix = pspEmuTraceEvtDumpPrefixCreate(pThis, &achPrefix[0], sizeof(achPrefix),
                                                           fFlags, pEvt);
    if (!pszPrefix)
        return -1;

    memset(&achPrefixSpace[0], ' ', sizeof(achPrefixSpace));
    achPrefixSpace[strlen(pszPrefix)] = '\0';

    /* Now the content specific data. */
    switch (pEvt->enmContent)
    {
        case PSPTRACEEVTCONTENTTYPE_STRING:
        {
            PPSPTRACEEVTSTR pStr = (PPSPTRACEEVTSTR)&pEvt->abContent[0];
            const char *pszStr = &pStr->achStr[0];

            for (uint32_t i = 0; i < pStr->cLines; i++)
            {
                rcStr = snprintf(pszCur, cchLeft, "%sSTRING \"%s\"%s",
                                   i == 0
                                 ? pszPrefix
                                 : &achPrefixSpace[0],
                                 pszStr, i == pStr->cLines - 1 ? "" : "\n");
                if (   rcStr < 0
                    || rcStr >= cchLeft)
                    return -1;

                pszStr   = strchr(pszStr, '\0') + 1;
                pszCur  += rcStr;
                cchLeft -= rcStr;
            }

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

            rcStr = snprintf(pszCur, cchLeft, "%sDEV %s %-32s %#16lx %u",
                             pszPrefix,
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
        case PSPTRACEEVTCONTENTTYPE_SMC:
        {
            PPSPTRACEEVTSVMC pSvmc = (PPSPTRACEEVTSVMC)&pEvt->abContent[0];

            rcStr = snprintf(pszCur, cchLeft, "%s%s %s %#x ",
                             pszPrefix,
                             pEvt->enmContent == PSPTRACEEVTCONTENTTYPE_SVC ? "SVC" : "SMC",
                             pSvmc->fEntry ? "ENTRY" : "EXIT ",
                             pSvmc->idxSvmc);
            if (   rcStr < 0
                || rcStr >= cchLeft)
                return -1;

            pszCur  += rcStr;
            cchLeft -= rcStr;

            if (pSvmc->fEntry)
                rcStr = snprintf(pszCur, cchLeft, "%#.8x %#.8x %#.8x %#.8x LR=%#08x",
                                 pSvmc->au32ArgsRet[0],
                                 pSvmc->au32ArgsRet[1],
                                 pSvmc->au32ArgsRet[2],
                                 pSvmc->au32ArgsRet[3],
                                 pSvmc->au32ArgsRet[4]);
            else
                rcStr = snprintf(pszCur, cchLeft, "%#.8x",
                                 pSvmc->au32ArgsRet[0]);

            if (   rcStr < 0
                || rcStr >= cchLeft)
                return -1;

            pszCur  += rcStr;
            cchLeft -= rcStr;

            if (pSvmc->szMsg[0] != '\0')
            {
                rcStr = snprintf(pszCur, cchLeft, " %s",
                                 &pSvmc->szMsg[0]);

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

    /* Flush */
    int rc = pThis->pfnFlush(pThis, &achBuf[0], sizeof(achBuf) - cchLeft, pThis->pvUser);
    if (rc != 0)
        return -1;

    /* Now dump any larger data blobs. */
    if (pvData && cbData)
    {
        /** @todo */
    }

    return 0;
}


/**
 * Maybe flushes any buffered events.
 *
 * @returns Status code.
 * @param   pThis                   The trace log instance data.
 */
static int pspEmuTraceFlushMaybe(PPSPTRACEINT pThis)
{
    int rc = 0;

    if (pThis->cEvtsBuffer < pThis->cTraceEvts)
    {
        /* Walk the trace events and dump one by one. */
        for (uint64_t i = 0; i < pThis->cTraceEvts; i++)
        {
            PCPSPTRACEEVT pEvt = pThis->papTraceEvts[i];

            pThis->papTraceEvts[i] = NULL;
            pspEmuTraceEvtDump(pThis, pThis->fFlags, pEvt);
            pThis->cbEvtAlloc -= pEvt->cbAlloc;
            free((void *)pEvt);
        }

        pThis->cTraceEvts = 0;
    }

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
            rc = pspEmuTraceFlushMaybe(pThis);
        }
    }
    return rc;
}


static int pspEmuTraceFileFlush(PSPTRACE hTrace, void *pvBuf, size_t cbBuf, void *pvUser)
{
    size_t cbWritten = fwrite(pvBuf, cbBuf, 1, (FILE *)pvUser);
    if (cbWritten != 1)
        return -1;

    fflush((FILE *)pvUser);
    return 0;
}


/**
 * Creates a SVC/SMC event.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmContentType          The content type of desdcriptor.
 * @param   enmSeverity             The severity of the event.
 * @param   enmOrigin               The origin of the event.
 * @param   idxSmc                  The SMC number being executed.
 * @param   fEntry                  Flag whether this SVC entry or return.
 * @param   pszMsg                  Additional message to log.
 */
static int pspEmuTraceEvtAddSvmc(PSPTRACE hTrace, PSPTRACEEVTCONTENTTYPE enmContentType,
                                 PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                                 uint32_t idxSvmc, bool fEntry, const char *pszMsg)
{
    int rc = STS_INF_SUCCESS;
    PPSPTRACEINT pThis = pspEmuTraceGetInstanceForEvtSeverityAndOrigin(hTrace, enmSeverity, enmEvtOrigin);
    if (pThis)
    {
        PPSPTRACEEVT pEvt;
        size_t cchMsg = pszMsg ? strlen(pszMsg) + 1 : 0;
        size_t cbAlloc = sizeof(PSPTRACEEVTSVMC) + cchMsg;
        rc = pspEmuTraceEvtCreateAndLink(pThis, enmSeverity, enmEvtOrigin, enmContentType, cbAlloc, &pEvt);
        if (!rc)
        {
            PPSPTRACEEVTSVMC pSvmc = (PPSPTRACEEVTSVMC)&pEvt->abContent[0];
            pSvmc->fEntry  = fEntry;
            pSvmc->idxSvmc = idxSvmc;

            /* Query the arguments from the core. */
            static const PSPCOREREG s_aSvmcRegQuery[] =
            {
                PSPCOREREG_R0,
                PSPCOREREG_R1,
                PSPCOREREG_R2,
                PSPCOREREG_R3,
                PSPCOREREG_LR
            };

            PSPEmuCoreQueryRegBatch(pThis->hPspCore, &s_aSvmcRegQuery[0], ELEMENTS(s_aSvmcRegQuery), &pSvmc->au32ArgsRet[0]);
            if (pszMsg)
                memcpy(&pSvmc->szMsg[0], pszMsg, cchMsg);
            else
                pSvmc->szMsg[0] = '\0'; /* Make sure it is terminated. */
            rc = pspEmuTraceFlushMaybe(pThis);
        }
    }

    return rc;
}

int PSPEmuTraceSeverityStringQueryEnum(const char *pszSeverity, PPSPTRACEEVTSEVERITY penmSeverity)
{
    for (uint32_t i = 0; i < ELEMENTS(g_apszSeverity2Str); i++)
    {
        if (pspEmuTraceStrAreEqual(pszSeverity, g_apszSeverity2Str[i]))
        {
            *penmSeverity = (PSPTRACEEVTSEVERITY)i;
            return STS_INF_SUCCESS;
        }
    }

    return STS_ERR_NOT_FOUND;
}


int PSPEmuTraceOriginStringQueryEnum(const char *pszOrigin, PPSPTRACEEVTORIGIN penmOrigin)
{
    for (uint32_t i = 0; i < ELEMENTS(g_apszOrigin2Str); i++)
    {
        if (pspEmuTraceStrAreEqual(pszOrigin, g_apszOrigin2Str[i]))
        {
            *penmOrigin = (PSPTRACEEVTORIGIN)i;
            return STS_INF_SUCCESS;
        }
    }

    return STS_ERR_NOT_FOUND;
}


int PSPEmuTraceCreate(PPSPTRACE phTrace, uint32_t fFlags, PSPCORE hPspCore,
                      uint32_t cEvtsBuffer, PFNPSPTRACEFLUSH pfnFlush, void *pvUser)
{
    int rc = 0;
    PPSPTRACEINT pThis = (PPSPTRACEINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->uTraceEvtIdNext  = 0;
        pThis->tsTraceCreatedNs = 0;
        pThis->hPspCore         = hPspCore;
        pThis->fFlags           = fFlags;
        pThis->cEvtsBuffer      = cEvtsBuffer;
        pThis->pfnFlush         = pfnFlush;
        pThis->pvUser           = pvUser;
        pThis->cbEvtAlloc       = 0;
        pThis->cTraceEvtsMax    = 0;
        pThis->cTraceEvts       = 0;
        pThis->papTraceEvts     = NULL;

        if (fFlags & PSPEMU_TRACE_F_ALL_EVENTS)
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


int PSPEmuTraceCreateForFile(PPSPTRACE phTrace, uint32_t fFlags, PSPCORE hPspCore,
                             uint32_t cEvtsBuffer, const char *pszFilename)
{
    int rc = 0;
    FILE *pTraceFile = fopen(pszFilename, "wb");
    if (pTraceFile)
        rc = PSPEmuTraceCreate(phTrace, fFlags, hPspCore, cEvtsBuffer, pspEmuTraceFileFlush, pTraceFile);
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


int PSPEmuTraceEvtEnable(PSPTRACE hTrace, PCPSPTRACEEVTORIGIN paEvtOrigins, PCPSPTRACEEVTSEVERITY paEvtSeverities, uint32_t cEvts)
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


int PSPEmuTraceEvtAddStringV(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                             const char *pszFmt, va_list hArgs)
{
    int rc = 0;
    PPSPTRACEINT pThis = pspEmuTraceGetInstanceForEvtSeverityAndOrigin(hTrace, enmSeverity, enmEvtOrigin);
    if (pThis)
    {
        uint8_t szTmp[_4K]; /** @todo Maybe allocate scratch buffer if this turns to be too small (or fix your damn log strings...). */

        bzero(&szTmp[0], sizeof(szTmp));
        int rcStr = vsnprintf(&szTmp[0], sizeof(szTmp), pszFmt, hArgs);
        if (rcStr > 0)
        {
            char *pszStart = &szTmp[0];

            /* Skip any newlines at the end. */
            while (   rcStr
                   && (   szTmp[rcStr - 1] == '\n'
                       || szTmp[rcStr - 1] == '\r'))
            {
                szTmp[rcStr - 1] = '\0';
                rcStr--;
            }

            /* Skip new lines at the front. */
            while (   rcStr
                   && (   *pszStart == '\n'
                       || *pszStart == '\r'))
            {
                pszStart++;
                rcStr--;
            }

            if (rcStr)
            {
                PPSPTRACEEVT pEvt;
                size_t cbStr = rcStr + 1; /* Include terminator. */
                size_t cbAlloc = cbStr + sizeof(PSPTRACEEVTSTR);

                rc = pspEmuTraceEvtCreateAndLink(pThis, enmSeverity, enmEvtOrigin, PSPTRACEEVTCONTENTTYPE_STRING, cbAlloc, &pEvt);
                if (!rc)
                {
                    PPSPTRACEEVTSTR pStr = (PPSPTRACEEVTSTR)&pEvt->abContent[0];

                    /* Count number of lines. */
                    uint32_t cLines = 0;
                    char *pszCur = pszStart;
                    do
                    {
                        cLines++;
                        pszCur = strchr(pszCur, '\n');
                        if (pszCur)
                            *pszCur++ = '\0';
                    } while (pszCur);

                    pStr->cLines = cLines;
                    memcpy(&pStr->achStr[0], pszStart, cbStr);
                    rc = pspEmuTraceFlushMaybe(pThis);
                }
            }
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
            rc = pspEmuTraceFlushMaybe(pThis);
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
    return pspEmuTraceEvtAddSvmc(hTrace, PSPTRACEEVTCONTENTTYPE_SVC, enmSeverity, enmEvtOrigin, idxSvc, fEntry, pszMsg);
}

int PSPEmuTraceEvtAddSmc(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                         uint32_t idxSmc, bool fEntry, const char *pszMsg)
{
    return pspEmuTraceEvtAddSvmc(hTrace, PSPTRACEEVTCONTENTTYPE_SMC, enmSeverity, enmEvtOrigin, idxSmc, fEntry, pszMsg);
}

