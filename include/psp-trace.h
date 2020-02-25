/** @file
 * PSP Emulator - Tracing framework
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
#ifndef __psp_trace_h
#define __psp_trace_h

#include <common/types.h>
#include <common/cdefs.h>

#include <psp-core.h>

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>


/** Opaque PSP tracer handle. */
typedef struct PSPTRACEINT *PSPTRACE;
/** Pointer to a PSP tracer handle. */
typedef PSPTRACE *PPSPTRACE;


/**
 * Trace event type.
 */
typedef enum PSPTRACEEVTTYPE
{
    /** Invalid type, do not use. */
    PSPTRACEEVTTYPE_INVALID = 0,
    /** Fatal error happened in the emulator possibly affecting the emulation result. */
    PSPTRACEEVTTYPE_FATAL_ERROR,
    /** A recoverable error happened. */
    PSPTRACEEVTTYPE_ERROR,
    /** PSP MMIO access. */
    PSPTRACEEVTTYPE_MMIO,
    /** PSP SMN access. */
    PSPTRACEEVTTYPE_SMN,
    /** PSP X86 MMIO access. */
    PSPTRACEEVTTYPE_X86_MMIO,
    /** PSP X86 memory access. */
    PSPTRACEEVTTYPE_X86_MEM,
    /** Emulated svc call. */
    PSPTRACEEVTTYPE_SVC,
    /** Last valid trace event type, MUST be last here!. */
    PSPTRACEEVTTYPE_LAST = PSPTRACEEVTTYPE_SVC,
    /** 32bit hack. */
    PSPTRACEEVTTYPE_32BIT_HACK = 0x7fffffff
} PSPTRACEEVTTYPE;


/** Include timestamps in the resulting logs (might not be supported on all hosts and will be ignored). */
#define PSPEMU_TRACE_F_TIMESTAMPS    BIT(0)
/** Dumps the complete PSP core state for each event (otherwise only the triggering PC is logged). */
#define PSPEMU_TRACE_F_FULL_CORE_CTX BIT(1)


/**
 * Creates a new tracer instance.
 *
 * @returns Status code.
 * @param   phTrace                 Where to store the tracer handle on success.
 * @param   fFlags                  Flags controlling the behavior, see PSPEMU_TRACE_F_XXX.
 * @param   hPspCore                PSP core handle to dump the state from if configured.
 */
int PSPEmuTraceCreate(PPSPTRACE phTrace, uint32_t fFlags, PSPCORE hPspCore);

/**
 * Destroys a given tracer handle.
 *
 * @returns nothing.
 * @param   hTrace                  The tracer handle to destroy.
 */
void PSPEmuTraceDestroy(PSPTRACE hTrace);

/**
 * Sets the default tracer (used when NULL is given in the actual tracing methods).
 *
 * @returns Status code.
 * @param   hTrace                  The new default tracer.
 */
int PSPEmuTraceSetDefault(PSPTRACE hTrace);

/**
 * Enables tracing of the given event types.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   paEvtTypes              Array of event types to enable.
 * @param   cEvtTypes               Number of events in the array.
 */
int PSPEmuTraceEvtEnable(PSPTRACE hTrace, PSPTRACEEVTTYPE *paEvtTypes, uint32_t cEvtTypes);

/**
 * Disables tracing of the given event types.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   paEvtTypes              Array of event types to disable.
 * @param   cEvtTypes               Number of events in the array.
 */
int PSPEmuTraceEvtDisable(PSPTRACE hTrace, PSPTRACEEVTTYPE *paEvtTypes, uint32_t cEvtTypes);

/**
 * Dumps the current trace to the given file.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   pszFilename             The file to dump the trace to.
 */
int PSPEmuTraceDumpToFile(PSPTRACE hTrace, const char *pszFilename);

/**
 * Adds the given string to the trace.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmEvtType              The event type this belongs to.
 * @param   pszFmt                  The format string to log.
 * @param   hArgs                   Arguments for the format string.
 */
int PSPEmuTraceEvtAddStringV(PSPTRACE hTrace, PSPTRACEEVTTYPE enmEvtType, const char *pszFmt, va_list hArgs);

/**
 * Adds the given string to the trace.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmEvtType              The event type this belongs to.
 * @param   pszFmt                  The format string to log.
 * @param   ...                     Arguments for the format string.
 */
int PSPEmuTraceEvtAddString(PSPTRACE hTrace, PSPTRACEEVTTYPE enmEvtType, const char *pszFmt, ...);

/**
 * Adds the given data transfer event to the trace.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmEvtType              The event type this belongs to.
 * @param   uAddrSrc                The context specific address the transfer started reading from.
 * @param   uAddrDst                The context specific address the transfer started writing to.
 * @param   pvBuf                   The transfered data.
 * @param   cbXfer                  The amount of bytes transfered.
 */
int PSPEmuTraceEvtAddXfer(PSPTRACE hTrace, PSPTRACEEVTTYPE enmEvtType, uint64_t uAddrSrc, uint64_t uAddrDst, const void *pvBuf, size_t cbXfer);

/**
 * Adds a device read event.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmEvtType              The event type this belongs to.
 * @param   pszDevId                The device identifier read from.
 * @param   uAddr                   The context specific device address the read started from.
 * @param   pvData                  The data being read.
 * @param   cbRead                  Number of bytes being read.
 */
int PSPEmuTraceEvtAddDevRead(PSPTRACE hTrace, PSPTRACEEVTTYPE enmEvtType, const char *pszDevId, uint64_t uAddr, const void *pvData, size_t cbRead);

/**
 * Adds a device write event.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmEvtType              The event type this belongs to.
 * @param   pszDevId                The device identifier written to.
 * @param   uAddr                   The context specific device address the write started at.
 * @param   pvData                  The data being written.
 * @param   cbWritten               Number of bytes being written.
 */
int PSPEmuTraceEvtAddDevWrite(PSPTRACE hTrace, PSPTRACEEVTTYPE enmEvtType, const char *pszDevId, uint64_t uAddr, const void *pvData, size_t cbWrite);

#endif /* __psp_trace_h */
