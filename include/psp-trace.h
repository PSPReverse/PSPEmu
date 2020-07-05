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
 * Trace event severity.
 */
typedef enum PSPTRACEEVTSEVERITY
{
    /** Invalid severity, do not use. */
    PSPTRACEEVTSEVERITY_INVALID = 0,
    /** Debug information (for debugging the PSP emulator). */
    PSPTRACEEVTSEVERITY_DEBUG,
    /** General information. */
    PSPTRACEEVTSEVERITY_INFO,
    /** Warning related to the emulation. */
    PSPTRACEEVTSEVERITY_WARNING,
    /** Error related to the emulation. */
    PSPTRACEEVTSEVERITY_ERROR,
    /** Fatal error related to the emulation which impacts the emulation result. */
    PSPTRACEEVTSEVERITY_FATAL_ERROR,
    /** 32bit hack. */
    PSPTRACEEVTSEVERITY_32BIT_HACK = 0x7fffffff
} PSPTRACEEVTSEVERITY;


/**
 * Trace event origin.
 */
typedef enum PSPTRACEEVTORIGIN
{
    /** Invalid origin, do not use. */
    PSPTRACEEVTORIGIN_INVALID,
    /** PSP MMIO access related. */
    PSPTRACEEVTORIGIN_MMIO,
    /** PSP SMN access related. */
    PSPTRACEEVTORIGIN_SMN,
    /** PSP X86 access related (not specified wether MMIO or memory. */
    PSPTRACEEVTORIGIN_X86,
    /** PSP X86 MMIO access related. */
    PSPTRACEEVTORIGIN_X86_MMIO,
    /** PSP X86 memory access related. */
    PSPTRACEEVTORIGIN_X86_MEM,
    /** Syscall emulation related. */
    PSPTRACEEVTORIGIN_SVC,
    /** SMC emulation related. */
    PSPTRACEEVTORIGIN_SMC,
    /** Cryptographic Co-processor related. */
    PSPTRACEEVTORIGIN_CCP,
    /** Status device related. */
    PSPTRACEEVTORIGIN_STS,
    /** ACPI device related. */
    PSPTRACEEVTORIGIN_ACPI,
    /** GPIO device related. */
    PSPTRACEEVTORIGIN_GPIO,
    /** IOMUX device related. */
    PSPTRACEEVTORIGIN_IOMUX,
    /** RTC device related. */
    PSPTRACEEVTORIGIN_RTC,
    /** LPC device related. */
    PSPTRACEEVTORIGIN_LPC,
    /** x86 UART related. */
    PSPTRACEEVTORIGIN_X86_UART,
    /** PSP proxy related. */
    PSPTRACEEVTORIGIN_PROXY,
    /** Debugger related. */
    PSPTRACEEVTORIGIN_DBG,
    /** PSP core related. */
    PSPTRACEEVTORIGIN_CORE,
    /** Interrupt controller related. */
    PSPTRACEEVTORIGIN_IRQ,
    /** Last valid origin. */
    PSPTRACEEVTORIGIN_LAST = PSPTRACEEVTORIGIN_CORE,
    /** 32bit hack. */
    PSPTRACEEVTORIGIN_32BIT_HACK = 0x7fffffff
} PSPTRACEEVTORIGIN;


/** Include timestamps in the resulting logs (might not be supported on all hosts and will be ignored). */
#define PSPEMU_TRACE_F_TIMESTAMPS      BIT(0)
/** Dumps the complete PSP core state for each event (otherwise only the triggering PC is logged). */
#define PSPEMU_TRACE_F_FULL_CORE_CTX   BIT(1)
/** Enable all events by default. */
#define PSPEMU_TRACE_F_ALL_EVENTS      BIT(2)
/** Default flags (no timestamps and no full context, all events enabled). */
#define PSPEMU_TRACE_F_DEFAULT         (PSPEMU_TRACE_F_ALL_EVENTS)


/** Trace log flush handler. */
typedef int (FNPSPTRACEFLUSH)(PSPTRACE hTrace, void *pvBuf, size_t cbBuf, void *pvUser);
/** Trace log flush handler pointer. */
typedef FNPSPTRACEFLUSH *PFNPSPTRACEFLUSH;

/**
 * Creates a new tracer instance.
 *
 * @returns Status code.
 * @param   phTrace                 Where to store the tracer handle on success.
 * @param   fFlags                  Flags controlling the behavior, see PSPEMU_TRACE_F_XXX.
 * @param   hPspCore                PSP core handle to dump the state from if configured.
 * @param   cEvtsBuffer             Number of events to buffer before flushing to the log, 0 disables any buffering.
 * @param   pfnFlush                The flush callback to call when writing log data.
 * @param   pvUser                  Opauqe user data to pass to the flush callback.
 */
int PSPEmuTraceCreate(PPSPTRACE phTrace, uint32_t fFlags, PSPCORE hPspCore,
                      uint32_t cEvtsBuffer, PFNPSPTRACEFLUSH pfnFlush, void *pvUser);

/**
 * Creates a file based trace log.
 *
 * @returns Status code.
 * @param   phTrace                 Where to store the tracer handle on success.
 * @param   fFlags                  Flags controlling the behavior, see PSPEMU_TRACE_F_XXX.
 * @param   hPspCore                PSP core handle to dump the state from if configured.
 * @param   cEvtsBuffer             Number of events to buffer before flushing to the log, 0 disables any buffering.
 * @param   pszFilename             Filename to log to.
 */
int PSPEmuTraceCreateForFile(PPSPTRACE phTrace, uint32_t fFlags, PSPCORE hPspCore,
                             uint32_t cEvtsBuffer, const char *pszFilename);

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
 * COnfigures tracing of the given event origins.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   paEvtOrigins            Array of event origins to configure.
 * @param   paEvtSeverities         Array of severities at which events are logging,
 *                                  PSPTRACEEVTSEVERITY_FATAL_ERROR to log only fatal errors
 *                                  and nothing else (always logged).
 * @param   cEvts                   Number of entries in both arrays.
 */
int PSPEmuTraceEvtEnable(PSPTRACE hTrace, PSPTRACEEVTORIGIN *paEvtOrigins, PSPTRACEEVTSEVERITY *paEvtSeverities, uint32_t cEvts);

/**
 * Adds the given string to the trace.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmSeverity             The severity of the event.
 * @param   enmOrigin               The origin of the event.
 * @param   pszFmt                  The format string to log.
 * @param   hArgs                   Arguments for the format string.
 */
int PSPEmuTraceEvtAddStringV(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                             const char *pszFmt, va_list hArgs);

/**
 * Adds the given string to the trace.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmSeverity             The severity of the event.
 * @param   enmOrigin               The origin of the event.
 * @param   pszFmt                  The format string to log.
 * @param   ...                     Arguments for the format string.
 */
int PSPEmuTraceEvtAddString(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                            const char *pszFmt, ...);

/**
 * Adds the given data transfer event to the trace.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmSeverity             The severity of the event.
 * @param   enmOrigin               The origin of the event.
 * @param   uAddrSrc                The context specific address the transfer started reading from.
 * @param   uAddrDst                The context specific address the transfer started writing to.
 * @param   pvBuf                   The transfered data.
 * @param   cbXfer                  The amount of bytes transfered.
 */
int PSPEmuTraceEvtAddXfer(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                          uint64_t uAddrSrc, uint64_t uAddrDst, const void *pvBuf, size_t cbXfer);

/**
 * Adds a device read event.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmSeverity             The severity of the event.
 * @param   enmOrigin               The origin of the event.
 * @param   pszDevId                The device identifier read from.
 * @param   uAddr                   The context specific device address the read started from.
 * @param   pvData                  The data being read.
 * @param   cbRead                  Number of bytes being read.
 */
int PSPEmuTraceEvtAddDevRead(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                             const char *pszDevId, uint64_t uAddr, const void *pvData, size_t cbRead);

/**
 * Adds a device write event.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmSeverity             The severity of the event.
 * @param   enmOrigin               The origin of the event.
 * @param   pszDevId                The device identifier written to.
 * @param   uAddr                   The context specific device address the write started at.
 * @param   pvData                  The data being written.
 * @param   cbWritten               Number of bytes being written.
 */
int PSPEmuTraceEvtAddDevWrite(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                              const char *pszDevId, uint64_t uAddr, const void *pvData, size_t cbWrite);

/**
 * Adds svc event.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmSeverity             The severity of the event.
 * @param   enmOrigin               The origin of the event.
 * @param   idxSvc                  The SVC number being executed.
 * @param   fEntry                  Flag whether this SVC entry or return.
 * @param   pszMsg                  Additional message to log.
 */
int PSPEmuTraceEvtAddSvc(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                         uint32_t idxSvc, bool fEntry, const char *pszMsg);

/**
 * Adds smc event.
 *
 * @returns Status code.
 * @param   hTrace                  The trace handle, NULL means default.
 * @param   enmSeverity             The severity of the event.
 * @param   enmOrigin               The origin of the event.
 * @param   idxSmc                  The SMC number being executed.
 * @param   fEntry                  Flag whether this SVC entry or return.
 * @param   pszMsg                  Additional message to log.
 */
int PSPEmuTraceEvtAddSmc(PSPTRACE hTrace, PSPTRACEEVTSEVERITY enmSeverity, PSPTRACEEVTORIGIN enmEvtOrigin,
                         uint32_t idxSmc, bool fEntry, const char *pszMsg);

#endif /* __psp_trace_h */
