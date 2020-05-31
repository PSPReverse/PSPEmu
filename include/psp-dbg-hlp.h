/** @file
 * PSP Emulator - Debug helper API.
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
#ifndef INCLUDED_psp_dbg_hlp_h
#define INCLUDED_psp_dbg_hlp_h

#include <common/types.h>
#include <common/cdefs.h>


/** Opaque PSP Debug helper handle. */
typedef struct PSPDBGHLPINT *PSPDBGHLP;
/** Pointer to a PSP Debug helper handle. */
typedef PSPDBGHLP *PPSPDBGHLP;


/** Forward decleration of a const debugger output helper structure. */
typedef const struct PSPDBGOUTHLP *PCPSPDBGOUTHLP;

/**
 * Debugger output helper callback table.
 */
typedef struct PSPDBGOUTHLP
{

    /**
     * Print formatted string.
     *
     * @returns Status code.
     * @param   pHlp                Pointer to this structure.
     * @param   pszFmt              The format string.
     * @param   ...                 Variable number of arguments depending on the format string.
     */
    int (*pfnPrintf) (PCPSPDBGOUTHLP pHlp, const char *pszFmt, ...);

} PSPDBGOUTHLP;


/**
 * Custom command descriptor.
 */
typedef struct DBGHLPCMD
{
    /** Command name. */
    const char                  *pszCmd;
    /** Command description, optional. */
    const char                  *pszDesc;

    /**
     * Command callback.
     *
     * @returns Status code.
     * @param   hDbgHlp             The debug helper handle this command was registered invoked from.
     * @param   pHlp                Pointer to output formatting helpers.
     * @param   pszArgs             Command arguments.
     * @param   pvUser              Opaque user data passed during stub context creation.
     */
    int (*pfnCmd) (PSPDBGHLP hDbgHlp, PCPSPDBGOUTHLP pHlp, const char *pszArgs, void *pvUser);
} DBGHLPCMD;
/** Pointer to a custom command descriptor. */
typedef DBGHLPCMD *PDBGHLPCMD;
/** Pointer to a const custom command descriptor. */
typedef const DBGHLPCMD *PCDBGHLPCMD;


/**
 * Creates a new debug helper module.
 *
 * @returns Status code.
 * @param   phDbgHlp                Where to store the debug helper handle on success.
 */
int PSPEmuDbgHlpCreate(PPSPDBGHLP phDbgHlp);


/**
 * Retains a reference to the given debug helper module.
 *
 * @returns New reference count.
 * @param   hDbgHlp                 The debug helper module handle.
 */
uint32_t PSPEmuDbgHlpRetain(PSPDBGHLP hDbgHlp);


/**
 * Releases a reference to the given debug helper module.
 *
 * @returns New reference count - 0 if the debug helper module was destroyed.
 * @param   hDbgHlp                 The debug helper module handle.
 */
uint32_t PSPEmuDbgHlpRelease(PSPDBGHLP hDbgHlp);


/**
 * Registers a the given set of commands with the debug helper module.
 *
 * @returns Status code.
 * @param   hDbgHlp                 The debug helper module handle - if NULL the call returns success without doing anything
 *                                  (to avoid if mazes if there is no debug helper existing).
 * @param   paCmds                  Array of command descriptors to register.
 * @param   cCmds                   Number of commands in the array.
 * @param   pvUser                  Opaque user data passed to the registered commands on invocation.
 */
int PSPEmuDbgHlpCmdRegister(PSPDBGHLP hDbgHlp, PCDBGHLPCMD paCmds, uint32_t cCmds, void *pvUser);


/**
 * Deregisters a the given set of commands from the debug helper module.
 *
 * @returns Status code.
 * @param   hDbgHlp                 The debug helper module handle.
 * @param   paCmds                  Array of command descriptors to to deregister.
 */
int PSPEmuDbgHlpCmdDeregister(PSPDBGHLP hDbgHlp, PCDBGHLPCMD paCmds);


/**
 * Calls the given command with the given set of arguments.
 *
 * @returns Status code.
 * @param   hDbgHlp                 The debug helper module handle.
 * @param   pszCmd                  The command to call.
 * @param   pszArgs                 Arguments given as a single string.
 * @param   pOutHlp                 The output helper to use.
 */
int PSPEmuDbgHlpCmdExec(PSPDBGHLP hDbgHlp, const char *pszCmd, const char *pszArgs, PCPSPDBGOUTHLP pOutHlp);

#endif /* !INCLUDED_psp_dbg_hlp_h */
