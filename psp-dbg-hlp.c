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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <common/status.h>

#include <psp-dbg-hlp.h>


/**
 * Comand descriptor record.
 */
typedef struct PSPDBGHLPCMDREC
{
    /** Pointer to the next record. */
    struct PSPDBGHLPCMDREC      *pNext;
    /** Pointer to the array of registered commands. */
    PCDBGHLPCMD                 paCmds;
    /** Number of commands in the array. */
    uint32_t                    cCmds;
    /** Opaque user data for the commands. */
    void                        *pvUser;
} PSPDBGHLPCMDREC;
/** Pointer to a command descriptor record. */
typedef PSPDBGHLPCMDREC *PPSPDBGHLPCMDREC;
/** Pointer to a const command descriptor record. */
typedef const PSPDBGHLPCMDREC *PCPSPDBGHLPCMDREC;


/**
 * The debug helper module instance data.
 */
typedef struct PSPDBGHLPINT
{
    /** Reference count. */
    volatile uint32_t           cRefs;
    /** Head to the list of registered commands. */
    PPSPDBGHLPCMDREC            pCmdsHead;
} PSPDBGHLPINT;
/** Pointer to the tracer instance data. */
typedef PSPDBGHLPINT *PPSPDBGHLPINT;
/** Pointer to a const tracer instance. */
typedef const PSPDBGHLPINT *PCPSPDBGHLPINT;


/**
 * Destroys the given debug helper module instance.
 *
 * @returns nothing.
 * @param   pThis                   The debug helper module instance.
 */
static void pspEmuDbgHlpDestroy(PPSPDBGHLPINT pThis)
{
    while (pThis->pCmdsHead)
    {
        PPSPDBGHLPCMDREC pCmdRec = pThis->pCmdsHead;
        pThis->pCmdsHead = pCmdRec->pNext;
        free(pCmdRec);
    }
    free(pThis);
}


/**
 * Tries to find the given command in the set of registered commands and returns the
 * descriptor or NULL if not found.
 *
 * @returns Pointer to the command descriptor or NULL if not found.
 * @param   pThis                   The debug helper module instance.
 * @param   pszCmd                  The command to look for.
 * @param   ppvUser                 Where to store the opaque user data the command was registered with if found, optional.
 */
static PCDBGHLPCMD pspEmuDbgHlpCmdFind(PPSPDBGHLPINT pThis, const char *pszCmd, void **ppvUser)
{
    PPSPDBGHLPCMDREC pCmdRecCur = pThis->pCmdsHead;
    while (pCmdRecCur)
    {
        for (uint32_t i = 0; i < pCmdRecCur->cCmds; i++)
        {
            if (!strcmp(pCmdRecCur->paCmds[i].pszCmd, pszCmd))
            {
                if (ppvUser)
                    *ppvUser = pCmdRecCur->pvUser;
                return &pCmdRecCur->paCmds[i];
            }
        }

        pCmdRecCur = pCmdRecCur->pNext;
    }

    return NULL; /* Nothing found. */
}


int PSPEmuDbgHlpCreate(PPSPDBGHLP phDbgHlp)
{
    int rc = STS_INF_SUCCESS;
    PPSPDBGHLPINT pThis = (PPSPDBGHLPINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->cRefs     = 1;
        pThis->pCmdsHead = NULL;
        *phDbgHlp = pThis;
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


uint32_t PSPEmuDbgHlpRetain(PSPDBGHLP hDbgHlp)
{
    PPSPDBGHLPINT pThis = hDbgHlp;

    return ++pThis->cRefs; /** @todo Atomics when going multi threaded. */
}


uint32_t PSPEmuDbgHlpRelease(PSPDBGHLP hDbgHlp)
{
    PPSPDBGHLPINT pThis = hDbgHlp;

    uint32_t cRefs = --pThis->cRefs; /** @todo Atomics when going multi threaded. */
    if (!cRefs)
        pspEmuDbgHlpDestroy(pThis);

    return cRefs;
}


int PSPEmuDbgHlpCmdRegister(PSPDBGHLP hDbgHlp, PCDBGHLPCMD paCmds, uint32_t cCmds, void *pvUser)
{
    PPSPDBGHLPINT pThis = hDbgHlp;

    /* Check that there is no command existing with the same name already. */
    for (uint32_t i = 0; i < cCmds; i++)
    {
        if (pspEmuDbgHlpCmdFind(pThis, paCmds[i].pszCmd, NULL /*ppvUser*/) != NULL)
            return STS_ERR_INVALID_PARAMETER; /** @todo New status code. */
    }

    int rc = STS_INF_SUCCESS;
    PPSPDBGHLPCMDREC pCmdRec = (PPSPDBGHLPCMDREC)calloc(1, sizeof(*pCmdRec));
    if (pCmdRec)
    {
        pCmdRec->paCmds = paCmds;
        pCmdRec->cCmds  = cCmds;
        pCmdRec->pvUser = pvUser;
        pCmdRec->pNext  = pThis->pCmdsHead;
        pThis->pCmdsHead = pCmdRec;
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


int PSPEmuDbgHlpCmdDeregister(PSPDBGHLP hDbgHlp, PCDBGHLPCMD paCmds)
{
    return STS_ERR_GENERAL_ERROR; /** @todo */
}


int PSPEmuDbgHlpCmdExec(PSPDBGHLP hDbgHlp, const char *pszCmd, const char *pszArgs, PCPSPDBGOUTHLP pOutHlp)
{
    PPSPDBGHLPINT pThis = hDbgHlp;
    void *pvCmdUser = NULL;
    PCDBGHLPCMD pCmd = pspEmuDbgHlpCmdFind(pThis, pszCmd, &pvCmdUser);
    int rc = STS_ERR_NOT_FOUND;
    if (pCmd)
        rc = pCmd->pfnCmd(pThis, pOutHlp, pszArgs, pvCmdUser);

    return rc;
}

