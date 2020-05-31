/** @file
 * PSP Emulator - Core API (interfacing with unicorn engine).
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <poll.h>
#include <sys/ioctl.h>

#include <libgdbstub.h>

#include <common/types.h>
#include <common/cdefs.h>
#include <common/status.h>

#include <psp-dbg.h>
#include <psp-cov.h>
#include <psp-trace.h>


/** Pointer to the debugger instance data. */
typedef struct PSPDBGINT *PPSPDBGINT;


/**
 * A coverage tracer instance.
 */
typedef struct PSPDBGCOV
{
    /** Next coverage tracer in the list. */
    struct PSPDBGCOV        *pNext;
    /** Coverage tracer ID. */
    uint32_t                idCov;
    /** The coverage tracer instance handle. */
    PSPCOV                  hCov;
} PSPDBGCOV;
/** Pointer to to a coverage tracer instance. */
typedef PSPDBGCOV *PPSPDBGCOV;


/**
 * A single tracepoint.
 */
typedef struct PSPDBGTP
{
    /** Next tracepoint in the list. */
    struct PSPDBGTP         *pNext;
    /** Pointer to the owning debugger instance. */
    PPSPDBGINT              pDbg;
    /** The tracepoint ID. */
    uint32_t                idTp;
    /** Number of times the trace point hit already. */
    uint32_t                cHits;
    /** Number of time the trace point should hit until it is delete. */
    uint32_t                cHitsMax;
    /** Flag whether this is "normal" or I/O trace point. */
    bool                    fIoTp;
    /** Type dependent data. */
    union
    {
        /** The tracepoint address. */
        PSPADDR             PspAddrTp;
        /** The IOM tracepoint handle. */
        PSPIOMTP            hIoTp;
    } u;
} PSPDBGTP;
/** Pointer to a tracepoint. */
typedef PSPDBGTP *PPSPDBGTP;
/** Pointer to a const tracepoint. */
typedef const PSPDBGTP *PCPSPDBGTP;


/**
 * PSP debugger instance data.
 */
typedef struct PSPDBGINT
{
    /** The GDB stub context for the debugger instance. */
    GDBSTUBCTX              hGdbStubCtx;
    /** The listening socket. */
    int                     iFdListening;
    /** The socket for the current GDB connection. */
    int                     iFdGdbCon;
    /** Flag whether the core is currently running. */
    bool                    fCoreRunning;
    /** Flag whether we are currently singel stepping (to avoid triggering breakpoints). */
    bool                    fSingleStep;
    /** Flags given to PSPEmuCoreExecRun(). */
    uint32_t                fCoreExecRun;
    /** Head of tracepoint list. */
    PPSPDBGTP               pTpsHead;
    /** List of active coverage tracers. */
    PPSPDBGCOV              pCovHead;
    /** Next tracepoint ID. */
    uint32_t                idTpNext;
    /** Next coverage trace ID. */
    uint32_t                idCovNext;
    /** Execute for the first time until this particular instruction is hit and
     * then wait for a debugger to connect. */
    PSPADDR                 PspAddrRunUpTo;
    /** Number of instructions to step when the code is running. */
    uint32_t                cInsnsStep;
    /** Number of CCDs in the array below. */
    uint32_t                cCcds;
    /** Currently selected CCD. */
    uint32_t                idxCcd;
    /** Array of CCDs assigned to this debugger - variable in syize. */
    PSPCCD                  ahCcds[1];
} PSPDBGINT;


/**
 * GDB stub ARM register names.
 */
static const GDBSTUBREG g_apszPspDbgGdbStubRegs[] =
{
    { "r0",   32, GDBSTUBREGTYPE_GP        },
    { "r1",   32, GDBSTUBREGTYPE_GP        },
    { "r2",   32, GDBSTUBREGTYPE_GP        },
    { "r3",   32, GDBSTUBREGTYPE_GP        },
    { "r4",   32, GDBSTUBREGTYPE_GP        },
    { "r5",   32, GDBSTUBREGTYPE_GP        },
    { "r6",   32, GDBSTUBREGTYPE_GP        },
    { "r7",   32, GDBSTUBREGTYPE_GP        },
    { "r8",   32, GDBSTUBREGTYPE_GP        },
    { "r9",   32, GDBSTUBREGTYPE_GP        },
    { "r10",  32, GDBSTUBREGTYPE_GP        },
    { "r11",  32, GDBSTUBREGTYPE_GP        },
    { "r12",  32, GDBSTUBREGTYPE_GP        },
    { "sp",   32, GDBSTUBREGTYPE_STACK_PTR },
    { "lr",   32, GDBSTUBREGTYPE_CODE_PTR  },
    { "pc",   32, GDBSTUBREGTYPE_PC        },
    { "cpsr", 32, GDBSTUBREGTYPE_STATUS    },
    { "spsr", 32, GDBSTUBREGTYPE_STATUS    },
    { NULL,    0, GDBSTUBREGTYPE_INVALID   }
};


/**
 * Converts a libgdbstub error to our internal status code.
 *
 * @returns Status code.
 * @param   rcGdbStub               The GDB stub status code to convert.
 */
static int pspEmuDbgErrConvertFromGdbStubErr(int rcGdbStub)
{
    if (rcGdbStub == GDBSTUB_INF_SUCCESS)
        return 0;

    printf("rcGdbStub=%d\n", rcGdbStub);
    return -1; /** @todo */
}


/**
 * Converts the given internal status code to the GDB stub library status code.
 *
 * @returns GDB stub status code.
 * @param   rc                      The status code to convert.
 */
static int pspEmuDbgErrConvertToGdbStubErr(int rc)
{
    if (!rc)
        return GDBSTUB_INF_SUCCESS;

    return GDBSTUB_ERR_INVALID_PARAMETER; /** @todo */
}


/**
 * Returns the PSP core instance from the currently selected CCD.
 *
 * @returns Handle to the PSP core.
 * @param   pThis                   The PSP debugger instance.
 */
static PSPCORE pspEmuDbgGetPspCoreFromSelectedCcd(PPSPDBGINT pThis)
{
    PSPCORE hPspCore = NULL;

    int rc = PSPEmuCcdQueryCore(pThis->ahCcds[pThis->idxCcd], &hPspCore);
    /** @todo assert(rc) */
    return hPspCore;
}


/**
 * Returns the PSP CCD instance from the currently selected CCD.
 *
 * @returns Handle to the PSP core.
 * @param   pThis                   The PSP debugger instance.
 */
static PSPCCD pspEmuDbgGetCcdFromSelectedCcd(PPSPDBGINT pThis)
{
    return pThis->ahCcds[pThis->idxCcd];
}


/**
 * Creates a new trace point and links it into the list.
 *
 * @returns Status code.
 * @param   pThis                   The PSP debugger instance.
 * @param   fIoTp                   Flag whether this is a I/O or normal trace point.
 * @param   cHitsMax                Maximum amount of hits until the TP is removed.
 *                                  Use 0 to disable removing the trace point altogether.
 * @param   ppTp                    Where to store the pointer to the created tracepoint on success.
 *
 * @note The trace point is already linked in to the list.
 */
static int pspDbgTpCreate(PPSPDBGINT pThis, bool fIoTp, uint32_t cHitsMax, PPSPDBGTP *ppTp)
{
    int rc = 0;
    PPSPDBGTP pTp = (PPSPDBGTP)calloc(1, sizeof(*pTp));
    if (pTp)
    {
        pTp->pNext    = NULL;
        pTp->pDbg     = pThis;
        pTp->idTp     = pThis->idTpNext++;
        pTp->cHits    = 0;
        pTp->cHitsMax = cHitsMax;
        pTp->fIoTp    = fIoTp;

        /* Link into the list. */
        pTp->pNext = pThis->pTpsHead;
        pThis->pTpsHead = pTp;

        *ppTp = pTp;
    }
    else
        rc = -1;

    return rc;
}


/**
 * Unlinks and destroys the given trace point.
 *
 * @returns nothing.
 * @param   pTp                     The trace point to destroy.
 */
static void pspDbgTpDestroy(PPSPDBGTP pTp)
{
    PPSPDBGINT pThis = pTp->pDbg;

    if (!pTp->fIoTp)
    {
        PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);
        PSPEmuCoreTraceDeregister(hPspCore, pTp->u.PspAddrTp, pTp->u.PspAddrTp);
    }
    else
    {
        /* Deregister the I/O trace point. */
        PSPEmuIoMgrTpDeregister(pTp->u.hIoTp);
    }

    /* Find the tracepoint to remove. */
    PPSPDBGTP pTpPrev = NULL;
    PPSPDBGTP pTpCur = pThis->pTpsHead;
    while (   pTpCur
           && pTpCur != pTp)
    {
        pTpPrev = pTpCur;
        pTpCur = pTpCur->pNext;
    }

    if (pTpCur)
    {
        /* Unlink and free memory. */
        if (pTpPrev)
            pTpPrev->pNext = pTpCur->pNext;
        else
            pThis->pTpsHead = pTpCur->pNext;
    }
    /* else assert() should never happen */

    free(pTp);
}


/**
 * Unlinks and destroys the given trace point.
 *
 * @returns nothing.
 * @param   pThis                   The PSP debugger instance.
 * @param   idTp                    The trace point ID to look for.
 */
static PPSPDBGTP pspDbgTpFindById(PPSPDBGINT pThis, uint32_t idTp)
{
    PPSPDBGTP pTpCur = pThis->pTpsHead;
    while (pTpCur)
    {
        if (pTpCur->idTp == idTp)
            return pTpCur;

        pTpCur = pTpCur->pNext;
    }

    return NULL;
}


/**
 * Handles normal and I/O trace points alike.
 *
 * @returns nothing.
 * @param   hPspCore                The PSP core which hit the trace point.
 * @param   pTp                     The trace point which hit.
 */
static void pspDbgTpHit(PSPCORE hCore, PPSPDBGTP pTp)
{
    PPSPDBGINT pThis = pTp->pDbg;

    pTp->cHits++;

    /* Stop the emulation if not in single stepping mode. */
    if (!pThis->fSingleStep)
    {
        pThis->fCoreRunning = false;
        PSPEmuCoreExecStop(hCore);
    }

    /* Remove the trace point when it reached the hit limit. */
    if (   pTp->cHits >= pTp->cHitsMax
        && pTp->cHitsMax > 0)
        pspDbgTpDestroy(pTp);
}


/**
 * Callback when a tracepoint is hit.
 *
 * @returns Nothing.
 * @param   hCore                   The PSP core handle.
 * @param   uPspAddr                The PSP address where the callback hit.
 * @param   cbInsn                  Instruction size.
 * @param   pvUser                  Opaque user data.
 */
static void pspDbgTpBpHit(PSPCORE hCore, PSPADDR uPspAddr, uint32_t cbInsn, void *pvUser)
{
    PPSPDBGTP pTp = (PPSPDBGTP)pvUser;
    pspDbgTpHit(hCore, pTp);
}


/**
 * Stops the emulation if a I/O trace point is hit.
 *
 * @returns nothing.
 * @param   pThis                   The PSP debugger instance.
 */
static void pspDbgIoTpHit(PPSPDBGTP pTp)
{
    PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pTp->pDbg);
    pspDbgTpHit(hPspCore, pTp);
}


/**
 * Finds a coverage tracer by the given ID.
 *
 * @returns Pointer to the coverage tracer on success or NULL if not found.
 * @param   pThis                   The PSP debugger instance.
 * @param   idCov                   The trace point ID to look for.
 */
static PPSPDBGCOV pspDbgCovFindById(PPSPDBGINT pThis, uint32_t idCov)
{
    PPSPDBGCOV pCovCur = pThis->pCovHead;
    while (pCovCur)
    {
        if (pCovCur->idCov == idCov)
            return pCovCur;

        pCovCur = pCovCur->pNext;
    }

    return NULL;
}


/**
 * Unlinks and destroys the given coverage tracer.
 *
 * @returns nothing.
 * @param   pThis                   The PSP debugger instance.
 * @param   pCov                    The coverage tracer to destroy.
 */
static void pspDbgCovDestroy(PPSPDBGINT pThis, PPSPDBGCOV pCov)
{
    /* Find the coverage to remove. */
    PPSPDBGCOV pCovPrev = NULL;
    PPSPDBGCOV pCovCur = pThis->pCovHead;
    while (   pCovCur
           && pCovCur != pCov)
    {
        pCovPrev = pCovCur;
        pCovCur = pCovCur->pNext;
    }

    if (pCovCur)
    {
        /* Unlink and free memory. */
        if (pCovPrev)
            pCovPrev->pNext = pCovCur->pNext;
        else
            pThis->pCovHead = pCovCur->pNext;
    }
    /* else assert() should never happen */

    free(pCov);
}


/**
 * Converts the given page table walk status to a human readable string.
 *
 * @returns Human readable string.
 * @param   enmPgTblWalk            The page table walk status.
 */
static const char *pspDbgPgTblWalkStsToStr(PSPCOREPGTBLWALKSTS enmPgTblWalk)
{
    switch (enmPgTblWalk)
    {
        case PSPCOREPGTBLWALKSTS_INVALID:
            return "INVALID";
        case PSPCOREPGTBLWALKSTS_NO_MMU:
            return "NO_MMU";
        case PSPCOREPGTBLWALKSTS_L1:
            return "L1";
        case PSPCOREPGTBLWALKSTS_L2:
            return "L2";
    }

    return "<UNKNOWN>";
}


/**
 * @copydoc{FNPSPIOMSMNTRACE}
 */
static void pspDbgIoSmnTpHit(SMNADDR offSmnAbs, const char *pszDevId, SMNADDR offSmnDev, size_t cbAccess,
                             const void *pvVal, uint32_t fFlags, void *pvUser)
{
    PPSPDBGTP pTp = (PPSPDBGTP)pvUser;
    pspDbgIoTpHit(pTp);
}


/**
 * @copydoc{FNPSPIOMMMIOTRACE}
 */
static void pspDbgIoMmioTpHit(PSPADDR offMmioAbs, const char *pszDevId, PSPADDR offMmioDev, size_t cbAccess,
                              const void *pvVal, uint32_t fFlags, void *pvUser)
{
    PPSPDBGTP pTp = (PPSPDBGTP)pvUser;
    pspDbgIoTpHit(pTp);
}


/**
 * @copydoc{FNPSPIOMX86TRACE}
 */
static void pspDbgIoX86TpHit(X86PADDR offX86Abs, const char *pszDevId, X86PADDR offX86Dev, size_t cbAccess,
                             const void *pvVal, uint32_t fFlags, void *pvUser)
{
    PPSPDBGTP pTp = (PPSPDBGTP)pvUser;
    pspDbgIoTpHit(pTp);
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdRestart(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCCD hCcd = pspEmuDbgGetCcdFromSelectedCcd(pThis);

    /** @todo Option to reset all CCDs when support for multiple CCds was added. */
    int rc = PSPEmuCcdReset(hCcd);
    if (!rc)
        pHlp->pfnPrintf(pHlp, "Reset of CCD %u successful\n", pThis->idxCcd);
    else
        pHlp->pfnPrintf(pHlp, "Reset of CCD %u failed with %d\n", pThis->idxCcd, rc);
    return pspEmuDbgErrConvertToGdbStubErr(rc);
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdIoBp(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCCD hCcd = pspEmuDbgGetCcdFromSelectedCcd(pThis);
    PSPIOM hIoMgr = NULL;

    int rc = PSPEmuCcdQueryIoMgr(hCcd, &hIoMgr);
    if (rc)
        return pspEmuDbgErrConvertToGdbStubErr(rc);

    /* Parse all arguments. */
    int rcGdbStub = GDBSTUB_INF_SUCCESS;
    const char *pszAddrType = pszArgs;
    const char *pszAddr     = pszArgs ? strchr(pszAddrType, ' ') : NULL;
    const char *pszSz       = pszAddr ? strchr(pszAddr + 1, ' ') : NULL;
    const char *pszRw       = pszSz   ? strchr(pszSz   + 1, ' ') : NULL;
    const char *pszTime     = pszRw   ? strchr(pszRw   + 1, ' ') : NULL;

    if (   pszAddrType
        && pszAddr
        && pszSz
        && pszRw
        && pszTime)
    {
        /* Get past the space. */
        pszAddr++;
        pszSz++;
        pszRw++;
        pszTime++;

        char *pszAddrEnd = NULL;
        uint64_t u64Addr = strtoull(pszAddr, &pszAddrEnd, 0 /*base*/);
        if (   pszAddrEnd != pszAddr
            && *pszAddrEnd == ' ')
        {
            if (   pszSz[1] == ' '
                && (   pszSz[0] == '0'
                    || pszSz[0] == '1'
                    || pszSz[0] == '2'
                    || pszSz[0] == '4'))
            {
                size_t cbAccess = (size_t)(pszSz[0] - '0');

                if (   (pszRw[0] == 'r' && pszRw[1] == ' ')
                    || (pszRw[0] == 'w' && pszRw[1] == ' ')
                    || (pszRw[0] == 'r' && pszRw[1] == 'w' && pszRw[2] == ' '))
                {
                    uint32_t fFlags = 0;

                    if (pszRw[0] == 'r')
                        fFlags |= PSPEMU_IOM_TRACE_F_READ;
                    if (pszRw[0] == 'w' || pszRw[1] == 'w')
                        fFlags |= PSPEMU_IOM_TRACE_F_WRITE;

                    if (!strcmp(pszTime, "before"))
                        fFlags |= PSPEMU_IOM_TRACE_F_BEFORE;
                    else if (!strcmp(pszTime, "after"))
                        fFlags |= PSPEMU_IOM_TRACE_F_AFTER;
                    else
                        rcGdbStub = GDBSTUB_ERR_INVALID_PARAMETER;

                    if (rcGdbStub == GDBSTUB_INF_SUCCESS)
                    {
                        PPSPDBGTP pIoTp = NULL;

                        int rc = pspDbgTpCreate(pThis, true /*fIoTp*/, 0 /*cHitsMax*/, &pIoTp);
                        if (!rc)
                        {
                            if (pszAddrType[0] == 's' && pszAddrType[1] == 'm' && pszAddrType[2] == 'n' && pszAddrType[3] == ' ')
                            {
                                rc = PSPEmuIoMgrSmnTraceRegister(hIoMgr, (SMNADDR)u64Addr, (SMNADDR)u64Addr, cbAccess,
                                                                 fFlags, pspDbgIoSmnTpHit, pIoTp, &pIoTp->u.hIoTp);
                                rcGdbStub = pspEmuDbgErrConvertToGdbStubErr(rc);
                            }
                            else if (pszAddrType[0] == 'm' && pszAddrType[1] == 'm' && pszAddrType[2] == 'i' && pszAddrType[3] == 'o' && pszAddrType[4] == ' ')
                            {
                                rc = PSPEmuIoMgrMmioTraceRegister(hIoMgr, (PSPADDR)u64Addr, (PSPADDR)u64Addr, cbAccess,
                                                                  fFlags, pspDbgIoMmioTpHit, pIoTp, &pIoTp->u.hIoTp);
                                rcGdbStub = pspEmuDbgErrConvertToGdbStubErr(rc);
                            }
                            else if (pszAddrType[0] == 'x' && pszAddrType[1] == '8' && pszAddrType[2] == '6' && pszAddrType[3] == ' ')
                            {
                                rc = PSPEmuIoMgrX86TraceRegister(hIoMgr, (X86PADDR)u64Addr, (X86PADDR)u64Addr, cbAccess,
                                                                 fFlags, pspDbgIoX86TpHit, pIoTp, &pIoTp->u.hIoTp);
                                rcGdbStub = pspEmuDbgErrConvertToGdbStubErr(rc);
                            }
                            else
                                rcGdbStub = GDBSTUB_ERR_INVALID_PARAMETER;

                            if (rcGdbStub == GDBSTUB_INF_SUCCESS)
                                pHlp->pfnPrintf(pHlp, "I/O trace point with ID %u created successfully\n", pIoTp->idTp);
                            else
                            {
                                /* Destroy trace point again as the lower registration failed. */
                                pspDbgTpDestroy(pIoTp);
                            }
                        }
                    }
                }
                else
                    rcGdbStub = GDBSTUB_ERR_INVALID_PARAMETER;
            }
            else
                rcGdbStub = GDBSTUB_ERR_INVALID_PARAMETER;
        }
        else
            rcGdbStub = GDBSTUB_ERR_INVALID_PARAMETER;
    }
    else
        rcGdbStub = GDBSTUB_ERR_INVALID_PARAMETER;

    return rcGdbStub;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdIoBpDel(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    /* Parse all arguments. */
    int rcGdbStub = GDBSTUB_INF_SUCCESS;
    char *pszArgsEnd = NULL;
    uint32_t idTp = strtoul(pszArgs, &pszArgsEnd, 10);
    if (   pszArgsEnd
        && *pszArgsEnd == '\0')
    {
        PPSPDBGTP pIoTp = pspDbgTpFindById(pThis, idTp);
        if (   pIoTp
            && pIoTp->fIoTp)
        {
            int rc = PSPEmuIoMgrTpDeregister(pIoTp->u.hIoTp);
            if (!rc)
                pspDbgTpDestroy(pIoTp);
            else
                pHlp->pfnPrintf(pHlp, "Trace point with id %u couldn't get deregistered from the underlying I/O manager which is really weird\n",
                                idTp);
        }
        else
            pHlp->pfnPrintf(pHlp, "Trace point with id %u doesn't exist or is not an I/O tracepoint."
                                  " Use the standard GDB delete command for normal breakpoints to prevent GDB from getting out of sync\n",
                            idTp);
    }
    else
        pHlp->pfnPrintf(pHlp, "Invalid argument %s given\n", pszArgs);

    return rcGdbStub;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdIoSetPc(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    /* Parse all arguments. */
    int rcGdbStub = GDBSTUB_INF_SUCCESS;
    char *pszArgsEnd = NULL;
    uint32_t uPc = strtoul(pszArgs, &pszArgsEnd, 0);
    if (   pszArgsEnd
        && *pszArgsEnd == '\0')
    {
        PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);
        int rc = PSPEmuCoreExecSetStartAddr(hPspCore, uPc);
        if (rc)
            pHlp->pfnPrintf(pHlp, "Failed to set %#x as the new PC\n", uPc);
        else
            pHlp->pfnPrintf(pHlp, "Set %#x as the new PC\n", uPc);
    }
    else
        pHlp->pfnPrintf(pHlp, "Invalid argument %s given\n", pszArgs);

    return rcGdbStub;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdCovTrace(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCCD  hCcd = pspEmuDbgGetCcdFromSelectedCcd(pThis);
    PSPCORE hPspCore = NULL;

    int rc = PSPEmuCcdQueryCore(hCcd, &hPspCore);
    if (rc)
        return pspEmuDbgErrConvertToGdbStubErr(rc);

    /* Parse all arguments. */
    const char *pszAddrBegin = pszArgs;
    const char *pszAddrEnd   = pszAddrBegin ? strchr(pszAddrBegin + 1, ' ') : NULL;
    if (   pszAddrBegin
        && pszAddrEnd)
    {
        pszAddrEnd++; /* Get past the space. */

        char *pszTmp = NULL;
        PSPADDR PspAddrBegin = strtoul(pszAddrBegin, &pszTmp, 0 /*base*/);
        if (   pszTmp != pszAddrBegin
            && *pszTmp == ' ')
        {
            PSPADDR PspAddrEnd = strtoul(pszAddrEnd, &pszTmp, 0 /*base*/);
            if (   pszTmp != pszAddrBegin
                && *pszTmp == '\0')
            {
                PPSPDBGCOV pCov = (PPSPDBGCOV)calloc(1, sizeof(*pCov));
                if (pCov)
                {
                    rc = PSPEmuCovCreate(&pCov->hCov, hPspCore, PspAddrBegin, PspAddrEnd);
                    if (!rc)
                    {
                        pCov->idCov = pThis->idCovNext++;
                        pCov->pNext = pThis->pCovHead;
                        pThis->pCovHead = pCov;
                        pHlp->pfnPrintf(pHlp, "Cover tracer with ID %u created succcessfully\n", pCov->idCov);
                    }
                    else
                        pHlp->pfnPrintf(pHlp, "Creating the coverage trace failed with %d\n", rc);
                }
                else
                    pHlp->pfnPrintf(pHlp, "Out of memory allocating coverage tracer tracking structure\n");
            }
            else
                pHlp->pfnPrintf(pHlp, "Invalid characters in end address detected: \"%s\"\n", pszArgs);
        }
        else
            pHlp->pfnPrintf(pHlp, "Invalid characters in start address detected: \"%s\"\n", pszArgs);
    }
    else
        pHlp->pfnPrintf(pHlp, "Command requires exactly two arguments: \"%s\"\n", pszArgs);

    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdCovTraceDump(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    /* Parse all arguments. */
    const char *pszId = pszArgs;
    const char *pszFilename = pszId ? strchr(pszId + 1, ' ') : NULL;
    if (   pszId
        && pszFilename)
    {
        pszFilename++; /* Get past the space. */

        char *pszTmp = NULL;
        uint32_t idCov = strtoul(pszId, &pszTmp, 10);
        PPSPDBGCOV pCov = pspDbgCovFindById(pThis, idCov);
        if (pCov)
        {
            int rc = PSPEmuCovDumpToFile(pCov->hCov, pszFilename);
            if (!rc)
                pHlp->pfnPrintf(pHlp, "Coverage trace dumped to file \"%s\"\n", pszFilename);
            else
                pHlp->pfnPrintf(pHlp, "Dumping coverage trace to file \"%s\" failed with %d\n", pszFilename, rc);
        }
        else
            pHlp->pfnPrintf(pHlp, "Coverage tracer with ID %u not found\n", idCov);
    }
    else
        pHlp->pfnPrintf(pHlp, "Command requires exactly two arguments: \"%s\"\n", pszArgs);

    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdCovTraceDel(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    /* Parse all arguments. */
    const char *pszId = pszArgs;
    if (pszId)
    {
        char *pszTmp = NULL;
        uint32_t idCov = strtoul(pszId, &pszTmp, 10);
        if (   pszId != pszTmp
            && *pszTmp == '\0')
        {
            PPSPDBGCOV pCov = pspDbgCovFindById(pThis, idCov);
            if (pCov)
            {
                pspDbgCovDestroy(pThis, pCov);
                pHlp->pfnPrintf(pHlp, "Coverage tracer with ID %u destroyed successfully\n", idCov);
            }
            else
                pHlp->pfnPrintf(pHlp, "Coverage tracer with ID %u not found\n", idCov);
        }
        else
            pHlp->pfnPrintf(pHlp, "Coverage trace ID contains invalid characters: \"%s\"\n", pszId);
    }
    else
        pHlp->pfnPrintf(pHlp, "Command requires exactly one argument: \"%s\"\n", pszArgs);

    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdQueryPAddrFromVAddr(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCCD  hCcd = pspEmuDbgGetCcdFromSelectedCcd(pThis);
    PSPCORE hPspCore = NULL;

    int rc = PSPEmuCcdQueryCore(hCcd, &hPspCore);
    if (rc)
        return pspEmuDbgErrConvertToGdbStubErr(rc);

    /* Parse all arguments. */
    const char *pszVa = pszArgs;
    if (pszVa)
    {
        char *pszTmp = NULL;
        PSPVADDR PspVAddr = strtoul(pszVa, &pszTmp, 0);
        if (   pszVa != pszTmp
            && *pszTmp == '\0')
        {
            PSPPADDR PspPAddr = 0;
            PSPCOREPGTBLWALKSTS enmPgTblWalk = PSPCOREPGTBLWALKSTS_INVALID;
            rc = PSPEmuCoreQueryPAddrFromVAddr(hPspCore, PspVAddr, &PspPAddr, &enmPgTblWalk);
            if (STS_SUCCESS(rc))
            {
                pHlp->pfnPrintf(pHlp, "VA[%#x] -> PA[%#x] (%s)\n", PspVAddr, PspPAddr, pspDbgPgTblWalkStsToStr(enmPgTblWalk));
            }
            else
                pHlp->pfnPrintf(pHlp, "Virtual address couldn't be resolved (%d)\n", rc);
        }
        else
            pHlp->pfnPrintf(pHlp, "Virtual address must be numeric: \"%s\"\n", pszVa);
    }
    else
        pHlp->pfnPrintf(pHlp, "Command requires exactly one argument: \"%s\"\n", pszArgs);

    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdTraceMarker(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    int rc = PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_DBG,
                                     "%s", pszArgs);
    if (STS_FAILURE(rc))
        pHlp->pfnPrintf(pHlp, "Adding trace marker failed with %d\n", rc);
    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdDumpCoreState(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCCD  hCcd = pspEmuDbgGetCcdFromSelectedCcd(pThis);
    PSPCORE hPspCore = NULL;

    int rc = PSPEmuCcdQueryCore(hCcd, &hPspCore);
    if (rc)
        return pspEmuDbgErrConvertToGdbStubErr(rc);

    PSPEmuCoreStateDump(hPspCore, PSPEMU_CORE_STATE_DUMP_F_DEFAULT, 0 /*cInsns*/);
    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdDumpX86MapSlotState(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCCD  hCcd = pspEmuDbgGetCcdFromSelectedCcd(pThis);
    PSPIOM hIoMgr = NULL;

    int rc = PSPEmuCcdQueryIoMgr(hCcd, &hIoMgr);
    if (rc)
        return pspEmuDbgErrConvertToGdbStubErr(rc);

    /* Parse all arguments. */
    const char *pszIdxBegin = pszArgs;
    const char *pszIdxEnd   = pszIdxBegin ? strchr(pszIdxBegin + 1, ' ') : NULL;
    if (   pszIdxBegin
        && pszIdxEnd)
    {
        pszIdxEnd++; /* Get past the space. */

        char *pszTmp = NULL;
        uint32_t idxBegin = strtoul(pszIdxBegin, &pszTmp, 0 /*base*/);
        if (   pszTmp != pszIdxBegin
            && *pszTmp == ' ')
        {
            uint32_t idxEnd = strtoul(pszIdxEnd, &pszTmp, 0 /*base*/);
            if (   pszTmp != pszIdxEnd
                && *pszTmp == '\0')
                PSPEmuIoMgrX86MapSlotDump(hIoMgr, idxBegin, idxEnd);
            else
                pHlp->pfnPrintf(pHlp, "Invalid characters in end index detected: \"%s\"\n", pszArgs);
        }
        else
            pHlp->pfnPrintf(pHlp, "Invalid characters in start index detected: \"%s\"\n", pszArgs);
    }
    else
        pHlp->pfnPrintf(pHlp, "Command requires exactly two arguments: \"%s\"\n", pszArgs);

    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdDumpSmnMapSlotState(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCCD  hCcd = pspEmuDbgGetCcdFromSelectedCcd(pThis);
    PSPIOM hIoMgr = NULL;

    int rc = PSPEmuCcdQueryIoMgr(hCcd, &hIoMgr);
    if (rc)
        return pspEmuDbgErrConvertToGdbStubErr(rc);

    /* Parse all arguments. */
    const char *pszIdxBegin = pszArgs;
    const char *pszIdxEnd   = pszIdxBegin ? strchr(pszIdxBegin + 1, ' ') : NULL;
    if (   pszIdxBegin
        && pszIdxEnd)
    {
        pszIdxEnd++; /* Get past the space. */

        char *pszTmp = NULL;
        uint32_t idxBegin = strtoul(pszIdxBegin, &pszTmp, 0 /*base*/);
        if (   pszTmp != pszIdxBegin
            && *pszTmp == ' ')
        {
            uint32_t idxEnd = strtoul(pszIdxEnd, &pszTmp, 0 /*base*/);
            if (   pszTmp != pszIdxEnd
                && *pszTmp == '\0')
                PSPEmuIoMgrSmnMapSlotDump(hIoMgr, idxBegin, idxEnd);
            else
                pHlp->pfnPrintf(pHlp, "Invalid characters in end index detected: \"%s\"\n", pszArgs);
        }
        else
            pHlp->pfnPrintf(pHlp, "Invalid characters in start index detected: \"%s\"\n", pszArgs);
    }
    else
        pHlp->pfnPrintf(pHlp, "Command requires exactly two arguments: \"%s\"\n", pszArgs);

    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdSingleStep(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    /* Parse all arguments. */
    if (pszArgs)
    {
        if (!strcmp(pszArgs, "on"))
            pThis->fCoreExecRun |= PSPEMU_CORE_EXEC_F_DUMP_CORE_STATE;
        else if (!strcmp(pszArgs, "off"))
            pThis->fCoreExecRun &= ~PSPEMU_CORE_EXEC_F_DUMP_CORE_STATE;
        else
            pHlp->pfnPrintf(pHlp, "Argument must be either \"on\" or \"off\", given:\n", pszArgs);
    }
    else
        pHlp->pfnPrintf(pHlp, "Command requires exactly one argument: \"%s\"\n", pszArgs);

    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 */
static int gdbStubCmdInsnStepCnt(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    /* Parse all arguments. */
    const char *pszCnt = pszArgs;
    if (pszCnt)
    {
        char *pszTmp = NULL;
        uint32_t cCnt = strtoul(pszCnt, &pszTmp, 10);
        if (   pszCnt != pszTmp
            && *pszTmp == '\0')
            pThis->cInsnsStep = cCnt;
        else
            pHlp->pfnPrintf(pHlp, "Step count must be numeric: \"%s\"\n", pszCnt);
    }
    else
        pHlp->pfnPrintf(pHlp, "Command requires exactly one argument: \"%s\"\n", pszArgs);

    return GDBSTUB_INF_SUCCESS;
}


static int gdbStubCmdHelp(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser);

/**
 * Custom commands descriptors.
 */
static const GDBSTUBCMD g_aGdbCmds[] =
{
    { "help",         "This help text",                                                                                  gdbStubCmdHelp                 },
    { "restart",      "Restarts the whole emulation",                                                                    gdbStubCmdRestart              },
    { "reset",        "Restarts the whole emulation",                                                                    gdbStubCmdRestart              }, /* Alias for restart */
    { "iobp",         "Sets an I/O breakpoint, arguments: mmio|smn|x86 <address> <sz (1,2,4 or 0)> r|w|rw before|after", gdbStubCmdIoBp                 },
    { "iobpdel",      "Deletes an I/O breakpoint, arguments: <id>",                                                      gdbStubCmdIoBpDel              },
    { "pcset",        "Sets the PC when GDB is too stupid to do it",                                                     gdbStubCmdIoSetPc              },
    { "covtrace",     "Enable a new coverage trace, arguments: <begin> <end>",                                           gdbStubCmdCovTrace             },
    { "covtracedump", "Dumps a coverage trace to the given file, arguments: <id> <filename>",                            gdbStubCmdCovTraceDump         },
    { "covtracedel",  "Delete a coverage tracer, arguments: <id>",                                                       gdbStubCmdCovTraceDel          },
    { "va2pa",        "Resolves the given virtual address to a physical one",                                            gdbStubCmdQueryPAddrFromVAddr  },
    { "tracemarker",  "Dumps the marker given as a string to the trace log",                                             gdbStubCmdTraceMarker          },
    { "corestate",    "Dumps the core state to the trace log",                                                           gdbStubCmdDumpCoreState        },
    { "x86mapslot",   "Dumps the x86 mapslot info to the trace log, arguments: <idx start> <idx end>",                   gdbStubCmdDumpX86MapSlotState  },
    { "smnmapslot",   "Dumps the SMN mapslot info to the trace log, arguments: <idx start> <idx end>",                   gdbStubCmdDumpSmnMapSlotState  },
    { "singlestep",   "Single steps through the code dumping the core state after each instruction, arguments: on|off",  gdbStubCmdSingleStep           },
    { "insnstepcnt",  "Sets the instruction step count for one debug runloop round, US AT OWN RISK!",                    gdbStubCmdInsnStepCnt          },
    { NULL,           NULL,                                                                                              NULL                           }
};


/**
 * @copydoc{GDBSTUBCMD,pfnCmd}
 *
 * @note This is only here because it accesses the command descriptor table...
 */
static int gdbStubCmdHelp(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    for (uint32_t i = 0; i < ELEMENTS(g_aGdbCmds) - 1; i++)
        pHlp->pfnPrintf(pHlp, "%s\t\t\t%s\n", g_aGdbCmds[i].pszCmd, g_aGdbCmds[i].pszDesc);

    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBIF,pfnMemAlloc}
 */
static void *pspDbgGdbStubIfMemAlloc(GDBSTUBCTX hGdbStubCtx, void *pvUser, size_t cb)
{
    (void)hGdbStubCtx;
    (void)pvUser;

    return calloc(1, cb);
}


/**
 * @copydoc{GDBSTUBIF,pfnMemFree}
 */
static void pspDbgGdbStubIfMemFree(GDBSTUBCTX hGdbStubCtx, void *pvUser, void *pv)
{
    (void)hGdbStubCtx;
    (void)pvUser;

    free(pv);
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtGetState}
 */
static GDBSTUBTGTSTATE pspDbgGdbStubIfTgtGetState(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    return pThis->fCoreRunning ? GDBSTUBTGTSTATE_RUNNING : GDBSTUBTGTSTATE_STOPPED;
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtStop}
 */
static int pspDbgGdbStubIfTgtStop(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    pThis->fCoreRunning = false;
    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtKill}
 */
static int pspDbgGdbStubIfTgtKill(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    exit(1);
    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtStep}
 */
static int pspDbgGdbStubIfTgtStep(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);

    pThis->fSingleStep = true;
    int rc = PSPEmuCoreExecRun(hPspCore, pThis->fCoreExecRun, 1, PSPEMU_CORE_EXEC_INDEFINITE);
    pThis->fSingleStep = false;
    return pspEmuDbgErrConvertToGdbStubErr(rc);
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtCont}
 */
static int pspDbgGdbStubIfTgtCont(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    pThis->fCoreRunning = true;
    return GDBSTUB_INF_SUCCESS;
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtMemRead}
 */
static int pspDbgGdbStubIfTgtMemRead(GDBSTUBCTX hGdbStubCtx, void *pvUser, GDBTGTMEMADDR GdbTgtMemAddr, void *pvDst, size_t cbRead)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);

    int rc = PSPEmuCoreMemReadVirt(hPspCore, (PSPVADDR)GdbTgtMemAddr, pvDst, cbRead);
    return pspEmuDbgErrConvertToGdbStubErr(rc);
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtMemWrite}
 */
static int pspDbgGdbStubIfTgtMemWrite(GDBSTUBCTX hGdbStubCtx, void *pvUser, GDBTGTMEMADDR GdbTgtMemAddr, const void *pvSrc, size_t cbWrite)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);

    int rc = PSPEmuCoreMemWriteVirt(hPspCore, (PSPVADDR)GdbTgtMemAddr, pvSrc, cbWrite);
    return pspEmuDbgErrConvertToGdbStubErr(rc);
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtRegsRead}
 */
static int pspDbgGdbStubIfTgtRegsRead(GDBSTUBCTX hGdbStubCtx, void *pvUser, uint32_t *paRegs, uint32_t cRegs, void *pvDst)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);

    int rc = 0;
    uint32_t *pau32RegVals = (uint32_t *)pvDst;
    for (uint32_t i = 0; i < cRegs && !rc; i++)
        rc = PSPEmuCoreQueryReg(hPspCore, (PSPCOREREG)(paRegs[i] + 1), &pau32RegVals[i]);

    return pspEmuDbgErrConvertToGdbStubErr(rc);
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtRegsWrite}
 */
static int pspDbgGdbStubIfTgtRegsWrite(GDBSTUBCTX hGdbStubCtx, void *pvUser, uint32_t *paRegs, uint32_t cRegs, const void *pvSrc)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);

    int rc = 0;
    uint32_t *pau32RegVals = (uint32_t *)pvSrc;
    for (uint32_t i = 0; i < cRegs && !rc; i++)
        rc = PSPEmuCoreSetReg(hPspCore, (PSPCOREREG)(paRegs[i] + 1), pau32RegVals[i]);

    return pspEmuDbgErrConvertToGdbStubErr(rc);
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtTpSet}
 */
static int pspDbgGdbStubIfTgtTpSet(GDBSTUBCTX hGdbStubCtx, void *pvUser, GDBTGTMEMADDR GdbTgtTpAddr, GDBSTUBTPTYPE enmTpType, GDBSTUBTPACTION enmTpAction)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;

    if (enmTpAction != GDBSTUBTPACTION_STOP)
        return GDBSTUB_ERR_NOT_SUPPORTED;

    uint32_t fTraceFlags = 0;
    switch (enmTpType)
    {
        case GDBSTUBTPTYPE_EXEC_SW:
        case GDBSTUBTPTYPE_EXEC_HW:
            fTraceFlags = PSPEMU_CORE_TRACE_F_EXEC;
            break;
        case GDBSTUBTPTYPE_MEM_READ:
            fTraceFlags = PSPEMU_CORE_TRACE_F_READ;
            break;
        case GDBSTUBTPTYPE_MEM_WRITE:
            fTraceFlags = PSPEMU_CORE_TRACE_F_WRITE;
            break;
        case GDBSTUBTPTYPE_MEM_ACCESS:
            fTraceFlags = PSPEMU_CORE_TRACE_F_READ | PSPEMU_CORE_TRACE_F_WRITE;
            break;
        default:
            /* Should not happen. */
            return GDBSTUB_ERR_NOT_SUPPORTED;
    }

    int rcGdbStub = GDBSTUB_INF_SUCCESS;
    PSPADDR PspAddrBp = (PSPADDR)GdbTgtTpAddr;
    PPSPDBGTP pTp = NULL;
    int rc = pspDbgTpCreate(pThis, false /*fIoTp*/, 0 /*cHitsMax*/, &pTp);
    if (!rc)
    {
        pTp->u.PspAddrTp = PspAddrBp;

        PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);
        rc = PSPEmuCoreTraceRegister(hPspCore, PspAddrBp, PspAddrBp, fTraceFlags, pspDbgTpBpHit, pTp);
        if (!rc)
            return GDBSTUB_INF_SUCCESS;
        else
            rcGdbStub = pspEmuDbgErrConvertToGdbStubErr(rc);

        pspDbgTpDestroy(pTp);
    }
    else
        rcGdbStub = GDBSTUB_ERR_NO_MEMORY;

    return rcGdbStub;
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtTpClear}
 */
static int pspDbgGdbStubIfTgtTpClear(GDBSTUBCTX hGdbStubCtx, void *pvUser, GDBTGTMEMADDR GdbTgtTpAddr)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPADDR PspAddrBp = (PSPADDR)GdbTgtTpAddr;

    /* Find the tracepoint to remove. */
    PPSPDBGTP pTpCur = pThis->pTpsHead;
    while (   pTpCur
           && (    pTpCur->fIoTp
               ||  pTpCur->u.PspAddrTp != PspAddrBp))
        pTpCur = pTpCur->pNext;

    int rcGdbStub = GDBSTUB_INF_SUCCESS;
    if (pTpCur)
        pspDbgTpDestroy(pTpCur);
    else
        rcGdbStub = GDBSTUB_ERR_INVALID_PARAMETER;

    return rcGdbStub;
}


/**
 * GDB stub interface callback table.
 */
static const GDBSTUBIF g_PspDbgGdbStubIf =
{
    /** enmArch */
    GDBSTUBTGTARCH_ARM,
    /** paRegs */
    &g_apszPspDbgGdbStubRegs[0],
    /** paCmds */
    &g_aGdbCmds[0],
    /** pfnMemAlloc */
    pspDbgGdbStubIfMemAlloc,
    /** pfnMemFree */
    pspDbgGdbStubIfMemFree,
    /** pfnTgtGetState */
    pspDbgGdbStubIfTgtGetState,
    /** pfnTgtStop */
    pspDbgGdbStubIfTgtStop,
    /** pfnTgtRestart */
    NULL,
    /** pfnTgtKill */
    pspDbgGdbStubIfTgtKill,
    /** pfnTgtStep */
    pspDbgGdbStubIfTgtStep,
    /** pfnTgtCont */
    pspDbgGdbStubIfTgtCont,
    /** pfnTgtMemRead */
    pspDbgGdbStubIfTgtMemRead,
    /** pfnTgtMemWrite */
    pspDbgGdbStubIfTgtMemWrite,
    /** pfnTgtRegsRead */
    pspDbgGdbStubIfTgtRegsRead,
    /** pfnTgtRegsWrite */
    pspDbgGdbStubIfTgtRegsWrite,
    /** pfnTgtTpSet */
    pspDbgGdbStubIfTgtTpSet,
    /** pfnTgtTpClear */
    pspDbgGdbStubIfTgtTpClear,
    /** pfnMonCmd */
    NULL
};


static size_t pspDbgStubIoIfPeek(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    (void)hGdbStubCtx;

    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    int cbAvail = 0;
    int rc = ioctl(pThis->iFdGdbCon, FIONREAD, &cbAvail);
    if (rc)
        return 0;

    return cbAvail;
}


static int pspDbgStubIoIfRead(GDBSTUBCTX hGdbStubCtx, void *pvUser, void *pvDst, size_t cbRead, size_t *pcbRead)
{
    (void)hGdbStubCtx;

    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    ssize_t cbRet = recv(pThis->iFdGdbCon, pvDst, cbRead, MSG_DONTWAIT);
    if (cbRet > 0)
    {
        *pcbRead = cbRead;
        return GDBSTUB_INF_SUCCESS;
    }

    if (!cbRet)
        return GDBSTUB_ERR_PEER_DISCONNECTED;

    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return GDBSTUB_INF_TRY_AGAIN;

    return GDBSTUB_ERR_INTERNAL_ERROR; /** @todo Better status codes for the individual errors. */
}


static int pspDbgStubIoIfWrite(GDBSTUBCTX hGdbStubCtx, void *pvUser, const void *pvPkt, size_t cbPkt)
{
    (void)hGdbStubCtx;

    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    ssize_t cbRet = send(pThis->iFdGdbCon, pvPkt, cbPkt, 0);
    if (cbRet == cbPkt)
        return GDBSTUB_INF_SUCCESS;

    return GDBSTUB_ERR_INTERNAL_ERROR; /** @todo Better status codes for the individual errors. */
}


/**
 * GDB stub I/O interface callback table.
 */
const GDBSTUBIOIF g_PspDbgGdbStubIoIf =
{
    /** pfnPeek */
    pspDbgStubIoIfPeek,
    /** pfnRead */
    pspDbgStubIoIfRead,
    /** pfnWrite */
    pspDbgStubIoIfWrite,
    /** pfnPoll */
    NULL /* We do the polling ourselves. */
};


/**
 * Waits until a GDB connects.
 *
 * @returns Status code.
 * @param   pThis                   The PSP debugger instance.
 */
static int pspEmuDbgWaitForGdbConnection(PPSPDBGINT pThis)
{
    int rc = 0;
    int rcPsx = listen(pThis->iFdListening, 1);
    if (!rcPsx)
    {
        pThis->iFdGdbCon = accept(pThis->iFdListening, (struct sockaddr *)NULL, NULL);
        if (pThis->iFdGdbCon == -1)
        {
            pThis->iFdGdbCon = 0;
            rc = -1;
        }
    }
    else
        rc = -1;

    return rc;
}


/**
 * The debugger runloop for the target not running case.
 *
 * @returns Status code.
 * @param   pThis                   The PSP debugger instance.
 */
static int pspEmuDbgRunloopCoreNotRunning(PPSPDBGINT pThis)
{
    /* Poll for data and feed it to the GDB stub, which will execute requests. */
    int rc = 0;
    struct pollfd PollFd;

    PollFd.fd      = pThis->iFdGdbCon;
    PollFd.events  = POLLIN | POLLHUP | POLLERR;

    /* Run the GDB stub runloop once to sync on the target state. */
    int rcGdbStub = GDBStubCtxRun(pThis->hGdbStubCtx);
    if (   rcGdbStub != GDBSTUB_INF_SUCCESS
        && rcGdbStub != GDBSTUB_INF_TRY_AGAIN)
        rc = -1;

    while (   !pThis->fCoreRunning
           && !rc)
    {
        PollFd.revents = 0;

        int rcPsx = poll(&PollFd, 1, INT32_MAX);
        if (rcPsx == 1)
        {
            /* Run the GDB stub runloop until it returns. */
            rcGdbStub = GDBStubCtxRun(pThis->hGdbStubCtx);
            if (   rcGdbStub != GDBSTUB_INF_SUCCESS
                && rcGdbStub != GDBSTUB_INF_TRY_AGAIN)
                rc = -1;
        }
        if (rcPsx == -1)
            rc = -1;
    }

    return rc;
}


/**
 * The debugger runloop for the target running case.
 *
 * @returns Status code.
 * @param   pThis                   The PSP debugger instance.
 */
static int pspEmuDbgRunloopCoreRunning(PPSPDBGINT pThis)
{
    /* Poll for data and feed it to the GDB stub, which will execute requests. */
    int rc = 0;
    struct pollfd PollFd;

    PollFd.fd      = pThis->iFdGdbCon;
    PollFd.events  = POLLIN | POLLHUP | POLLERR;
    PollFd.revents = 0;

    while (   pThis->fCoreRunning
           && !rc)
    {
        PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);

        /*
         * Execute a bunch of instructions, check whether we have data from GDB
         * and act accordingly.
         *
         * XXX: Unicorn has problems to sync states properly when a breakpoint is
         *      hit and we stop the emulation from the callback, so we single step
         *      through the code when the debugger is enabled.
         */
        rc = PSPEmuCoreExecRun(hPspCore, pThis->fCoreExecRun, pThis->cInsnsStep != 0 ? pThis->cInsnsStep : 1, PSPEMU_CORE_EXEC_INDEFINITE);
        if (!rc)
        {
            int rcPsx = poll(&PollFd, 1, 0);
            if (rcPsx == 1)
            {
                /* Run the GDB stub runloop until it returns. */
                int rcGdbStub = GDBStubCtxRun(pThis->hGdbStubCtx);
                if (   rcGdbStub != GDBSTUB_INF_SUCCESS
                    && rcGdbStub != GDBSTUB_INF_TRY_AGAIN)
                    rc = -1;
            }
            if (rcPsx == -1)
                rc = -1;
        }
        else
            PSPEmuCoreStateDump(hPspCore, PSPEMU_CORE_STATE_DUMP_F_DEFAULT, 0 /*cInsns*/);
    }

    return rc;
}


int PSPEmuDbgCreate(PPSPDBG phDbg, uint16_t uPort, uint32_t cInsnsStep, PSPADDR PspAddrRunUpTo, const PPSPCCD pahCcds, uint32_t cCcds)
{
    int rc = 0;
    PPSPDBGINT pThis = (PPSPDBGINT)calloc(1, sizeof(*pThis) + cCcds * sizeof(PSPCCD));
    if (pThis)
    {
        pThis->iFdGdbCon        = 0;
        pThis->fCoreRunning     = false;
        pThis->fCoreExecRun     = PSPEMU_CORE_EXEC_F_DEFAULT;
        pThis->pTpsHead         = NULL;
        pThis->pCovHead         = NULL;
        pThis->cInsnsStep       = cInsnsStep;
        pThis->cCcds            = cCcds;
        pThis->idxCcd           = 0;
        pThis->idCovNext        = 0;
        pThis->PspAddrRunUpTo   = PspAddrRunUpTo;
        for (uint32_t i = 0; i < cCcds; i++)
            pThis->ahCcds[i] = pahCcds[i];

        int rcGdbStub = GDBStubCtxCreate(&pThis->hGdbStubCtx, &g_PspDbgGdbStubIoIf, &g_PspDbgGdbStubIf, pThis);
        if (rcGdbStub == GDBSTUB_INF_SUCCESS)
        {
            struct sockaddr_in SockAddr;

            pThis->iFdListening = socket(AF_INET, SOCK_STREAM, 0);
            if (pThis->iFdListening > -1)
            {
                memset(&SockAddr, 0, sizeof(SockAddr));

                SockAddr.sin_family      = AF_INET;
                SockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
                SockAddr.sin_port        = htons(uPort);
                int rcPsx = bind(pThis->iFdListening, (struct sockaddr *)&SockAddr, sizeof(SockAddr));
                if (!rcPsx)
                {
                    *phDbg = pThis;
                    return 0;
                }
                else
                    rc = -1;

                close(pThis->iFdListening);
            }
            else
                rc = -1;

            GDBStubCtxDestroy(pThis->hGdbStubCtx);
        }
        else
            rc = pspEmuDbgErrConvertFromGdbStubErr(rcGdbStub);

        free(pThis);
    }
    else
        rc = -1;

    return rc;
}


int PSPEmuDbgDestroy(PSPDBG hDbg)
{
    PPSPDBGINT pThis = hDbg;

    if (pThis->iFdGdbCon != 0)
        close(pThis->iFdGdbCon);
    close(pThis->iFdListening);
    GDBStubCtxDestroy(pThis->hGdbStubCtx);
    free(pThis);
    return 0;
}


int PSPEmuDbgRunloop(PSPDBG hDbg)
{
    int rc = 0;
    PPSPDBGINT pThis = hDbg;

    /* We are supposed to be running up to a specified point insert a single shot trace point
     * and a excercise the running runloop until the trace point is hit.
     */
    if (pThis->PspAddrRunUpTo != UINT32_MAX)
    {
        PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);
        PPSPDBGTP pTp = NULL;
        pspDbgTpCreate(pThis, false /*fIoTp*/, 1 /*cHitsMax*/, &pTp);
        pTp->u.PspAddrTp = pThis->PspAddrRunUpTo;
        PSPEmuCoreTraceRegister(hPspCore, pThis->PspAddrRunUpTo, pThis->PspAddrRunUpTo,
                                PSPEMU_CORE_TRACE_F_EXEC, pspDbgTpBpHit, pTp);
        pThis->fCoreRunning = true;
        rc = PSPEmuCoreExecRun(hPspCore, pThis->fCoreExecRun, 0, PSPEMU_CORE_EXEC_INDEFINITE);
        pThis->fCoreRunning = false;
    }

    while (!rc)
    {
        /* Wait until we get a connection. */
        while (   !rc
               && pThis->iFdGdbCon == 0)
            rc = pspEmuDbgWaitForGdbConnection(pThis);

        if (!pThis->fCoreRunning)
            rc = pspEmuDbgRunloopCoreNotRunning(pThis);
        else
        {
            rc = pspEmuDbgRunloopCoreRunning(pThis);
            if (rc)
            {
                pThis->fCoreRunning = false;
                rc = 0;
            }
        }
    }

    return rc;
}


int PSPEmuDbgKick(PSPDBG hDbg)
{
    return -1;
}
