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

#include <psp-dbg.h>


/** Pointer to the debugger instance data. */
typedef struct PSPDBGINT *PPSPDBGINT;


/**
 * A single tracepoint.
 */
typedef struct PSPDBGTP
{
    /** Next tracepoint in the list. */
    struct PSPDBGTP         *pNext;
    /** Pointer to the owning debugger instance. */
    PPSPDBGINT              pDbg;
    /** The tracepoint address. */
    PSPADDR                 PspAddrTp;
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
    /** Head of tracepoint list. */
    PPSPDBGTP               pTpsHead;
    /** Current breakpoint which hit. */
    PCPSPDBGTP              pTpHit;
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
    PCPSPDBGTP pTp = (PCPSPDBGTP)pvUser;
    PPSPDBGINT pThis = pTp->pDbg;

    /* Stop the emulation if not in single stepping mode. */
    if (!pThis->fSingleStep)
    {
        pThis->fCoreRunning = false;
        pThis->pTpHit = pTp;
        PSPEmuCoreExecStop(hCore);
    }
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
    int rc = PSPEmuCoreExecRun(hPspCore, 1, PSPEMU_CORE_EXEC_INDEFINITE);
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

    int rc = PSPEmuCoreMemRead(hPspCore, (PSPADDR)GdbTgtMemAddr, pvDst, cbRead);
    return pspEmuDbgErrConvertToGdbStubErr(rc);
}


/**
 * @copydoc{GDBSTUBIF,pfnTgtMemWrite}
 */
static int pspDbgGdbStubIfTgtMemWrite(GDBSTUBCTX hGdbStubCtx, void *pvUser, GDBTGTMEMADDR GdbTgtMemAddr, const void *pvSrc, size_t cbWrite)
{
    PPSPDBGINT pThis = (PPSPDBGINT)pvUser;
    PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);

    int rc = PSPEmuCoreMemWrite(hPspCore, (PSPADDR)GdbTgtMemAddr, pvSrc, cbWrite);
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
    PPSPDBGTP pTp = (PPSPDBGTP)calloc(1, sizeof(*pTp));
    if (pTp)
    {
        pTp->pNext     = NULL;
        pTp->pDbg      = pThis;
        pTp->PspAddrTp = PspAddrBp;

        PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);
        int rc = PSPEmuCoreTraceRegister(hPspCore, PspAddrBp, PspAddrBp, fTraceFlags, pspDbgTpBpHit, pTp);
        if (!rc)
        {
            pTp->pNext = pThis->pTpsHead;
            pThis->pTpsHead = pTp;
            return GDBSTUB_INF_SUCCESS;
        }
        else
            rcGdbStub = pspEmuDbgErrConvertToGdbStubErr(rc);

        free(pTp);
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
    PPSPDBGTP pTpPrev = NULL;
    PPSPDBGTP pTpCur = pThis->pTpsHead;
    while (   pTpCur
           && pTpCur->PspAddrTp != PspAddrBp)
    {
        pTpPrev = pTpCur;
        pTpCur = pTpCur->pNext;
    }

    int rcGdbStub = GDBSTUB_INF_SUCCESS;
    if (pTpCur)
    {
        PSPCORE hPspCore = pspEmuDbgGetPspCoreFromSelectedCcd(pThis);

        int rc = PSPEmuCoreTraceDeregister(hPspCore, pTpCur->PspAddrTp, pTpCur->PspAddrTp);
        if (!rc)
        {
            /* Unlink and free memory. */
            if (pTpPrev)
                pTpPrev->pNext = pTpCur->pNext;
            else
                pThis->pTpsHead = pTpCur->pNext;

            free(pTpCur);
        }
        else
            rcGdbStub = pspEmuDbgErrConvertToGdbStubErr(rc);
    }
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
    NULL,
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
        rc = PSPEmuCoreExecRun(hPspCore, 1, PSPEMU_CORE_EXEC_INDEFINITE);
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
    }

    return rc;
}


int PSPEmuDbgCreate(PPSPDBG phDbg, uint16_t uPort, const PPSPCCD pahCcds, uint32_t cCcds)
{
    int rc = 0;
    PPSPDBGINT pThis = (PPSPDBGINT)calloc(1, sizeof(*pThis) + cCcds * sizeof(PSPCCD));
    if (pThis)
    {
        pThis->iFdGdbCon    = 0;
        pThis->fCoreRunning = false;
        pThis->pTpsHead     = NULL;
        pThis->cCcds        = cCcds;
        pThis->idxCcd       = 0;
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

    while (!rc)
    {
        /* Wait until we get a connection. */
        while (   !rc
               && pThis->iFdGdbCon == 0)
            rc = pspEmuDbgWaitForGdbConnection(pThis);

        if (!pThis->fCoreRunning)
            rc = pspEmuDbgRunloopCoreNotRunning(pThis);
        else
            rc = pspEmuDbgRunloopCoreRunning(pThis);
    }

    return rc;
}


int PSPEmuDbgKick(PSPDBG hDbg)
{
    return -1;
}
