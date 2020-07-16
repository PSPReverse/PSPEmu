/** @file
 * PSP Emulator - Captures status information from x86 port 80h (0xfffdfc000080) and MMIO 0x32000e8.
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

#include <stdio.h>

#include <common/cdefs.h>
#include <psp-fw/err.h>

#include <psp-devs.h>
#include <psp-trace.h>

/**
 * Status device instance data.
 */
typedef struct PSPDEVSTS
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE      hMmio;
    /** X86 MMIO region handle. */
    PSPIOMREGIONHANDLE      hX86Mmio;
    /** Flag whether the firmware is currently logging a string through port 80h. */
    bool                    fPort80hLog;
    /** Next character to write. */
    uint32_t                offWrite;
    /** Character buffer holding the string. */
    char                    achBuf[512];
} PSPDEVSTS;
/** Pointer to the device instance data. */
typedef PSPDEVSTS *PPSPDEVSTS;

/**
 * The human readable status code strings.
 */
static const char *g_apszPspFwSts[] =
{
    PSPSTATUS_STR_TBL
};


/**
 * Logs the given status code from the firmware to the trace log.
 *
 * @returns nothing.
 * @param   pThis               The status device instance data.
 * @param   fX86                Flag whether this value was written to the standard 80h x86 port.
 * @param   uStsVal             The status value to log.
 */
static void pspDevStsLogCode(PPSPDEVSTS pThis, bool fX86, uint32_t uStsVal)
{
    if (uStsVal < ELEMENTS(g_apszPspFwSts))
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_STS,
                                "POST CODE (%s): %s", fX86 ? "X86" : "PSP", g_apszPspFwSts[uStsVal]);
    else
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_STS,
                                "POST CODE (%s): UNKNOWN %#x", fX86 ? "X86" : "PSP", uStsVal);
}

static void pspDevStsMmioRead(PSPADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVSTS pThis = (PPSPDEVSTS)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_STS,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    *(uint32_t *)pvVal = 0; /** @todo Figure out value on real hardware. */
}

static void pspDevStsMmioWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVSTS pThis = (PPSPDEVSTS)pvUser;

    if (cbWrite != sizeof(uint32_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_STS,
                                "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        return;
    }

    uint32_t uVal = *(uint32_t *)pvVal;
    if (uVal & BIT(8))
        pspDevStsLogCode(pThis, false /*fX86*/, uVal & 0xff);
    else
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_STS,
                                "PSP STS PORT: %#x", uVal);
}

static void pspDevStsX86Read(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVSTS pThis = (PPSPDEVSTS)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_STS,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    *(uint32_t *)pvVal = 0; /** @todo Figure out value on real hardware. */
}

static void pspDevStsX86Write(X86PADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVSTS pThis = (PPSPDEVSTS)pvUser;

    if (   cbWrite != sizeof(uint32_t)
        && cbWrite != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_STS,
                                "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        return;
    }

    switch (cbWrite)
    {
        case 4:
        {
            uint32_t uVal = *(uint32_t *)pvVal;
            if (uVal == 0x5f535452 /*_STR*/)
            {
                /* Marks the beginning of a firmware log entry. */
                pThis->fPort80hLog = true;
                pThis->offWrite    = 0;
            }
            else if (uVal == 0x5f454e44 /*_END*/)
            {
                /* Marks the end of a firmware log entry. */
                pThis->fPort80hLog = false;
                pThis->achBuf[pThis->offWrite] = '\0'; /* Ensure termination. */
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_STS,
                                        "%s", &pThis->achBuf[0]);
                pThis->offWrite = 0;
            }
            else
                pspDevStsLogCode(pThis, true /*fX86*/, uVal & 0xffff);
            break;
        }
        case 1:
        {
            if (pThis->fPort80hLog)
            {
                if (pThis->offWrite < sizeof(pThis->achBuf) - 1)
                    pThis->achBuf[pThis->offWrite++] = *(char *)pvVal;
            }
            else
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_STS,
                                        "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        }
    }
}

static int pspDevStsInit(PPSPDEV pDev)
{
    PPSPDEVSTS pThis = (PPSPDEVSTS)&pDev->abInstance[0];

    pThis->pDev        = pDev;
    pThis->fPort80hLog = false;
    pThis->offWrite    = 0;

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrMmioRegister(pDev->hIoMgr, pDev->pCfg->pPspProfile->PspAddrMmioSts, 4,
                                     pspDevStsMmioRead, pspDevStsMmioWrite, pThis,
                                     "PspSts", &pThis->hMmio);
    if (!rc)
        rc = PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfffdfc000080, 4,
                                        pspDevStsX86Read, pspDevStsX86Write, pThis,
                                        "X86Sts",&pThis->hX86Mmio);
    return rc;
}


static void pspDevStsDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegSts =
{
    /** pszName */
    "status",
    /** pszDesc */
    "Status collector device",
    /** cbInstance */
    sizeof(PSPDEVSTS),
    /** pfnInit */
    pspDevStsInit,
    /** pfnDestruct */
    pspDevStsDestruct,
    /** pfnReset */
    NULL
};

