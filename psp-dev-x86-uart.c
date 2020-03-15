/** @file
 * PSP Emulator - UART like device living at 0xfffdfc0003f8 (on Ryzen Pro so far).
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

#include <stdio.h>

#include <common/cdefs.h>
#include <x86/uart.h>

#include <psp-devs.h>
#include <psp-trace.h>


/**
 * Unknown device instance data.
 */
typedef struct PSPDEVUART
{
    /** Pointer to the owning device instance. */
    PPSPDEV                 pDev;
    /** MMIO region handle. */
    PSPIOMREGIONHANDLE      hMmio;
    /** LCR register value. */
    uint8_t                 u8RegLcr;
    /** RBR register value. */
    uint8_t                 u8RegRbr;
    /** Divisor determining the baud rate. */
    uint16_t                u16Divisor;
    /** Temporary char buffer. */
    uint8_t                 achBuf[512];
    /** Where to write next. */
    uint32_t                offWrite;
} PSPDEVUART;
/** Pointer to the device instance data. */
typedef PSPDEVUART *PPSPDEVUART;

static void pspDevX86UartRead(X86PADDR offMmio, size_t cbRead, void *pvVal, void *pvUser)
{
    PPSPDEVUART pThis = (PPSPDEVUART)pvUser;

    if (cbRead != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                "Invalid register read size %u cbRead=%zu", offMmio, cbRead);
        return;
    }

    uint8_t *pbVal = (uint8_t *)pvVal;
    switch (offMmio)
    {
        case X86_UART_REG_RBR_OFF:
        {
            *pbVal = pThis->u8RegRbr;
            break;
        }
        case X86_UART_REG_LSR_OFF:
        {
            *pbVal = X86_UART_REG_LSR_THRE | X86_UART_REG_LSR_TEMT; /* We can always take data. */
            break;
        }
        case X86_UART_REG_IER_OFF:
        {
            *pbVal = X86_UART_REG_IIR_NOT_PENDING; /* Required for the UART detection logic. */
            break;
        }
        case X86_UART_REG_LCR_OFF:
        {
            *pbVal = pThis->u8RegLcr;
            break;
        }
        default:
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                    "Register %u not implemented", offMmio);
    }
}

static void pspDevX86UartWrite(X86PADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVUART pThis = (PPSPDEVUART)pvUser;

    if (cbWrite != sizeof(uint8_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                "Invalid register write size %u cbWrite=%zu", offMmio, cbWrite);
        return;
    }

    uint8_t bVal = *(const uint8_t *)pvVal;
    switch (offMmio)
    {
        case X86_UART_REG_THR_OFF:
        /*case X86_UART_REG_DL_MSB_OFF:*/
        {
            /* Set divisor if DLAB is set. */
            if (pThis->u8RegLcr & X86_UART_REG_LCR_DLAB)
            {
                pThis->u16Divisor = (pThis->u16Divisor & 0xff00) | (uint16_t)bVal;

                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_X86_UART,
                                        "Line parameters set to %u %u%s%u",
                                        115200 / pThis->u16Divisor,
                                        (pThis->u8RegLcr & 0x3) + 5,
                                        pThis->u8RegLcr & X86_UART_REG_LCR_PEN ? "O" : "N", /** @todo Not correct as even bit is not checked. */
                                        pThis->u8RegLcr & X86_UART_REG_LCR_STB ? 2 : 1);
            }
            else if (bVal != '\r') /* Ignore carriage return. */
            {
                /* Store character. */
                if (pThis->offWrite < sizeof(pThis->achBuf))
                {
                    pThis->achBuf[pThis->offWrite] = bVal;
                    if (bVal == '\n')
                    {
                        pThis->achBuf[pThis->offWrite] = '\0';
                        /* Dump to the trace log and reset the buffer. */
                        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_X86_UART,
                                                "%s", &pThis->achBuf[0]);
                        pThis->offWrite = 0;
                    }
                    else
                        pThis->offWrite++;
                }
                else
                    PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                            "Buffer too small");
            }
            break;
        }
        case X86_UART_REG_LCR_OFF:
        {
            pThis->u8RegLcr = bVal;
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_X86_UART,
                                    "Line parameters set to %u %u%s%u",
                                    115200 / pThis->u16Divisor,
                                        (pThis->u8RegLcr & 0x3) + 5,
                                    pThis->u8RegLcr & X86_UART_REG_LCR_PEN ? "O" : "N", /** @todo Not correct as even bit is not checked. */
                                    pThis->u8RegLcr & X86_UART_REG_LCR_STB ? 2 : 1);
            break;
        }
        case X86_UART_REG_DL_MSB_OFF:
        /*case X86_UART_REG_IER_OFF:*/
        {
            /* Set divisor if DLAB is set. */
            if (pThis->u8RegLcr & X86_UART_REG_LCR_DLAB)
            {
                pThis->u16Divisor = (pThis->u16Divisor & 0xff) | ((uint16_t)bVal << 8);

                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_DEBUG, PSPTRACEEVTORIGIN_X86_UART,
                                        "Line parameters set to %u %u%s%u",
                                        115200 / pThis->u16Divisor,
                                        (pThis->u8RegLcr & 0x3) + 5,
                                        pThis->u8RegLcr & X86_UART_REG_LCR_PEN ? "O" : "N", /** @todo Not correct as even bit is not checked. */
                                        pThis->u8RegLcr & X86_UART_REG_LCR_STB ? 2 : 1);
            }
            /* else Ignore access to IER. */

            break;
        }
        case X86_UART_REG_LSR_OFF:
            break; /* Ignore. */
        default:
            PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_X86_UART,
                                    "Register %u not implemented", offMmio);
    }
}

static int pspDevX86UartInit(PPSPDEV pDev)
{
    PPSPDEVUART pThis = (PPSPDEVUART)&pDev->abInstance[0];

    pThis->pDev       = pDev;
    pThis->offWrite   = 0;
    pThis->u8RegRbr   = 1; /* Required for the detection logic. */
    pThis->u8RegLcr   = 0;
    pThis->u16Divisor = 1; /* 115200 baud */
    X86_UART_REG_LCR_WLS_SET(pThis->u8RegLcr, X86_UART_REG_LCR_WLS_8); /* Required for the UART detection logic. */

    /* Register MMIO ranges. */
    int rc = PSPEmuIoMgrX86MmioRegister(pDev->hIoMgr, 0xfffdfc0003f8, 8,
                                        pspDevX86UartRead, pspDevX86UartWrite, pThis,
                                        &pThis->hMmio);
    return rc;
}


static void pspDevX86UartDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegX86Uart =
{
    /** pszName */
    "x86-uart",
    /** pszDesc */
    "Standard x86 UART",
    /** cbInstance */
    sizeof(PSPDEVUART),
    /** pfnInit */
    pspDevX86UartInit,
    /** pfnDestruct */
    pspDevX86UartDestruct
};

