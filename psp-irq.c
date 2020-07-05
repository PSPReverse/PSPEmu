/** @file
 * PSP Emulator - Interrupt controller.
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
/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/

#include <stdlib.h>

#include <common/types.h>
#include <common/cdefs.h>
#include <common/status.h>

#include <psp/irq.h>

#include <psp-irq.h>
#include <psp-trace.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/**
 * Interrupt controller instance data.
 */
typedef struct PSPIRQINT
{
    /** The PSP core to forward interrupt requests to. */
    PSPCORE                     hPspCore;
    /** I/O manager for the MMIO register interface. */
    PSPIOM                      hIoMgr;
    /** The MMIO region handle for the register interface. */
    PSPIOMREGIONHANDLE          hMmio;
    /** Interrupt request groups pending. */
    uint32_t                    cGrpPending;
    /** The individual groups. */
    uint32_t                    abmGrpDev[4];
    /** Hidden individual groups to trigger an IRQ only on a rising edge. */
    uint32_t                    abmGrpDevLast[4];
} PSPIRQINT;
/** Pointer to the internal interrupt controller instance data. */
typedef PSPIRQINT *PPSPIRQINT;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/


/**
 * @copydoc{PFNPSPIOMMMIOREAD, IRQ controller read handler}
 */
static void pspIrqMmioRead(PSPADDR offMmio, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPIRQINT pThis = (PPSPIRQINT)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_IRQ,
                                "%s: offMmio=%#x cbRead=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbRead);
        return;
    }

    uint32_t *pu32Dst = (uint32_t *)pvDst;
    *pu32Dst = 0;
    switch (offMmio)
    {
        case PSP_IRQ_REG_ACK_PRIO0_OFF:
        case PSP_IRQ_REG_ACK_PRIO1_OFF:
        case PSP_IRQ_REG_ACK_PRIO2_OFF:
        case PSP_IRQ_REG_ACK_PRIO3_OFF:
        {
            uint32_t idPrio = (offMmio - PSP_IRQ_REG_ACK_PRIO0_OFF) / sizeof(uint32_t);
            *pu32Dst = pThis->abmGrpDev[idPrio];
            break;
        }
        case PSP_IRQ_REG_PEN_OFF:
        {
            if (pThis->cGrpPending)
                *pu32Dst = PSP_IRQ_REG_PEN_PENDING;
            else
                *pu32Dst = PSP_IRQ_REG_PEN_NOT_PENDING;
            break;
        }
        case PSP_IRQ_REG_ID_OFF:
        {
            /*
             * How it is decided which interrupt source to return on real hardware is not
             * known actually at the moment.
             *
             * We just start from the lowest priority/group and device ID (highest priority) for now.
             */
            for (uint32_t i = 0; i < ELEMENTS(pThis->abmGrpDev); i++)
            {
                if (pThis->abmGrpDev[i] != 0)
                {
                    /** @todo Optimize. */
                    uint32_t uPrio = pThis->abmGrpDev[i];
                    uint32_t idDev = 0;
                    while (uPrio)
                    {
                        if (uPrio & 1)
                            break; /* Found the device. */
                        uPrio >>= 1;
                        idDev++;
                    }

                    *pu32Dst = PSP_IRQ_REG_ID_MAKE(i, idDev);
                    break;
                }
            }
            break;
        }
        default:
            break;
    }
}


/**
 * @copydoc{PFNPSPIOMMMIOWRITE, IRQ controller write handler}
 */
static void pspIrqMmioWrite(PSPADDR offMmio, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPIRQINT pThis = (PPSPIRQINT)pvUser;

    if (cbWrite != sizeof(uint32_t))
    {
        PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_ERROR, PSPTRACEEVTORIGIN_IRQ,
                                "%s: offMmio=%#x cbWrite=%zu -> Unsupported access width\n", __FUNCTION__, offMmio, cbWrite);
        return;
    }

    uint32_t uVal = *(uint32_t *)pvVal;
    switch (offMmio)
    {
        case PSP_IRQ_REG_ACK_PRIO0_OFF:
        case PSP_IRQ_REG_ACK_PRIO1_OFF:
        case PSP_IRQ_REG_ACK_PRIO2_OFF:
        case PSP_IRQ_REG_ACK_PRIO3_OFF:
        {
            uint32_t idPrio = (offMmio - PSP_IRQ_REG_ACK_PRIO0_OFF) / sizeof(uint32_t);

            pThis->abmGrpDev[idPrio] &= ~uVal;
            if (!pThis->abmGrpDev[idPrio])
                pThis->cGrpPending--;

            if (!pThis->cGrpPending) /* Reset the interrupt line. */
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_IRQ, "De-Asserting IRQ\n");
                PSPEmuCoreIrqSet(pThis->hPspCore, false /*fAssert*/);
            }
            break;
        }
        case PSP_IRQ_REG_PEN_OFF:
        case PSP_IRQ_REG_ID_OFF:
        default:
            break; /* Ignore. */
    }
}


int PSPIrqCreate(PPSPIRQ phIrq, PSPCORE hPspCore, PSPIOM hIoMgr)
{
    int rc = STS_INF_SUCCESS;
    PPSPIRQINT pThis = (PPSPIRQINT)calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->hPspCore = hPspCore;
        pThis->hIoMgr   = hIoMgr;

        rc = PSPEmuIoMgrMmioRegister(hIoMgr, PSP_IRQ_MMIO_ADDR_BASE, PSP_IRQ_MMIO_SZ,
                                     pspIrqMmioRead, pspIrqMmioWrite, pThis,
                                     "IRQ Ctrl", &pThis->hMmio);
        if (STS_SUCCESS(rc))
        {
            *phIrq = pThis;
            PSPIrqReset(pThis);
            return STS_INF_SUCCESS;
        }

        free(pThis);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


void PSPIrqDestroy(PSPIRQ hIrq)
{
    PPSPIRQINT pThis = hIrq;

    PSPEmuIoMgrDeregister(pThis->hMmio);
    free(pThis);
}


void PSPIrqReset(PSPIRQ hIrq)
{
    PPSPIRQINT pThis = hIrq;

    pThis->cGrpPending = 0;
    for (uint32_t i = 0; i < ELEMENTS(pThis->abmGrpDev); i++)
    {
        pThis->abmGrpDev[i] = 0;
        pThis->abmGrpDevLast[i] = 0;
    }
}


int PSPIrqSet(PSPIRQ hIrq, uint32_t uPrioGrp, uint8_t uIrq, bool fAssert)
{
    PPSPIRQINT pThis = hIrq;

    if (   uPrioGrp < ELEMENTS(pThis->abmGrpDev)
        && uIrq < sizeof(uint32_t) * 8)
    {
        /** @todo Check somehow whether interrupts are level or rising edge triggered.
         * For now we assume that interrupts are triggered on the rising edge as this
         * makes the most sense with how the interrupt handlers we've seen process interrupts so far.
         */
        if (   !(pThis->abmGrpDevLast[uPrioGrp] & BIT(uIrq))
            && fAssert)
        {
            if (!pThis->abmGrpDev[uPrioGrp])
                pThis->cGrpPending++;

            pThis->abmGrpDevLast[uPrioGrp] |= BIT(uIrq);
            pThis->abmGrpDev[uPrioGrp] |= BIT(uIrq);
            if (pThis->cGrpPending == 1)
            {
                PSPEmuTraceEvtAddString(NULL, PSPTRACEEVTSEVERITY_INFO, PSPTRACEEVTORIGIN_IRQ,
                                        "Asserting IRQ caused by idPrio=%u idDev=%u\n", uPrioGrp, uIrq);
                PSPEmuCoreIrqSet(pThis->hPspCore, true /*fAssert*/);
            }
        }
        else if (!fAssert)
            pThis->abmGrpDevLast[uPrioGrp] &= ~BIT(uIrq);

        return STS_INF_SUCCESS;
    }

    return STS_ERR_INVALID_PARAMETER;
}
