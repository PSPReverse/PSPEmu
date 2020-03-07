/** @file
 * PSP Emulator - SMU attached to SMN.
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
#include <string.h>

#include <common/cdefs.h>

#include <psp-devs.h>


/**
 * SMU device instance data.
 */
typedef struct PSPDEVSMU
{
    /** SMN region handle. */
    PSPIOMREGIONHANDLE          hSmn;
    /** SMN region handle for the interrupt read register? */
    PSPIOMREGIONHANDLE          hSmnIntrRdy;
    /** SMN region handle for the message passing interface. */
    PSPIOMREGIONHANDLE          hSmnMsg;
    /** SMN region handle for the firmware region. */
    PSPIOMREGIONHANDLE          hSmnFw;
    /** Message status register. */
    uint32_t                    u32RegMsgSts;
    /** Argument/Return value register. */
    uint32_t                    u32RegMsgArgRet;
    /** Message ID register. */
    uint32_t                    u32RegMsgId;
    /** The memory the firmware is loaded to residing at SMN address 0x3c00000. */
    uint8_t                     abFw[_256K];
} PSPDEVSMU;
/** Pointer to the device instance data. */
typedef PSPDEVSMU *PPSPDEVSMU;


static void pspDevSmuRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVSMU pThis = (PPSPDEVSMU)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        printf("%s: offSmn=%#x cbRead=%zu -> Unsupported access width\n", __FUNCTION__, offSmn, cbRead);
        return;
    }

    switch (offSmn)
    {
        case 0: /* Maybe some sort of status register. */
        {
            *(uint32_t *)pvDst = 0x1; /* Some SMU ready/online bit the off chip bootloader waits for after the firmware was loaded. */
            break;
        }
    }
}


static void pspDevSmuMsgRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVSMU pThis = (PPSPDEVSMU)pvUser;

    if (cbRead != sizeof(uint32_t))
    {
        printf("%s: offSmn=%#x cbRead=%zu -> Unsupported access width\n", __FUNCTION__, offSmn, cbRead);
        return;
    }

    switch (offSmn)
    {
        case 0: /* Message argument register. */
        {
            *(uint32_t *)pvDst = pThis->u32RegMsgArgRet;
            break;
        }
        case 4: /* Status register. */
        {
            *(uint32_t *)pvDst = pThis->u32RegMsgSts;
            break;
        }
        case 20: /* Message ID register. */
        {
            *(uint32_t *)pvDst = pThis->u32RegMsgId;
            break;
        }
        default:
            printf("%s: offSmn=%#x cbRead=%zu -> Unsupported register offset\n", __FUNCTION__, offSmn, cbRead);
    }
}


static void pspDevSmuMsgWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVSMU pThis = (PPSPDEVSMU)pvUser;

    if (cbWrite != sizeof(uint32_t))
    {
        printf("%s: offSmn=%#x cbWrite=%zu -> Unsupported access width\n", __FUNCTION__, offSmn, cbWrite);
        return;
    }

    switch (offSmn)
    {
        case 0: /* Message argument register. */
        {
            pThis->u32RegMsgArgRet = *(const uint32_t *)pvVal;
            break;
        }
        case 4: /* Status register. */
        {
            pThis->u32RegMsgSts = *(const uint32_t *)pvVal;
            break;
        }
        case 20: /* Message ID register which kicks off the request. */
        {
            pThis->u32RegMsgId = *(const uint32_t *)pvVal;
            printf("SMU: Executing request %#x with argument %#x\n", pThis->u32RegMsgId, pThis->u32RegMsgArgRet);
            /* Writing the message register, executes the request and sets the ready bit when done. */
            pThis->u32RegMsgSts |= 0x1;
            break;
        }
        default:
            printf("%s: offSmn=%#x cbWrite=%zu -> Unsupported register offset\n", __FUNCTION__, offSmn, cbWrite);
    }
}


static void pspDevSmuFwRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVSMU pThis = (PPSPDEVSMU)pvUser;

    memcpy(pvDst, &pThis->abFw[offSmn], cbRead);
}


static void pspDevSmuFwWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVSMU pThis = (PPSPDEVSMU)pvUser;

    memcpy(&pThis->abFw[offSmn], pvVal, cbWrite);
}


static int pspDevSmuInit(PPSPDEV pDev)
{
    PPSPDEVSMU pThis = (PPSPDEVSMU)&pDev->abInstance[0];

    pThis->u32RegMsgSts = 0x1; /* Ready for message bit? */

    int rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x03b10034, 4,
                                    pspDevSmuRead, NULL, pThis,
                                    &pThis->hSmn);
    if (!rc) /* The off chip Ryzen bootloader waits for the interrupt ready flag. */
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x03b10028, 4,
                                    pspDevSmuRead, NULL, pThis,
                                    &pThis->hSmnIntrRdy);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x03b10700, 6 * sizeof(uint32_t),
                                    pspDevSmuMsgRead, pspDevSmuMsgWrite, pThis,
                                    &pThis->hSmnMsg);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x03c00000, sizeof(pThis->abFw),
                                    pspDevSmuFwRead, pspDevSmuFwWrite, pThis,
                                    &pThis->hSmnFw);
    return rc;
}


static void pspDevSmuDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegSmu =
{
    /** pszName */
    "smu",
    /** pszDesc */
    "SMU device",
    /** cbInstance */
    sizeof(PSPDEVSMU),
    /** pfnInit */
    pspDevSmuInit,
    /** pfnDestruct */
    pspDevSmuDestruct,
};

