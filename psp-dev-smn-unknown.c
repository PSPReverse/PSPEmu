/** @file
 * PSP Emulator - Unknown SMN device residing at 0x0005e000.
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

#include <psp-devs.h>


/**
 * Unknown device instance data.
 */
typedef struct PSPDEVUNK
{
    /** 0x0005e000 register handle. */
    PSPIOMREGIONHANDLE          hSmn0x0005e000;
    /** 0x0005d0cc register handle. */
    PSPIOMREGIONHANDLE          hSmn0x0005d0cc;
    /** 0x01025034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01025034;
    /** 0x01004034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01004034;
    /** 0x01003034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01003034;
    /** 0x18080064 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x18080064;
    /** 0x18480064 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x18480064;
    /** 0x01018034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01018034;
    /** 0x0102e034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0102e034;
    /** 0x01030034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01030034;
    /** 0x01046034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01046034;
    /** 0x01047034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01047034;
    /** 0x0106c034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0106c034;
    /** 0x0106d034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0106d034;
    /** 0x0106e034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0106e034;
    /** 0x01080034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01080034;
    /** 0x01081034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01081034;
    /** 0x01096034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01096034;
    /** 0x01097034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01097034;
    /** 0x010a8034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x010a8034;
    /** 0x010d8034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x010d8034;
    /** 0x0005a088 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0005a088;
} PSPDEVUNK;
/** Pointer to the device instance data. */
typedef PSPDEVUNK *PPSPDEVUNK;


static void pspDevUnkSmnRead0x0005e000(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offSmn=%#x cbRead=%zu\n", __FUNCTION__, offSmn, cbRead);

    switch (offSmn)
    {
        case 0x0:
            /* The on chip bootloader waits for bit 0 to go 1. */
            *(uint32_t *)pvVal = 0x1;
            break;
    }
}

static void pspDevUnkSmnRead0x0005d0cc(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offSmn=%#x cbRead=%zu\n", __FUNCTION__, offSmn, cbRead);

    switch (offSmn)
    {
        case 0x0:
            /* The off chip bootloader wants bit 5 to be one, otherwise it returns an error
             * dubbed PSPSTATUS_CCX_SEC_BISI_EN_NOT_SET_IN_FUSE_RAM. */
            *(uint32_t *)pvVal = BIT(5);
            break;
    }
}

static void pspDevUnkSmnRead0x01025034(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offSmn=%#x cbRead=%zu\n", __FUNCTION__, offSmn, cbRead);

    switch (offSmn)
    {
        case 0x0:
            /* Read by the on chip bootloader and acted upon. */
            *(uint32_t *)pvVal = 0x1e113;
            break;
    }
}

static void pspDevUnkSmnRead0x01004034(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offSmn=%#x cbRead=%zu\n", __FUNCTION__, offSmn, cbRead);

    switch (offSmn)
    {
        case 0x0:
            /* Read by the on chip bootloader and acted upon. */
            *(uint32_t *)pvVal = 0x1e112;
            break;
    }
}

static void pspDevUnkSmnRead0x0102e034(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offSmn=%#x cbRead=%zu\n", __FUNCTION__, offSmn, cbRead);

    switch (offSmn)
    {
        case 0x0:
            /* Read by the on chip bootloader and acted upon. */
            *(uint32_t *)pvVal = 0x1e312;
            break;
    }
}

static void pspDevUnkSmnRead0x01046034(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offSmn=%#x cbRead=%zu\n", __FUNCTION__, offSmn, cbRead);

    switch (offSmn)
    {
        case 0x0:
            /* Read by the on chip bootloader and acted upon. */
            *(uint32_t *)pvVal = 0x1e103;
            break;
    }
}


static void pspDevUnkSmnRead0x18080064(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    printf("%s: offSmn=%#x cbRead=%zu\n", __FUNCTION__, offSmn, cbRead);

    switch (offSmn)
    {
        case 0x0:
            /* The on chip bootloader waits for bit 10 to to get set. */
            *(uint32_t *)pvVal = BIT(10);
            break;
    }
}

static void pspDevUnkSmnWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    printf("%s: offSmn=%#x cbWrite=%zu\n", __FUNCTION__, offSmn, cbWrite);

    switch (cbWrite)
    {
        case 4:
            printf("    u32Val=%#x\n", *(uint32_t *)pvVal);
            break;
    }
}


static int pspDevUnkInit(PPSPDEV pDev)
{
    PPSPDEVUNK pThis = (PPSPDEVUNK)&pDev->abInstance[0];

    int rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005e000, 4,
                                    pspDevUnkSmnRead0x0005e000, pspDevUnkSmnWrite, pThis,
                                    &pThis->hSmn0x0005e000);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005d0cc, 4,
                                    pspDevUnkSmnRead0x0005d0cc, pspDevUnkSmnWrite, pThis,
                                    &pThis->hSmn0x0005d0cc);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01025034, 4,
                                    pspDevUnkSmnRead0x01025034, NULL, pThis,
                                    &pThis->hSmn0x01025034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01004034, 4,
                                    pspDevUnkSmnRead0x01004034, NULL, pThis,
                                    &pThis->hSmn0x01004034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01003034, 4,
                                    pspDevUnkSmnRead0x01004034, NULL, pThis,
                                    &pThis->hSmn0x01003034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x18080064, 4,
                                    pspDevUnkSmnRead0x18080064, NULL, pThis,
                                    &pThis->hSmn0x18080064);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x18480064, 4,
                                    pspDevUnkSmnRead0x18080064, NULL, pThis,
                                    &pThis->hSmn0x18480064);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01018034, 4,
                                    pspDevUnkSmnRead0x01025034, NULL, pThis,
                                    &pThis->hSmn0x18480064);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0102e034, 4,
                                    pspDevUnkSmnRead0x0102e034, NULL, pThis,
                                    &pThis->hSmn0x0102e034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01030034, 4,
                                    pspDevUnkSmnRead0x0102e034, NULL, pThis,
                                    &pThis->hSmn0x01030034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01046034, 4,
                                    pspDevUnkSmnRead0x01046034, NULL, pThis,
                                    &pThis->hSmn0x01046034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01047034, 4,
                                    pspDevUnkSmnRead0x01046034, NULL, pThis,
                                    &pThis->hSmn0x01047034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0106c034, 4,
                                    pspDevUnkSmnRead0x01025034, NULL, pThis,
                                    &pThis->hSmn0x0106c034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0106d034, 4,
                                    pspDevUnkSmnRead0x01025034, NULL, pThis,
                                    &pThis->hSmn0x0106d034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0106e034, 4,
                                    pspDevUnkSmnRead0x0102e034, NULL, pThis,
                                    &pThis->hSmn0x0106e034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01080034, 4,
                                    pspDevUnkSmnRead0x01025034, NULL, pThis,
                                    &pThis->hSmn0x01080034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01081034, 4,
                                    pspDevUnkSmnRead0x01025034, NULL, pThis,
                                    &pThis->hSmn0x01081034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01096034, 4,
                                    pspDevUnkSmnRead0x0102e034, NULL, pThis,
                                    &pThis->hSmn0x01096034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01097034, 4,
                                    pspDevUnkSmnRead0x0102e034, NULL, pThis,
                                    &pThis->hSmn0x01097034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x010a8034, 4,
                                    pspDevUnkSmnRead0x0102e034, NULL, pThis,
                                    &pThis->hSmn0x010a8034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x010d8034, 4,
                                    pspDevUnkSmnRead0x0102e034, NULL, pThis,
                                    &pThis->hSmn0x010d8034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005a088, 4,
                                    pspDevUnkSmnRead0x0005e000, NULL, pThis,
                                    &pThis->hSmn0x0005a088);

    return rc;
}


static void pspDevUnkDestruct(PPSPDEV pDev)
{
    /* Nothing to do so far. */
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegSmnUnk =
{
    /** pszName */
    "smn-unknown",
    /** pszDesc */
    "Unknown SMN registers",
    /** cbInstance */
    sizeof(PSPDEVUNK),
    /** pfnInit */
    pspDevUnkInit,
    /** pfnDestruct */
    pspDevUnkDestruct,
};

