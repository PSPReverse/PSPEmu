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
    /** 0x0005a098 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0005a098;
    /** 0x01010034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01010034;
    /** 0x01002034 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x01002034;
    /** 0x0005b310 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0005b310;
    /** 0x0005bb10 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0005bb10;
    /** 0x0005c310 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0005c310;
    /** 0x0005fb10 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x0005fb10;

    /** 0x51050 region handle. */
    PSPIOMREGIONHANDLE          hSmn0x51050;
    /** 0x5105c region handle. */
    PSPIOMREGIONHANDLE          hSmn0x5105c;

    /** 0x5a078 register handle. */
    PSPIOMREGIONHANDLE          hSmn0x5a078;
    /** 0x5a86c register handle. */
    PSPIOMREGIONHANDLE          hSmn0x5a86c;
    /** 0x5a870 register handle. */
    PSPIOMREGIONHANDLE          hSmn0x5a870;
    /** 0x501ec register handle. */
    PSPIOMREGIONHANDLE          hSmn0x501ec;
    /** 0x5b304 register handle. */
    PSPIOMREGIONHANDLE          hSmn0x5b304;
} PSPDEVUNK;
/** Pointer to the device instance data. */
typedef PSPDEVUNK *PPSPDEVUNK;


static void pspDevUnkSmnRead0x0005e000(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
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
    switch (offSmn)
    {
        case 0x0:
            /* The on chip bootloader waits for bit 9 and 10 to become set. */
            *(uint32_t *)pvVal = BIT(10) | BIT(9);
            break;
    }
}

static void pspDevUnkSmnRead0x01002034(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    switch (offSmn)
    {
        case 0x0:
            /* The Ryzen on chip bootloader waits for bit 13 to become set. */
            *(uint32_t *)pvVal = BIT(13);
            break;
    }
}

static void pspDevUnkSmnRead0x0005b310(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    switch (offSmn)
    {
        case 0x0:
            /* The Ryzen on chip bootloader waits for bit 4 to become set. */
            *(uint32_t *)pvVal = BIT(4);
            break;
    }
}

static void pspDevUnkSmnRead0x51050(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
#if 0
    *(uint32_t *)pvVal = 0x5a335a33; /* Magic to enable debug logging through x86 port 80h. */
#else
    *(uint32_t *)pvVal = 0xb1aab1aa; /* Enables pre-silicon environment. */
#endif
}

static void pspDevUnkSmnRead0x5105c(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0xc001c001; /* Magic to make ABL1 go further. */
}

static void pspDevUnkSmnRead0x5a86c(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0x00800f12; /* Magic read from an Epyc system read by the ABL1 stage. */
}

static void pspDevUnkSmnRead0x501ec(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0xffffffff; /* Hopefully disables a few checks for our simulation environment. */
}

static void pspDevUnkSmnRead0x5a870(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0x1; /* Bitmask of cores being present. */
}

static void pspDevUnkSmnRead0x5b304(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0xffffffff;
}

static void pspDevUnkSmnRead0x5c14c(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0x100; /* Zen2 Ryzen on chip BL waits for it. */
}

static void pspDevUnkSmnRead0x5a304(SMNADDR offSmn, size_t cbRead, void *pvVal, void *pvUser)
{
    *(uint32_t *)pvVal = 0x1; /* Zen2 Ryzen on chip BL waits for it. */
}

static int pspDevUnkInit(PPSPDEV pDev)
{
    PPSPDEVUNK pThis = (PPSPDEVUNK)&pDev->abInstance[0];

    int rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005e000, 4,
                                    pspDevUnkSmnRead0x0005e000, NULL, pThis,
                                    &pThis->hSmn0x0005e000);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005d0cc, 4,
                                    pspDevUnkSmnRead0x0005d0cc, NULL, pThis,
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

    /* For the Ryzen on chip bootloader, the actual value is not known so far. */
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01010034, 4,
                                    pspDevUnkSmnRead0x01025034, NULL, pThis,
                                    &pThis->hSmn0x01010034);
    /* The Ryzen on chip bootloader waits for the first bit to become 1. */
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005a098, 4,
                                    pspDevUnkSmnRead0x0005e000, NULL, pThis,
                                    &pThis->hSmn0x0005a098);
    /* The Ryzen on chip bootloader waits for bit 13 to become one. */
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x01002034, 4,
                                    pspDevUnkSmnRead0x01002034, NULL, pThis,
                                    &pThis->hSmn0x01002034);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005b310, 4,
                                    pspDevUnkSmnRead0x0005b310, NULL, pThis,
                                    &pThis->hSmn0x0005b310);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005bb10, 4,
                                    pspDevUnkSmnRead0x0005b310, NULL, pThis,
                                    &pThis->hSmn0x0005bb10);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005c310, 4,
                                    pspDevUnkSmnRead0x0005b310, NULL, pThis,
                                    &pThis->hSmn0x0005c310);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x0005fb10, 4,
                                    pspDevUnkSmnRead0x0005b310, NULL, pThis,
                                    &pThis->hSmn0x0005fb10);

    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x51050, 4,
                                    pspDevUnkSmnRead0x51050, NULL, pThis,
                                    &pThis->hSmn0x51050);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x5105c, 4,
                                    pspDevUnkSmnRead0x5105c, NULL, pThis,
                                    &pThis->hSmn0x5105c);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x5a86c, 4,
                                    pspDevUnkSmnRead0x5a86c, NULL, pThis,
                                    &pThis->hSmn0x5a86c);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x501ec, 4,
                                    pspDevUnkSmnRead0x501ec, NULL, pThis,
                                    &pThis->hSmn0x501ec);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x5a870, 4,
                                    pspDevUnkSmnRead0x5a870, NULL, pThis,
                                    &pThis->hSmn0x5a870);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x5b304, 4,
                                    pspDevUnkSmnRead0x5b304, NULL, pThis,
                                    &pThis->hSmn0x5b304);
    PSPIOMREGIONHANDLE hSmn;
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x5bb04, 4,
                                    pspDevUnkSmnRead0x5b304, NULL, pThis,
                                    &hSmn);

    /* For the Zen2 Ryzen on chip bootloader, the actual value is not known so far. */
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x9025034, 4,
                                    pspDevUnkSmnRead0x01025034, NULL, pThis,
                                    &hSmn);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x5c14c, 4,
                                    pspDevUnkSmnRead0x5c14c, NULL, pThis,
                                    &hSmn);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x5c94c, 4,
                                    pspDevUnkSmnRead0x5c14c, NULL, pThis,
                                    &hSmn);
    if (!rc)
        rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, 0x5a304, 4,
                                    pspDevUnkSmnRead0x5a304, NULL, pThis,
                                    &hSmn);

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
    /** pfnReset */
    NULL
};

