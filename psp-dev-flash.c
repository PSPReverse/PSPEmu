/** @file
 * PSP Emulator - Flash ROM device attached to SMN.
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
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <poll.h>
#include <sys/ioctl.h>

#include <pthread.h>

#include <common/cdefs.h>

#include <psp-devs.h>


/**
 * Request header sent over the network.
 */
typedef struct REQHDR
{
    /** Magic for the header. */
    uint32_t                u32Magic;
    /** Command ID 0 = read, 1 = write. */
    uint32_t                u32Cmd;
    /** Start address to access. */
    uint32_t                u32AddrStart;
    /** Number of bytes for the transfer. */
    uint32_t                cbXfer;
} REQHDR;


#define REQHDR_MAGIC 0xebadc0de


/**
 * EM100 emulation state.
 */
typedef struct EM100EMU
{
    /** Flag whether it should be running. */
    bool                    fRunning;
    /** The port to listen on. */
    uint16_t                uPort;
    /** The thread which handles the network I/O. */
    pthread_t               hThrdIo;
    /** Flash image pointer. */
    void                    *pvFlash;
    /** Size of the flash. */
    size_t                  cbFlash;
} EM100EMU;
/** Pointer to the EM100 emulation state. */
typedef EM100EMU *PEM100EMU;


/**
 * Flash device instance data.
 */
typedef struct PSPDEVFLASH
{
    /** Device instance pointer. */
    PPSPDEV                     pDev;
    /** SMN region handle. */
    PSPIOMREGIONHANDLE          hSmn;
    /** The EM100 flash emulation state if enabled. */
    PEM100EMU                   pEm100;
} PSPDEVFLASH;
/** Pointer to the device instance data. */
typedef PSPDEVFLASH *PPSPDEVFLASH;



/**
 * I/O loop for a single connection.
 *
 * @returns Status code.
 * @param   pThis                   The EM100 network emulation state.
 * @param   iFdCon                  File descriptor of the socket.
 */
static int pspEm100ConIoLoop(PEM100EMU pThis, int iFdCon)
{
    int rc = 0;
    void *pvScratch = NULL;
    size_t cbScratch = 0;

    do
    {
        /* Receive the header first. */
        REQHDR Req;
        ssize_t cbRecv = recv(iFdCon, &Req, sizeof(Req), 0);
        if (   cbRecv == sizeof(Req)
            && Req.u32Magic == REQHDR_MAGIC)
        {
            if (cbScratch < Req.cbXfer)
            {
                void *pvNew = realloc(pvScratch, Req.cbXfer);
                if (pvNew)
                {
                    pvScratch = pvNew;
                    cbScratch = Req.cbXfer;
                }
            }

            if (cbScratch >= Req.cbXfer)
            {
                int rcReq = 0;

                if (Req.u32Cmd == 1)
                {
                    /* Receive the data to write. */
                    cbRecv = recv(iFdCon, pvScratch, Req.cbXfer, 0);
                    if (cbRecv == Req.cbXfer)
                        memcpy((uint8_t *)pThis->pvFlash + Req.u32AddrStart, pvScratch, Req.cbXfer);
                    else
                        rc = -1;
                }
                else
                    memcpy(pvScratch, (uint8_t *)pThis->pvFlash + Req.u32AddrStart, Req.cbXfer);

                /* Send response and optional data. */
                int32_t rcResp = 0;
                ssize_t cbSend = send(iFdCon, &rcResp, sizeof(rcResp), 0);
                if (cbSend == sizeof(rcResp))
                {
                    if (   Req.u32Cmd == 0
                        && rcResp == 0)
                    {
                        /* Send payload on successful read. */
                        cbSend = send(iFdCon, pvScratch, Req.cbXfer, 0);
                        if (cbSend != Req.cbXfer)
                            rc = -1;
                    }
                }
                else
                    rc = -1;
            }
            else
                rc = -1;
        }
        else
            rc = -1;
    } while (!rc);

    if (pvScratch)
        free(pvScratch);
    close(iFdCon);
    return rc;
}


/**
 * The EM100 network emulation thread worker.
 *
 * @returns Opaque return value.
 * @param   pvUser                  Opaque user data given during thread creation.
 */
static void *pspEm100IoThread(void *pvUser)
{
    int rc = 0;
    PEM100EMU pThis = (PEM100EMU)pvUser;

    while (   pThis->fRunning
           && !rc)
    {
        int iFdListening = socket(AF_INET, SOCK_STREAM, 0);
        if (iFdListening > -1)
        {
            struct sockaddr_in SockAddr;

            memset(&SockAddr, 0, sizeof(SockAddr));
            SockAddr.sin_family      = AF_INET;
            SockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
            SockAddr.sin_port        = htons(pThis->uPort);
            int rcPsx = bind(iFdListening, (struct sockaddr *)&SockAddr, sizeof(SockAddr));
            if (!rcPsx)
            {
                printf("EM100: Waiting for incoming connection...\n");
                rcPsx = listen(iFdListening, 1);
                if (!rcPsx)
                {
                    int iFdCon = accept(iFdListening, (struct sockaddr *)NULL, NULL);
                    if (iFdCon == -1)
                        rc = -1;
                    else
                    {
                        printf("EM100: Connected, entering I/O loop\n");
                        rc = pspEm100ConIoLoop(pThis, iFdCon);
                        if (rc < 0)
                        {
                            printf("EM100: Network I/O loop failed\n");
                            rc = -1;
                        }
                    }
                }
                else
                    rc = -1;
            }
            else
                rc = -1;

            close(iFdListening);
        }
        else
            break;
    }

    return NULL;
}


/**
 * Create a EM100 network emulation state.
 *
 * @returns Status code.
 * @param   ppEm100                 Where to store the pointer to the EM100 state on success.
 * @param   uPort                   The network port to listen on.
 * @param   pvFlash                 The flash image pointer.
 * @param   cbFlash                 Size of the flash image in bytes.
 */
static int pspEm100EmuCreate(PEM100EMU *ppEm100, uint16_t uPort, void *pvFlash, size_t cbFlash)
{
    int rc = 0;
    PEM100EMU pThis = calloc(1, sizeof(*pThis));
    if (pThis)
    {
        pThis->fRunning = true;
        pThis->uPort    = uPort;
        pThis->pvFlash  = pvFlash;
        pThis->cbFlash  = cbFlash;

        /* Spin up the network I/O thread. */
        int rcThrd = pthread_create(&pThis->hThrdIo, NULL, pspEm100IoThread, pThis);
        if (!rcThrd)
        {
            *ppEm100 = pThis;
            return 0;
        }
        else
            rc = -1;

        free(pThis);
    }
    else
        rc = -1;

    return rc;
}


/**
 * Destroys the given EM100 network emulation state.
 *
 * @returns nothing.
 * @param   pEm100                  The emulation state to destroy.
 */
static void pspEm100EmuDestroy(PEM100EMU pEm100)
{
    pEm100->fRunning = false;
    /** @todo Poke thread. */
    pthread_join(pEm100->hThrdIo, NULL);
    free(pEm100);
}


static void pspDevFlashRead(SMNADDR offSmn, size_t cbRead, void *pvDst, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    if (offSmn + cbRead <= pThis->pDev->pCfg->cbFlashRom)
        memcpy(pvDst, (uint8_t *)pThis->pDev->pCfg->pvFlashRom + offSmn, cbRead);
    else
        printf("%s: ATTEMPTED out of bounds read from offSmn=%#x cbRead=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbRead);
}


static void pspDevFlashWrite(SMNADDR offSmn, size_t cbWrite, const void *pvVal, void *pvUser)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)pvUser;

    if (pThis->pEm100)
    {
        if (offSmn + cbWrite <= pThis->pDev->pCfg->cbFlashRom)
            memcpy((uint8_t *)pThis->pDev->pCfg->pvFlashRom + offSmn, pvVal, cbWrite);
        else
            printf("%s: ATTEMPTED out of bounds write from offSmn=%#x cbWrite=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbWrite);
    }
    else
        printf("%s: ATTEMPTED write access to offSmn=%#x cbWrite=%zu -> IGNORED\n", __FUNCTION__, offSmn, cbWrite);
}


static int pspDevFlashInit(PPSPDEV pDev)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)&pDev->abInstance[0];

    pThis->pDev = pDev;

    SMNADDR SmnAddrFlash = pDev->pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN2 ? 0x44000000 : 0x0a000000;
    int rc = PSPEmuIoMgrSmnRegister(pDev->hIoMgr, SmnAddrFlash, pDev->pCfg->cbFlashRom,
                                    pspDevFlashRead, pspDevFlashWrite, pThis,
                                    &pThis->hSmn);
    if (   !rc
        && pDev->pCfg->uEm100FlashEmuPort)
        rc = pspEm100EmuCreate(&pThis->pEm100, pDev->pCfg->uEm100FlashEmuPort,
                               pDev->pCfg->pvFlashRom, pDev->pCfg->cbFlashRom);
    return rc;
}


static void pspDevFlashDestruct(PPSPDEV pDev)
{
    PPSPDEVFLASH pThis = (PPSPDEVFLASH)&pDev->abInstance[0];

    if (pThis->pEm100)
        pspEm100EmuDestroy(pThis->pEm100);
}


/**
 * Device registration structure.
 */
const PSPDEVREG g_DevRegFlash =
{
    /** pszName */
    "flash",
    /** pszDesc */
    "Flash device",
    /** cbInstance */
    sizeof(PSPDEVFLASH),
    /** pfnInit */
    pspDevFlashInit,
    /** pfnDestruct */
    pspDevFlashDestruct,
};

