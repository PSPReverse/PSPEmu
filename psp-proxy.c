/** @file
 * PSP Emulator - CCD API.
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
#include <common/types.h>
#include <common/cdefs.h>

#include <psp-proxy.h>


/**
 * PSP MMIO blacklist descriptor.
 */
typedef struct PSPMMIOBLACKLISTDESC
{
    /** MMIO address being blacklisted. */
    PSPADDR                         PspAddrMmio;
    /** Access size, 0 means size doesn't matter. */
    size_t                          cbAcc;
    /** Flag whether writes are blacklisted. */
    bool                            fWrites;
    /** Flag whether reads are blacklisted. */
    bool                            fReads;
    /** Value to return on reads if blacklisted. */
    uint32_t                        u32ValRead;
} PSPMMIOBLACKLISTDESC;
/** Pointer to a blacklist descriptor. */
typedef PSPMMIOBLACKLISTDESC *PPSPMMIOBLACKLISTDESC;
/** Pointer to a const blacklist descriptor. */
typedef const PSPMMIOBLACKLISTDESC *PCPSPMMIOBLACKLISTDESC;


/**
 * PSP SMN blacklist descriptor.
 */
typedef struct PSPSMNBLACKLISTDESC
{
    /** SMN address being blacklisted. */
    SMNADDR                         SmnAddr;
    /** Access size, 0 means size doesn't matter. */
    size_t                          cbAcc;
    /** Flag whether writes are blacklisted. */
    bool                            fWrites;
    /** Flag whether reads are blacklisted. */
    bool                            fReads;
    /** Value to return on reads if blacklisted. */
    uint32_t                        u32ValRead;
} PSPSMNBLACKLISTDESC;
/** Pointer to a blacklist descriptor. */
typedef PSPSMNBLACKLISTDESC *PPSPSMNBLACKLISTDESC;
/** Pointer to a const blacklist descriptor. */
typedef const PSPSMNBLACKLISTDESC *PCPSPSMNBLACKLISTDESC;


/**
 * MMIO address blacklisted for the Zen on chip bootloader.
 */
static const PSPMMIOBLACKLISTDESC g_aMmioBlacklistedZenOnChip[] =
{
     { 0x320001c, 0, true, false, 0 } /* Writing hangs the proxy stub. */
};


/**
 * SMN address blacklisted for the Zen off chip bootloader.
 */
static const PSPSMNBLACKLISTDESC g_aSmnBlacklistedZenOffChip[] =
{
     { 0x00000c00, 0, true, true, 0 }, /* Reading hangs the proxy stub. */
     { 0x00000c0c, 0, true, true, 0 }  /* Reading hangs the proxy stub. */
};


/**
 * Read helper.
 *
 * @returns nothing.
 * @param   pvDst                   Where to store the value.
 * @param   u32Val                  The value to store.
 * @param   cbAcc                   Access width.
 */
static void pspProxyRead(void *pvDst, uint32_t u32Val, size_t cbAcc)
{
    switch (cbAcc)
    {
        case 1:
            *(uint8_t *)pvDst = (uint8_t)u32Val;
            break;
        case 2:
            *(uint16_t *)pvDst = (uint16_t)u32Val;
            break;
        case 4:
            *(uint32_t *)pvDst = u32Val;
            break;
    }
}


bool PSPProxyIsMmioAccessAllowed(PSPADDR PspAddrMmio, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                 PCPSPEMUCFG pCfg, void *pvReadVal)
{
    if (   (   enmStage == PSPPROXYBLSTAGE_ON_CHIP
            || enmStage == PSPPROXYBLSTAGE_UNKNOWN)
        && pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN)
    {
        for (uint32_t i = 0; i < ELEMENTS(g_aMmioBlacklistedZenOnChip); i++)
        {
            PCPSPMMIOBLACKLISTDESC pDesc = &g_aMmioBlacklistedZenOnChip[i];

            if (pDesc->PspAddrMmio == PspAddrMmio)
            {
                if (   (   pDesc->cbAcc == cbAcc
                        || pDesc->cbAcc == 0)
                    && (   (   fWrite
                            && pDesc->fWrites)
                        || (   !fWrite
                            && pDesc->fReads)))
                {
                    /* On a read return the value to be used instead. */
                    if (!fWrite)
                        pspProxyRead(pvReadVal, pDesc->u32ValRead, cbAcc);
                    return false;
                }

                /* Other checks failed so we can stop searching here (every address only has one descriptor). */
                break;
            }
        }
    }

    return true;
}


bool PSPProxyIsSmnAccessAllowed(SMNADDR SmnAddr, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                PCPSPEMUCFG pCfg, void *pvReadVal)
{
    if (   (   enmStage == PSPPROXYBLSTAGE_OFF_CHIP
            || enmStage == PSPPROXYBLSTAGE_UNKNOWN)
        && pCfg->enmMicroArch == PSPEMUMICROARCH_ZEN)
    {
        for (uint32_t i = 0; i < ELEMENTS(g_aSmnBlacklistedZenOffChip); i++)
        {
            PCPSPSMNBLACKLISTDESC pDesc = &g_aSmnBlacklistedZenOffChip[i];

            if (pDesc->SmnAddr == SmnAddr)
            {
                if (   (   pDesc->cbAcc == cbAcc
                        || pDesc->cbAcc == 0)
                    && (   (   fWrite
                            && pDesc->fWrites)
                        || (   !fWrite
                            && pDesc->fReads)))
                {
                    /* On a read return the value to be used instead. */
                    if (!fWrite)
                        pspProxyRead(pvReadVal, pDesc->u32ValRead, cbAcc);
                    return false;
                }

                /* Other checks failed so we can stop searching here (every address only has one descriptor). */
                break;
            }
        }
    }

    return true;
}


bool PSPProxyIsX86AccessAllowed(X86PADDR PhysX86Addr, size_t cbAcc, bool fWrite, PSPPROXYBLSTAGE enmStage,
                                PCPSPEMUCFG pCfg, void *pvReadVal)
{
    return true;
}

