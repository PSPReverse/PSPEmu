/** @file
 * PSP Emulator - API for handling the flash filesystem.
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
#include <string.h>

#include <common/cdefs.h>
#include <common/status.h>

#include <psp-flash.h>


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/**
 * Flash filesystem reader state.
 */
typedef struct PSPFFSINT
{
    /** Pointer to the in memory flash image. */
    const void                      *pvFlash;
    /** size of the flasg image in bytes. */
    size_t                          cbFlash;
    /** Determined flash address mask. */
    PSPFFSADDR                      FfsAddrMask;
    /** Pointer to the found FET. */
    PCPSPFFSFET                     pFet;
    /** 1st level PSP dir. */
    PCPSPFFSDIR                     pPspDirL1;
    /** 2nd level PSP dir, can be NULL. */
    PCPSPFFSDIR                     pPspDirL2;
} PSPFFSINT;
/** Pointer to a flash filesystem reader state. */
typedef PSPFFSINT *PPSPFFSINT;
/** Pointer to const flash filesystem reader state. */
typedef const PSPFFSINT *PCPSPFFSINT;


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

/**
 * Iniitalizes the given flash filesystem reader instance.
 *
 * @returns Status code.
 * @param   pThis                   The flash filesystem reader instance.
 * @param   pvFlash                 The flash image.
 * @param   cbFlash                 Size of the flash image in bytes.
 */
static int pspFlashFsInit(PPSPFFSINT pThis, const void *pvFlash, size_t cbFlash)
{
    int rc = STS_INF_SUCCESS;

    pThis->pvFlash   = pvFlash;
    pThis->cbFlash   = cbFlash;
    pThis->pFet      = NULL;
    pThis->pPspDirL1 = NULL;
    pThis->pPspDirL2 = NULL;

    /* Determine the address mask, the flash size must be a power of two. */
    switch (cbFlash)
    {
        case _1M:
            pThis->FfsAddrMask = 0xfffff;
            break;
        case 2 * _1M:
            pThis->FfsAddrMask = 0x1fffff;
            break;
        case 4 * _1M:
            pThis->FfsAddrMask = 0x3fffff;
            break;
        case 8 * _1M:
            pThis->FfsAddrMask = 0x7fffff;
            break;
        case 16 * _1M:
            pThis->FfsAddrMask = 0xffffff;
            break;
        case 32 * _1M:
            pThis->FfsAddrMask = 0xffffff;
            break;
        default:
            rc = STS_ERR_BUFFER_OVERFLOW; /** @todo Designated status code. */
    }

    return rc;
}


/**
 * Converts the given flash address to a pointer inside the in memory flash image if the address is valid.
 *
 * @returns Pointer to the memory address the given flash address points to or NULL if outside of the flash image.
 * @param   pThis                   The flash filesystem instance.
 * @param   FfsAddr                 The flash address to convert.
 * @param   pcbValid                Where to return the number of valid bytes till the end of the flash image, optional.
 */
static const void *pspFlashAddrToPtr(PPSPFFSINT pThis, PSPFFSADDR FfsAddr, size_t *pcbValid)
{
    FfsAddr &= pThis->FfsAddrMask;
    if (FfsAddr < pThis->cbFlash)
    {
        if (pcbValid)
            *pcbValid = pThis->cbFlash - FfsAddr;

        return (const uint8_t *)pThis->pvFlash + FfsAddr;
    }

    return NULL;
}


/**
 * Verifies the given FET for sanity.
 *
 * @returns Flag whether the given FET is considered sane, true if valid, false otherwise.
 * @param   pThis                   The flash filesystem instance.
 * @param   pFet                    Pointer to the FET candidate.
 */
static bool pspFlashFsFetVerify(PPSPFFSINT pThis, PCPSPFFSFET pFet)
{
    /* Should be checked already but we are paranoid here. */
    if (pFet->u32Magic != PSP_FFS_FET_MAGIC)
        return false;

    /* Just check the following addresses to be inside the flash image. */
    if (   !pspFlashAddrToPtr(pThis, pFet->FfsAddrEcRom, NULL /*pcbValid*/)
        || !pspFlashAddrToPtr(pThis, pFet->FfsAddrGecRom, NULL /*pcbValid*/)
        || !pspFlashAddrToPtr(pThis, pFet->FfsAddrUsb3Rom, NULL /*pcbValid*/))
        return false;

    /* Check that the PSP directory pointer points to what looks like a PSP direcotry. */
    size_t cbDirMax;
    PCPSPFFSDIRHDR pDir = (PCPSPFFSDIRHDR)pspFlashAddrToPtr(pThis, pFet->FfsAddrPspOrComboDir, &cbDirMax);
    if (   !pDir
        || cbDirMax < sizeof(PCPSPFFSDIRHDR))
        return false;

    /* Check directory magic. */
    if (   pDir->u32Magic != PSP_FFS_PSP_DIR_HDR_MAGIC
        && pDir->u32Magic != PSP_FFS_PSP_DIR_HDR_MAGIC_COMBO)
        return false;

    /** @todo Check remaining directory pointers. */

    return true;
}


/**
 * Tries to find the FET in the given flash image instance.
 *
 * @returns Status code.
 * @param   pThis                   The flash filesystem instance.
 */
static int pspFlashFsFetFind(PPSPFFSINT pThis)
{
    /*
     * Go through the image and try to find the FET magic.
     * This is not enough however as the magic can appear someone else,
     * we also have to verify that the addresses in there are sane (within bounds of the flash image)
     * and that the PSP directory pointers point to an actual PSP directory (verified by magic).
     */
    const uint8_t *pbFlash = (const uint8_t *)pThis->pvFlash;
    size_t cbLeft = pThis->cbFlash - sizeof(PSPFFSFET);

    /* We assume that the magic is aligned on a 32bit boundary. */
    /** @todo We assume running on little endian HW here... */
    while (cbLeft)
    {
        uint32_t u32Magic = *(const uint32_t *)pbFlash;
        if (   u32Magic == PSP_FFS_FET_MAGIC
            && pspFlashFsFetVerify(pThis, (PCPSPFFSFET)pbFlash))
        {
            pThis->pFet = (PCPSPFFSFET)pbFlash;
            return STS_INF_SUCCESS;
        }

        cbLeft  -= sizeof(u32Magic);
        pbFlash += sizeof(u32Magic);
    }

    return STS_ERR_NOT_FOUND;
}


/**
 * Verifies the given PSP directory header for sanity.
 *
 * @returns Flag whether the given PSP directory is considered sane, true if valid, false otherwise.
 * @param   pThis                   The flash filesystem instance.
 * @param   pDirHdr                 Pointer to the directory candidate header.
 * @param   cbDirMax                Maximum size of the directory until the flash image ends.
 * @param   cbDirMin                Minimum size of the directory required.
 * @param   u32Magic                The magic to validate.
 * @param   cbDirEntry              Size of a single directory entry in bytes.
 */
static bool pspFlashFsPspDirHdrVerify(PPSPFFSINT pThis, PCPSPFFSDIRHDR pDirHdr, size_t cbDirMax, size_t cbDirMin,
                                      uint32_t u32Magic, size_t cbDirEntry)
{
    /* We need at least the size of the directory header + one entry to consider the directory to be valid. */
    if (cbDirMax < cbDirMin)
        return false;

    if (pDirHdr->u32Magic != u32Magic)
        return false;

    /* No entries considiered invalid as well as exceeding the flash image space with the number of entries. */
    if (   !pDirHdr->cEntries
        || pDirHdr->cEntries > PSP_FFS_PSP_DIR_HDR_ENTRIES_MAX
        || pDirHdr->cEntries * cbDirEntry + sizeof(*pDirHdr) > cbDirMax)
        return false;

    /** @todo Fletcher checksum. */

    return true;
}


/**
 * Verifies the given PSP directory for sanity.
 *
 * @returns Flag whether the given PSP directory is considered sane, true if valid, false otherwise.
 * @param   pThis                   The flash filesystem instance.
 * @param   pDir                    Pointer to the directory candidate.
 * @param   cbDirMax                Maximum size of the directory until the flash image ends.
 * @param   fL2                     Flag whether the verification should be done for a L2 directory.
 */
static bool pspFlashFsPspDirVerify(PPSPFFSINT pThis, PCPSPFFSDIR pDir, size_t cbDirMax, bool fL2)
{
    if (!pspFlashFsPspDirHdrVerify(pThis, &pDir->Hdr, cbDirMax, sizeof(PSPFFSDIR),
                                   fL2 ? PSP_FFS_PSP_DIR_HDR_MAGIC_L2 : PSP_FFS_PSP_DIR_HDR_MAGIC,
                                   sizeof(PSPFFSDIRENTRY)))
        return false;

    /* Walk all entries and verify that they point into the flash image. */
    for (uint32_t i = 0; i < pDir->Hdr.cEntries; i++)
    {
        PCPSPFFSDIRENTRY pEntry = &pDir->aEntries[i];
        size_t cbEntryMax = 0;

        if (   pEntry->enmType != PSPFFSDIRENTRYTYPE_AMD_SOFT_FUSE_CHAIN_01
            && (   !pspFlashAddrToPtr(pThis, pEntry->FfsAddrStart, &cbEntryMax)
                || pEntry->cbEntry > cbEntryMax))
            return false;
    }

    return true;
}


/**
 * Verifies the given combo directory candidate.
 *
 * @returns Flag whether the given PSP combo directory is considered sane, true if valid, false otherwise.
 * @param   pThis                   The flash filesystem instance.
 * @param   pDirHdr                 Pointer to the combo directory candidate header.
 * @param   cbDirMax                Maximum size of the directory until the flash image ends.
 */
static bool pspFlashFsPspDirComboVerify(PPSPFFSINT pThis, PCPSPFFSDIRHDR pDirHdr, size_t cbDirMax)
{
    if (!pspFlashFsPspDirHdrVerify(pThis, pDirHdr, cbDirMax, sizeof(PSPFFSCOMBODIR),
                                   PSP_FFS_PSP_DIR_HDR_MAGIC_COMBO, sizeof(PSPFFSCOMBODIRENTRY)))
        return false;

    /* Walk all entries and verify that they point into the flash image. */
    PCPSPFFSCOMBODIR pDir = (PCPSPFFSCOMBODIR)pDirHdr;
    for (uint32_t i = 0; i < pDir->Hdr.cEntries; i++)
    {
        PCPSPFFSCOMBODIRENTRY pEntry = &pDir->aEntries[i];

        if (!pspFlashAddrToPtr(pThis, pEntry->FfsAddrPspDir, NULL))
            return false;
    }

    return true;
}


/**
 * Loads the directory structures from the given combo directory.based on the given micro architecture.
 *
 * @returns Status code.
 * @param   pThis                   The flash filesystem instance.
 * @param   pComboDirHdr            The combo directory header.
 * @param   cbDirMax                Maximum size of the combo directory in bytes.
 * @param   idPsp                   The PSP identification value to load the directories for.
 */
static int pspFlashFsPspDirComboLoad(PPSPFFSINT pThis, PCPSPFFSDIRHDR pComboDirHdr, size_t cbDirMax,
                                     uint32_t idPsp)
{
    int rc = STS_INF_SUCCESS;

    if (pspFlashFsPspDirComboVerify(pThis, pComboDirHdr, cbDirMax))
    {
        PCPSPFFSCOMBODIR pComboDir = (PCPSPFFSCOMBODIR)pComboDirHdr;

        /* Check for the entry matching the given identification value. */
        rc = STS_ERR_NOT_FOUND;
        for (uint32_t i = 0; i < pComboDir->Hdr.cEntries; i++)
        {
            if ((pComboDir->aEntries[i].idPsp & 0xffffff00) == (idPsp & 0xffffff00))
            {
                PSPFFSADDR FfsAddrPspDir = pComboDir->aEntries[0].FfsAddrPspDir;

                PCPSPFFSDIR pDirL1 = (PCPSPFFSDIR)pspFlashAddrToPtr(pThis, FfsAddrPspDir, &cbDirMax);
                if (pDirL1->Hdr.u32Magic == PSP_FFS_PSP_DIR_HDR_MAGIC)
                {
                    if (pspFlashFsPspDirVerify(pThis, pDirL1, cbDirMax, false /*fL2*/))
                    {
                        pThis->pPspDirL1 = pDirL1;
                        rc = STS_INF_SUCCESS;
                    }
                    else
                        rc = STS_ERR_BUFFER_OVERFLOW; /** @todo Designated status code. */
                }
                else
                    rc = STS_ERR_NOT_FOUND;
                break;
            }
        }
    }
    else
        rc = STS_ERR_BUFFER_OVERFLOW;

    return rc;
}


/**
 * Loads and verifies the PSP directory structures.
 *
 * @returns Status code.
 * @param   pThis                   The flash filesystem instance.
 * @param   idPsp                   The PSP identification value to load the directories for.
 */
static int pspFlashFsPspDirLoad(PPSPFFSINT pThis, uint32_t idPsp)
{
    /* This requires a valid FET. */
    if (!pThis->pFet)
        return STS_ERR_INVALID_PARAMETER;

    int rc = STS_INF_SUCCESS;
    size_t cbDirMax;
    PSPFFSADDR FfsAddrPspDir = pThis->pFet->FfsAddrPspOrComboDir; /** @todo Pre Zen systems also have another PSP directory it looks like. */
    PCPSPFFSDIR pDirL1 = (PCPSPFFSDIR)pspFlashAddrToPtr(pThis, FfsAddrPspDir, &cbDirMax);
    if (pDirL1->Hdr.u32Magic == PSP_FFS_PSP_DIR_HDR_MAGIC)
    {
        if (pspFlashFsPspDirVerify(pThis, pDirL1, cbDirMax, false /*fL2*/))
            pThis->pPspDirL1 = pDirL1;
        else
            rc = STS_ERR_BUFFER_OVERFLOW; /** @todo Designated status code. */
    }
    else if (pDirL1->Hdr.u32Magic == PSP_FFS_PSP_DIR_HDR_MAGIC_COMBO)
        rc = pspFlashFsPspDirComboLoad(pThis, &pDirL1->Hdr, cbDirMax, idPsp);
    else
        rc = STS_ERR_NOT_FOUND;

    if (STS_SUCCESS(rc))
    {
        /* Check whether we have a 2nd level directory, the address and size is already verified. */
        for (uint32_t i = 0; i <  pThis->pPspDirL1->Hdr.cEntries && STS_SUCCESS(rc); i++)
        {
            PCPSPFFSDIRENTRY pEntry = & pThis->pPspDirL1->aEntries[i];

            if (pEntry->enmType == PSPFFSDIRENTRYTYPE_PSP_DIR_L2)
            {
                PCPSPFFSDIR pDirL2 = (PCPSPFFSDIR)pspFlashAddrToPtr(pThis, pEntry->FfsAddrStart, NULL /*pcbValid*/);

                /* Verify directory, the entry size was already verified during L1 directory verification so it can be used right away. */
                if (pspFlashFsPspDirVerify(pThis, pDirL2, pEntry->cbEntry, true /*fL2*/))
                    pThis->pPspDirL2 = pDirL2;
                else
                    rc = STS_ERR_BUFFER_OVERFLOW;
                break; /* There should be only one so if we found an invalid L2 directory we also just quit with an error. */
            }
        }
    }

    return rc;
}


/**
 * Finds and returns the entry matching the given type if found for the given directory.
 *
 * @returns Status code.
 * @retval  STS_ERR_NOT_FOUND if the entry couldn't be found.
 * @param   pThis                   The flash filesystem instance.
 * @param   pDir                    The directory to look in.
 * @param   enmEntry                The entry to look for.
 * @param   ppvEntry                Where to return the start address of the entry points to in flash if found.
 * @param   pcbEntry                Where to store the entry size if found.
 */
static int pspFlashFsRdrDirQueryEntry(PPSPFFSINT pThis, PCPSPFFSDIR pDir, PSPFFSDIRENTRYTYPE enmEntry, const void **ppvEntry, size_t *pcbEntry)
{
    for (uint32_t i = 0; i < pDir->Hdr.cEntries; i++)
    {
        PCPSPFFSDIRENTRY pEntry = &pDir->aEntries[i];
        if (pEntry->enmType == enmEntry)
        {
            /* Start addresses and sizes were verified already when the directories were loaded. */
            *ppvEntry = pspFlashAddrToPtr(pThis, pEntry->FfsAddrStart, NULL /*pcbValid*/);
            *pcbEntry = pEntry->cbEntry;
            return STS_INF_SUCCESS;
        }
    }

    return STS_ERR_NOT_FOUND;
}


/**
 * Finds and returns the entry from the flash filesystem matching the given type if found.
 *
 * @returns Status code.
 * @retval  STS_ERR_NOT_FOUND if the entry couldn't be found.
 * @param   pThis                   The flash filesystem reader instance.
 * @param   enmEntry                The entry to look for.
 * @param   ppvEntry                Where to return the start address of the entry points to in flash if found.
 * @param   pcbEntry                Where to store the entry size if found.
 */
static int pspFlashFsQueryEntry(PPSPFFSINT pThis, PSPFFSDIRENTRYTYPE enmEntry, const void **ppvEntry, size_t *pcbEntry)
{
    int rc = pspFlashFsRdrDirQueryEntry(pThis, pThis->pPspDirL1, enmEntry, ppvEntry, pcbEntry);
    if (   rc == STS_ERR_NOT_FOUND
        && pThis->pPspDirL2)
        rc = pspFlashFsRdrDirQueryEntry(pThis, pThis->pPspDirL2, enmEntry, ppvEntry, pcbEntry);

    return rc;
}


int PSPFlashFsCreate(PPSPFFS phFfs, uint32_t idPsp, const void *pvFlash, size_t cbFlash)
{
    int rc = STS_INF_SUCCESS;
    PPSPFFSINT pThis = calloc(1, sizeof(*pThis));
    if (pThis)
    {
        rc = pspFlashFsInit(pThis, pvFlash, cbFlash);
        if (STS_SUCCESS(rc))
        {
            rc = pspFlashFsFetFind(pThis);
            if (STS_SUCCESS(rc))
            {
                rc = pspFlashFsPspDirLoad(pThis, idPsp);
                if (STS_SUCCESS(rc))
                {
                    *phFfs = pThis;
                    return STS_INF_SUCCESS;
                }
            }
        }

        free(pThis);
    }
    else
        rc = STS_ERR_NO_MEMORY;

    return rc;
}


void PSPFlashFsDestroy(PSPFFS hFfs)
{
    PPSPFFSINT pThis = hFfs;

    pThis->pvFlash   = NULL;
    pThis->cbFlash   = 0;
    pThis->pFet      = NULL;
    pThis->pPspDirL1 = NULL;
    pThis->pPspDirL2 = NULL;
    free(pThis);
}


int PSPFlashFsQueryL1Dir(PSPFFS hFfs, PCPSPFFSDIR *ppDirL1, size_t *pcbDirL1)
{
    PPSPFFSINT pThis = hFfs;

    *ppDirL1  = pThis->pPspDirL1;
    *pcbDirL1 = pThis->pPspDirL1->Hdr.cEntries * sizeof(PSPFFSDIRENTRY) + sizeof(PSPFFSDIRHDR);
    return STS_INF_SUCCESS;
}


int PSPFlashFsDirQuery(PSPFFS hFfs, PPSPFFSDIRHDR pDirHdr, PPSPFFSDIRENTRY paDirEntries, size_t cEntriesMax, bool fMergeL2)
{
    PPSPFFSINT pThis = hFfs;
    PCPSPFFSDIR pDirL1 = pThis->pPspDirL1;

    memset(paDirEntries, 0, cEntriesMax * sizeof(*paDirEntries)); /* Paranoia */

    if (pDirHdr)
        memcpy(pDirHdr, &pDirL1->Hdr, sizeof(pDirL1->Hdr));

    size_t cEntriesCopied = MIN(pDirL1->Hdr.cEntries, cEntriesMax);
    memcpy(paDirEntries, &pDirL1->aEntries[0], cEntriesCopied * sizeof(pDirL1->aEntries[0]));

    if (   fMergeL2
        && cEntriesCopied < cEntriesMax
        && pThis->pPspDirL2)
    {
        /* Merge the L2 directory, first the L2 directory pointer is removed and then we append as much as possible. */
        for (uint32_t i = 0; i < cEntriesCopied; i++)
        {
            if (paDirEntries[i].enmType == PSPFFSDIRENTRYTYPE_PSP_DIR_L2)
            {
                /* The last entry gets zeroed, otherwise we have to move everything one slot to the front (shouldn't happen). */
                if (i < cEntriesCopied - 1)
                    memmove(&paDirEntries[i], &paDirEntries[i + 1], (cEntriesCopied - i - 1) * sizeof(*paDirEntries));
                else
                    memset(&paDirEntries[i], 0, sizeof(paDirEntries[i]));

                cEntriesCopied--;
                break;
            }
        }

        /* Determine the space remaining for the L2 directory. */
        uint32_t idxStart = cEntriesCopied;
        PCPSPFFSDIR pDirL2 = pThis->pPspDirL2;
        cEntriesCopied = MIN(cEntriesMax - cEntriesCopied, pDirL2->Hdr.cEntries);
        memcpy(&paDirEntries[idxStart], &pDirL2->aEntries[0], cEntriesCopied * sizeof(pDirL2->aEntries[0]));

        /* We have to update the header. */
        /** @todo Fletcher checksum? */
        if (pDirHdr)
            pDirHdr->cEntries += cEntriesCopied - 1; /* The L2 directory pointer got removed. */
    }

    return STS_INF_SUCCESS;
}


int PSPFlashFsQueryEntry(PSPFFS hFfs, PSPFFSDIRENTRYTYPE enmEntry, const void **ppvEntry, size_t *pcbEntry)
{
    PPSPFFSINT pThis = hFfs;

    return pspFlashFsQueryEntry(pThis, enmEntry, ppvEntry, pcbEntry);
}

