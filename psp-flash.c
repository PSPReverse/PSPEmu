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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <psp-flash.h>

int PSPEmuFlashLoadFromFile(const char *pszFilename, void **ppv, size_t *pcb)
{
    int rc = 0;
    FILE *pFwFile = fopen(pszFilename, "rb");
    if (pFwFile)
    {
        /* Determine file size. */
        rc = fseek(pFwFile, 0, SEEK_END);
        if (!rc)
        {
            long cbFw = ftell(pFwFile);
            if (cbFw != -1)
            {
                rewind(pFwFile);

                void *pvFw = malloc(cbFw);
                if (pvFw)
                {
                    size_t cbRead = fread(pvFw, cbFw, 1, pFwFile);
                    if (cbRead == 1)
                    {
                        *ppv = pvFw;
                        *pcb = cbFw;
                        return 0;
                    }

                    free(pvFw);
                    rc = -1;
                }
                else
                    rc = -1;
            }
            else
                rc = errno;
        }
        else
            rc = errno;

        fclose(pFwFile);
    }
    else
        rc = errno;

    return rc;
}

int PSPEmuFlashFree(void *pv, size_t cb)
{
    free(pv);
    return 0;
}

int PSPEmuFlashReadEntry(uint32_t enmEntryId, void *pvFlash, size_t cbFlash, void *pvDst, size_t cbDst)
{
    return -1;
}

