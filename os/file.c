/** @file
 * PSP Emulator - OS abstraction for file accesses.
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
#include <stdio.h>
#include <errno.h>

#include <common/status.h>

#include <os/file.h>


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

int OSFileLoadAll(const char *pszFilename, void **ppv, size_t *pcb)
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
                        return STS_INF_SUCCESS;
                    }

                    free(pvFw);
                    rc = STS_ERR_INVALID_PARAMETER;
                }
                else
                    rc = STS_ERR_INVALID_PARAMETER;
            }
            else
                rc = STS_ERR_INVALID_PARAMETER;
        }
        else
            rc = STS_ERR_INVALID_PARAMETER;

        fclose(pFwFile);
    }
    else
        rc = STS_ERR_INVALID_PARAMETER;

    return rc;
}


int OSFileLoadAllFree(void *pv, size_t cb)
{
    free(pv);
    return STS_INF_SUCCESS;
}

