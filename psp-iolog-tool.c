/** @file
 * PSP Emulator - I/O log dump tool.
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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <common/cdefs.h>
#include <common/status.h>

#include <psp-iolog.h>


/*********************************************************************************************************************************
*   Global Variables                                                                                                             *
*********************************************************************************************************************************/

/**
 * Available options for PSPEmu.
 */
static struct option g_aOptions[] =
{
    {"iolog-input",                  required_argument, 0, 'i'},

    {"help",                         no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

/**
 * Dumps the given I/O event.
 *
 * @returns nothing.
 * @param   pIoEvt                  The I/O event to dump.
 */
static void pspIoLogToolEvtDump(PCPSPIOLOGRDREVT pIoEvt)
{
    const char *pszAddrSpace = "<INVALID>"; 
    uint64_t uAddr;

    switch (pIoEvt->enmAddrSpace)
    {
        case PSPADDRSPACE_SMN:
            uAddr = pIoEvt->u.SmnAddr;
            pszAddrSpace = "SMN     ";
            break;
        case PSPADDRSPACE_PSP:
            uAddr = pIoEvt->u.PspAddrMmio;
            pszAddrSpace = "PSP/MMIO";
            break;
        case PSPADDRSPACE_X86:
            uAddr = pIoEvt->u.PhysX86Addr;
            pszAddrSpace = "X86     ";
            break;
    }

    fprintf(stdout, "%s %16s %#16lx %u",
            pszAddrSpace,
            pIoEvt->fWrite ? "WRITE" : "READ ",
            uAddr, pIoEvt->cbAcc);

    if (   pIoEvt->cbAcc == 1
        || pIoEvt->cbAcc == 2
        || pIoEvt->cbAcc == 4
        || pIoEvt->cbAcc == 8)
    {
        uint64_t uVal = 0;

        switch (pIoEvt->cbAcc)
        {
            case 1:
                uVal = *(const uint8_t *)pIoEvt->pvData;
                break;
            case 2:
                uVal = *(const uint16_t *)pIoEvt->pvData;
                break;
            case 4:
                uVal = *(const uint32_t *)pIoEvt->pvData;
                break;
            case 8:
                uVal = *(const uint64_t *)pIoEvt->pvData;
                break;
            default: /* Paranoia */
                return;
        }

        fprintf(stdout, " 0x%.*lx", pIoEvt->cbAcc * 2, uVal);
    }

    fprintf(stdout, "\n");
}


int main(int argc, char *argv[])
{
    int ch = 0;
    int idxOption = 0;
    const char *pszFilename = NULL;

    while ((ch = getopt_long (argc, argv, "Hvi:", &g_aOptions[0], &idxOption)) != -1)
    {
        switch (ch)
        {
            case 'h':
            case 'H':
                printf("%s: I/O log dump tool\n"
                       "    --iolog-input <path/to/iolog>\n",
                       argv[0]);
                return 0;
            case 'i':
                pszFilename = optarg;
                break;

            default:
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                return 1;
        }
    }

    if (!pszFilename)
    {
        fprintf(stderr, "A filepath to the I/O log is required!\n");
        return 1;
    }

    PSPIOLOGRDR hIoLogRdr = NULL;
    int rc = PSPEmuIoLogRdrCreate(&hIoLogRdr, pszFilename);
    if (STS_SUCCESS(rc))
    {
        do
        {
            PCPSPIOLOGRDREVT pIoEvt = NULL;
            rc = PSPEmuIoLogRdrEvtQueryNext(hIoLogRdr, &pIoEvt);
            if (STS_SUCCESS(rc))
            {
                pspIoLogToolEvtDump(pIoEvt);
                PSPEmuIoLogRdrEvtFree(hIoLogRdr, pIoEvt);
            }
            else
                fprintf(stderr, "Reading I/O event failed with %d\n", rc);
        } while (STS_SUCCESS(rc));

        PSPEmuIoLogRdrDestroy(hIoLogRdr);
    }
    else
        fprintf(stderr, "The file '%s' could not be opened\n", pszFilename);

    return 0;
}

