/** @file
 * PSP Emulator - API for the x86 ICE (In-circuit emulator) network interface.
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
#ifndef INCLUDED_psp_x86_ice_h
#define INCLUDED_psp_x86_ice_h

#include <common/types.h>


/** Opaque PSP x86 ICE handle. */
typedef struct PSPX86ICEINT *PSPX86ICE;
/** Pointer to a PSP x86 ICE handle. */
typedef PSPX86ICE *PPSPX86ICE;


/**
 * x86 I/O port read handler.
 *
 * @returns Status code.
 * @param   hX86Ice                 The X86 ICE instance triggering the callback.
 * @param   IoPort                  The absolute I/O port to read from.
 * @param   cbRead                  Number of bytes to read.
 * @param   pvVal                   Where to store the read data.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef int (FNPSPX86ICEIOPORTREAD)(PSPX86ICE hX86Ice, uint16_t IoPort, size_t cbRead, void *pvVal, void *pvUser);
/** x86 I/O port read handler pointer. */
typedef FNPSPX86ICEIOPORTREAD *PFNPSPX86ICEIOPORTREAD;


/**
 * x86 I/O port write handler.
 *
 * @returns Status code.
 * @param   hX86Ice                 The X86 ICE instance triggering the callback.
 * @param   IoPort                  The absolute I/O port to write to.
 * @param   cbWrite                 Number of bytes to write.
 * @param   pvVal                   The data to write.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef int (FNPSPX86ICEIOPORTWRITE)(PSPX86ICE hX86Ice, uint16_t IoPort, size_t cbWrite, const void *pvVal, void *pvUser);
/** x86 I/O port write handler pointer. */
typedef FNPSPX86ICEIOPORTWRITE *PFNPSPX86ICEIOPORTWRITE;


/**
 * x86 MMIO access type.
 */
typedef enum PSPX86ICEMEMTYPE
{
    /** Invalid memory type. */
    PSPX86ICEMEMTYPE_INVALID = 0,
    /** RAM access. */
    PSPX86ICEMEMTYPE_RAM,
    /** MMIO access. */
    PSPX86ICEMEMTYPE_MMIO,
    /** Unknown memory type. */
    PSPX86ICEMEMTYPE_UNKNOWN,
    /** 32bit hack. */
    PSPX86ICEMEMTYPE_32BIT_HACK = 0x7fffffff
} PSPX86ICEMEMTYPE;


/**
 * x86 memory read handler.
 *
 * @returns Status code.
 * @param   hX86Ice                 The X86 ICE instance triggering the callback.
 * @param   PhysX86Addr             The absolute x86 physical address to read from.
 * @param   cbRead                  Number of bytes to read.
 * @param   pvVal                   Where to store the read data.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef int (FNPSPX86ICEMEMREAD)(PSPX86ICE hX86Ice, X86PADDR PhysX86Addr, PSPX86ICEMEMTYPE enmMemType, size_t cbRead, void *pvVal, void *pvUser);
/** x86 memory read handler pointer. */
typedef FNPSPX86ICEMEMREAD *PFNPSPX86ICEMEMREAD;


/**
 * x86 memory write handler.
 *
 * @returns Status code.
 * @param   hX86Ice                 The X86 ICE instance triggering the callback.
 * @param   PhysX86Addr             The absolute x86 physical address to write to.
 * @param   cbWrite                 Number of bytes to write.
 * @param   pvVal                   The data to write.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef int (FNPSPX86ICEMEMWRITE)(PSPX86ICE hX86Ice, X86PADDR PhysX86Addr, PSPX86ICEMEMTYPE enmMemType, size_t cbWrite, const void *pvVal, void *pvUser);
/** x86 memory write handler pointer. */
typedef FNPSPX86ICEMEMWRITE *PFNPSPX86ICEMEMWRITE;


/**
 * x86 MSR read handler.
 *
 * @returns Status code.
 * @param   hX86Ice                 The X86 ICE instance triggering the callback.
 * @param   idMsr                   The MSR to read.
 * @param   idKey                   The key to use ((was?) required on for some MSRs on some older AMD CPUs)
 * @param   pu64Val                 Where to store the read value.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef int (FNPSPX86ICEMSRREAD)(PSPX86ICE hX86Ice, uint32_t idMsr, uint32_t idKey, uint64_t *pu64Val, void *pvUser);
/** x86 MSR read handler pointer. */
typedef FNPSPX86ICEMSRREAD *PFNPSPX86ICEMSRREAD;


/**
 * x86 MSR write handler.
 *
 * @returns Status code.
 * @param   hX86Ice                 The X86 ICE instance triggering the callback.
 * @param   idMsr                   The MSR to write.
 * @param   idKey                   The key to use ((was?) required on for some MSRs on some older AMD CPUs)
 * @param   u64Val                  The value to write.
 * @param   pvUser                  Opaque user data passed during registration.
 */
typedef int (FNPSPX86ICEMSRWRITE)(PSPX86ICE hX86Ice, uint32_t idMsr, uint32_t idKey, uint64_t u64Val, void *pvUser);
/** x86 MSR write handler pointer. */
typedef FNPSPX86ICEMSRWRITE *PFNPSPX86ICEMSRWRITE;


/**
 * Creates a new x86 ICE instance.
 *
 * @returns Status code.
 * @param   phX86Ice                Where to store the handle to the x86 ICE instance on success.
 * @param   uPort                   The TCP port to listen on.
 */
int PSPX86IceCreate(PPSPX86ICE phX86Ice, uint16_t uPort);


/**
 * Destroys the given x86 ICE handle.
 *
 * @returns nothing.
 * @param   hX86Ice                 The x86 ICE handle to destroy.
 */
void PSPX86IceDestroy(PSPX86ICE hX86Ice);


/**
 * Sets the given I/O port read/write handlers which get called for a matching request.
 *
 * @returns Status code.
 * @param   hX86Ice                 The x86 ICE instance handle.
 * @param   pfnIoPortRead           The read handler to set.
 * @param   pfnIoPortWrite          The write handler to set.
 * @param   pvUser                  Opaque user data passed in the callbacks.
 */
int PSPX86IceIoPortRwHandlerSet(PSPX86ICE hX86Ice, PFNPSPX86ICEIOPORTREAD pfnIoPortRead, PFNPSPX86ICEIOPORTWRITE pfnIoPortWrite, void *pvUser);


/**
 * Sets the given memory read/write handlers which get called for a matching request.
 *
 * @returns Status code.
 * @param   hX86Ice                 The x86 ICE instance handle.
 * @param   pfnMemRead              The read handler to set.
 * @param   pfnMemWrite             The write handler to set.
 * @param   pvUser                  Opaque user data passed in the callbacks.
 */
int PSPX86IceMemRwHandlerSet(PSPX86ICE hX86Ice, PFNPSPX86ICEMEMREAD pfnMemRead, PFNPSPX86ICEMEMWRITE pfnMemWrite, void *pvUser);


/**
 * Sets the given MSR read/write handlers which get called for a matching request.
 *
 * @returns Status code.
 * @param   hX86Ice                 The x86 ICE instance handle.
 * @param   pfnMsrRead              The read handler to set.
 * @param   pfnMsrWrite             The write handler to set.
 * @param   pvUser                  Opaque user data passed in the callbacks.
 */
int PSPX86IceMsrRwHandlerSet(PSPX86ICE hX86Ice, PFNPSPX86ICEMSRREAD pfnMsrRead, PFNPSPX86ICEMSRWRITE pfnMsrWrite, void *pvUser);

#endif /* !INCLUDED_psp_x86_ice_h */
