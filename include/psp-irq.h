/** @file
 * PSP Emulator - Interrupt controller.
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
#ifndef INCLUDED_psp_irq_h
#define INCLUDED_psp_irq_h

#include <common/types.h>

#include <psp-core.h>
#include <psp-iom.h>


/** Opaque PSP interrupt controller handle. */
typedef struct PSPIRQINT *PSPIRQ;
/** Pointer to a PSP interrupt controller handle. */
typedef PSPIRQ *PPSPIRQ;


/**
 * Creates a new interrupt controller instance.
 *
 * @returns Status code.
 * @param   phIrq                   Where to store the IRQ controller handle on success.
 * @param   hPspCore                The PSP core the interrupt controller is connected to.
 * @param   hIoMgr                  The I/O manager handle for the given PSP core to register MMIO handlers
 *                                  for the interrupt controller registers.
 */
int PSPIrqCreate(PPSPIRQ phIrq, PSPCORE hPspCore, PSPIOM hIoMgr);


/**
 * Destroys a given interrupt controller handle.
 *
 * @returns nothing.
 * @param   hIrq                    The interrupt controller handle to destroy.
 */
void PSPIrqDestroy(PSPIRQ hIrq);


/**
 * Resets the interrupt controller state.
 *
 * @returns nothing.
 * @param   hIrq                    The interrupt controller handle.
 */
void PSPIrqReset(PSPIRQ hIrq);


/**
 * Sets an interrupt request for the specified priority group and interrupt number.
 *
 * @returns Status code.
 * @param   hIrq                    The interrupt controller handle.
 * @param   uPrioGrp                The priority group of the device sending the interrupt.
 * @param   uIrq                    The interrupt number inside the priority group of the device.
 * @param   fAssert                 Flag whether the interrupt line is asserted.
 */
int PSPIrqSet(PSPIRQ hIrq, uint32_t uPrioGrp, uint8_t uIrq, bool fAssert);

#endif /* !INCLUDED_psp_irq_h */
