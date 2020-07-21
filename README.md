# PSPEmu - Emulator for AMDs (Platform) Secure Processor

## Description

This is an emulator for AMDs (Platform) Secure Processor or PSP with the goal to understand
AMDs prorietary AGESA code running on the PSP by watching execution of the involved code modules.
The PSP is the first processor to run on an AMD CPU after power is applied and is responsible for bootstrapping
the whole system. It loads firmware for other micro controllers inside the CPU like the SMU for instance
and initializes the memory controllers so DRAM is fully initialized when the first instruction starts executing
on the x86 cores. The PSP also acts as the systems trust anchor by doing signature verification for loaded code
including the UEFI firmware running on the x86 cores and implementing a firmware TPM on some models.
On EPYC the PSP is responsible for key management and programming the encryption keys for the AES engines inside
the memory controllers for AMDs Secure Encrypted Virtualization (SEV) feature.

## Target audience

The emulator is targeted at firmware engineers who want to gain a deeper understanding about the PSP and the interaction
with the UEFI firmware. Because of the security aspect it is interesting to security researchers as well.

## Features

The following features are currently implemented in the emulator:

- [x] Execute on-chip, off-chip bootloaders and the secure OS in a virtual environment
- [x] Supports Zen, Zen+ and Zen2 (partial) based bootloaders
- [x] Logging of hardware accesses, syscalls, etc.
- [x] GDB stub interface with full support for breakpoints, watchpoints, stepping, etc.
- [x] Create coverage traces compatible with the DrCov format
- [x] Proxy mode allows accessing real hardware by running a small stub on a real PSP using code from the [psp-apps](https://github.com/PSPReverse/psp-apps) repository.

## Building

### Requirements

A fairly recent Linux host with openssl, zlib and the respective development packages installed is required.

### Actual building

Building the whole thing is a bit icky right now, patches certainly welcome!

First [libpspproxy](https://github.com/PSPReverse/libpspproxy) needs to be installed.

Then PSPEmu itself can be built by cloning the repository and issuing the following commands:
```
git clone --recurse-submodules https://github.com/PSPReverse/PSPEmu.git
cd PSPEmu
cd capstone && make && cd ..
cd libgdbstub && cmake . && make && cd..
cd unicorn && sh make.sh && cd ..
cmake . && make
```

## Usage

### Fully emulated setup

For first steps no access to AMD hardware is required, only a firmware image from a Mainboard
vendor which can be downloaded from the vendors websites. In this example the off chip BL is
executed in the emulator by using a fully emulated setup based on the first generation Zen architecture.
As the first step the off chip BL needs to be extracted from the firmware image which can be done
with [PSPTool](https://github.com/PSPReverse/PSPTool).
After that a so called boot ROM service page needs to be created which is normally left behind by the on chip bootloader
which is skipped in this example. `PSPEmu` is currently not able to automatically create one for the emulated system
(has high priority on the todo list). Finally the binary can be run inside the emulator using the following command
```
./PSPEmu \
    --emulation-mode sys \                       # Sets the emulation mode to start at the off chip BL stage
    --psp-profile zen-standard \                 # Standard Zen based PSP profile
    --flash-rom <path/to/complete/flash/image> \ # The flash image to use for the emulated flash device
    --bin-load <path/to/extracted/off/chip/bl> \ # The off chip BL binary to load
    --bin-contains-hdr \                         # The biniary extracted with PSPTool has a 256 byte header prepended
    --boot-rom-svc-page <path/to/created/BRSP> \ # The BRSP to load
    --timer-real-time \                          # Emulated timers tick in host real time
    --trace-log ./log \                          # Destination for the log
    --intercept-svc-6 \                          # Intercept and log svc 6 debug log syscalls
    --trace-svcs                                 # Log all syscalls being made from usermode
```

### Understanding the log

Running `PSPEmu` with `--trace-log` will create a log which has the following layout:
```
00000000          WARNING             MMIO 0x000028ac[0x0000289b][  SVC, S, M, I,NF,0x00014000] DEV WRITE <UNASSIGNED>                            0x3006000 4 0x00000001
```

The first column is monotonically increasing event ID, it is useful when filtering the log after the run to see how far certain events are apart. This is followed by the event severity
which ranges from debug messages to fatal errors which will make the run fail or continue with undefined behavior. The following severities can occur:

Severity | Description
------------ | -------------
DEBUG | Debug messages usually only useful when working on `PSPEmu` itself
INFO | Informational messages like accesses to devices, syscalls being made, etc.
WARNING | Warnings that something is not emulated correctly or at all. This will usually be shown for accesses to MMIO/SMN/X86 regions which are not backed by an emulated device.
ERROR | Error messages where the error could be conveyed to the firmware so it can respond correctly, like errors in the CCP.
FATAL_ERROR | Errors which can not be conveyed to the firmware in a meaningful way so the emulation result will be undefined because the firmware continues with a bogus state.

After the severity comes the event origin i.e. which component of the emulator triggered the event. The most important origins are MMIO/SMN/X86 accesses or messages made from the proxy component
or the syscall tracing.

The fourth column is the PC value of the instruction causing the event, followed by the value of the LR register in square brackets. Next comes a brief state about the emulated ARM core when
the event happened:

Values | Description
------------ | -------------
SVC,USR,FIQ,IRQ,ABRT,UNDEF,MON,SYS | CPU mode
S,NS | Secure/Non-secure World
M,NM | MMU active/inactive
I,NI | Interrupts enabled/masked
F,NF | Fast interrupts enabled/masked
addr | TTBR0 content for the page table root

The following content is dependent on the type of event. The example shows a device write event to an unassigned region at address `0x3006000` which is 4 bytes in size and the value `0x00000001`

### Enabling the GDB stub

`PSPEmu` offers the ability to debug the firmware using a standard GDB which has support for ARM. This requires adding `--dbg <port>` to the command line. The GDB stub will listen on the given port
which one can connect to using GDBs `target remote localhost:<port>` command. When connected you can set breakpoints and watchpoints, inspect and manipulate registers and memory and step through the 
executed code. `PSPEmu` offers specialized commands through GDBs `monitor` command. `monitor help` will print all available commands.

### Proxy mode

TODO

