/*
   PSP emulator using unicorn.
 */

#define __STDC_FORMAT_MACROS

#include <unicorn/unicorn.h>
#include <libpspproxy.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define IN_PSP_EMULATOR
#include <psp-fw/svc_id.h>
#include <sev/sev.h>

typedef struct PSPCCPREQSVC0X38
{
    PSPADDR             PspAddrBufUnk0;
    uint32_t            cbBufUnk0;
    uint32_t            dwUnk1;
    PSPADDR             PspAddrBufUnk1;
    uint32_t            cbBufUnk1;
    uint32_t            PspAddrBufUnk2;
    uint32_t            dwUnk3;
    uint32_t            dwUnk4;
    uint32_t            dwUnk5;
} PSPCCPREQSVC0X38;
typedef PSPCCPREQSVC0X38 *PPSPCCPREQSVC0X38;

/**
 * A datum read/written.
 */
typedef union PSPDATUM
{
    uint8_t   u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    uint8_t  ab[8];
} PSPDATUM;
typedef PSPDATUM *PPSPDATUM;

/** Pointer to a PSP core instance. */
typedef struct PSPCORE *PPSPCORE;
/** Pointer to a const PSP core instance. */
typedef const struct PSPCORE *PCPSPCORE;

/**
 * Cached x86 memory mapping
 */
typedef struct PSPX86MEMCACHEDMAPPING
{
    /** Pointer to the owning PSP core instance. */
    PCPSPCORE           pPspCore;
    /** X86 Mapped base address, NIL_X86PADDR if mapping is not used. */
    X86PADDR            PhysX86AddrBase;
    /** 4K alogned base address of the mapping (for unicorn). */
    PSPADDR             PspAddrBase4K;
    /** PSP base address of the mapping. */
    PSPADDR             PspAddrBase;
    /** Highest cached address so far (exclusive, defines the memory span initialized). */
    PSPADDR             PspAddrCached;
    /** Highest address written so far (exclusive, defines range of memory we have to sync back on unmap). */
    PSPADDR             PspAddrHighestWritten;
    /** Size of mapped area. */
    size_t              cbMapped;
    /** 4K aligned mapping size (for unicorn). */
    size_t              cbMapped4K;
    /** Amount of memory allocated. */
    size_t              cbAlloc;
    /** Pointer to the memory caching the mapping. */
    void                *pvMapping;
} PSPX86MEMCACHEDMAPPING;
typedef PSPX86MEMCACHEDMAPPING *PPSPX86MEMCACHEDMAPPING;

/**
 * A single PSP core executing.
 */
typedef struct PSPCORE
{
    /** The PSP proxy context handle to forward requests to a real PSP. */
    PSPPROXYCTX             hProxyCtx;
    /** The unicorn engine pointer. */
    uc_engine               *pUcEngine;
    /** The loaded firmware image which is mapped at the flash location. */
    void                    *pvFw;
    /** Size of the firmware region. */
    size_t                  cbFw;
    /** The shared memory region with the proxied PSP. */
    X86PADDR                PhysX86AddrShm;
    /** The R0 kernel virtual address of the shared memory region. */
    R0PTR                   R0AddrShm;
    /** Size of the shared memory region. */
    size_t                  cbShm;
    /** The x86 mapping for the privileged DRAM region where the SEV app state is saved. */
    PSPX86MEMCACHEDMAPPING  X86MappingPrivState;
    /** Size of the state region. */
    uint32_t                cbStateRegion;
    /** Cached temporary x86 mappings. */
    PSPX86MEMCACHEDMAPPING  aX86Mappings[8];
} PSPCORE;

static const int registers[] = { UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                                 UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                                 UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                                 UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC };

static void print_ctx(uc_engine *emu) {

    int64_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc;
    r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = r8 = r9 = r10 = r11 = r12 = sp = lr = pc = 0;
    int64_t *reg_array[] = {&r0, &r1, &r2, &r3, &r4, &r5, &r6, &r7, &r8, &r9, &r10, &r11, &r12, &sp, &lr, &pc};
    uc_reg_read_batch(emu, (int*)registers, (void**)reg_array, 16);
    printf( "R0 > 0x%08" PRIx64 " | R1 > 0x%08" PRIx64 " | R2 > 0x%08" PRIx64 " | R3 > 0x%08" PRIx64 "\n"
            "R4 > 0x%08" PRIx64 " | R5 > 0x%08" PRIx64 " | R6 > 0x%08" PRIx64 " | R7 > 0x%08" PRIx64 "\n"
            "R8 > 0x%08" PRIx64 " | R9 > 0x%08" PRIx64 " | R10> 0x%08" PRIx64 " | R11> 0x%08" PRIx64 "\n"
            "R12> 0x%08" PRIx64 " | SP > 0x%08" PRIx64 " | LR > 0x%08" PRIx64 " | PC > 0x%08" PRIx64 "\n",
            r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc);
}

#if 1
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
    print_ctx(uc);
}
#endif

#ifdef PSP_EMU_SYSTEM
static uint64_t pspEmuCcpMmioRead(struct uc_struct* uc, void *opaque, uint64_t addr, unsigned size)
{
    printf(">>> CCP read at 0x%08" PRIx64 "\n", addr);
    switch (addr)
    {
        case 0x1000: /* Control register */
            return 2; /* Halt bit. */
            break;
        default:
            print_ctx(uc);
    }
    return 0;
}

static void pspEmuCcpMmioWrite(struct uc_struct* uc, void *opaque, uint64_t addr, uint64_t data, unsigned size)
{
    printf(">>> CCP write 0x%08" PRIx64 " at 0x%08" PRIx64 "\n", data, addr);
    print_ctx(uc);
    switch(addr)
    {
        default:
            break;
    }
}

static uint64_t pspEmuUnkDevMmioRead(struct uc_struct* uc, void *opaque, uint64_t addr, unsigned size)
{
    printf(">>> Unkown device read at 0x%08" PRIx64 "\n", addr);
    print_ctx(uc);
    return 0;
}

static void pspEmuUnkDevMmioWrite(struct uc_struct* uc, void *opaque, uint64_t addr, uint64_t data, unsigned size)
{
    printf(">>> Unknown device write 0x%08" PRIx64 " at 0x%08" PRIx64 "\n", data, addr);
    print_ctx(uc);
    switch(addr)
    {
        default:
            break;
    }
}
#elif defined(PSP_EMU_APP)
static uint64_t pspEmuX86MapRead(struct uc_struct* uc, void *pvUser, uint64_t addr, unsigned size);
static void pspEmuX86MapWrite(struct uc_struct* uc, void *pvUser, uint64_t addr, uint64_t data, unsigned size);

static int PSPEmuWriteData(const char *pszFilename, void *pv, size_t cb)
{
    int rc = 0;
    FILE *pFile = fopen(pszFilename, "wb+");
    if (pFile)
    {

        size_t cbWritten = fwrite(pv, cb, 1, pFile);
        if (cbWritten != 1)
            rc = EINVAL;

        fclose(pFile);
    }
    else
        rc = errno;

    return rc;
}


static void psp_emu_app_svc(uc_engine *uc, uint32_t intno, void *pvUser)
{
    PPSPCORE pThis = (PPSPCORE)pvUser;

    if (intno == 2)
    {
        //print_ctx(uc);

        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);

        /* PC is advanced already, should be in thumb mode so go back 2 bytes and examine the svc instruction extracting the syscall number. */
        uint16_t uInsnSvc = 0;
        uc_mem_read(uc, pc - 2, &uInsnSvc, sizeof(uint16_t));
        if (((uInsnSvc >> 8) & 0xff) == 0xdf)
        {
            uint32_t idxSyscall = uInsnSvc & 0xff;
            printf("Syscall %#x happened at %#x\n", idxSyscall, pc - 2);

            switch (idxSyscall)
            {
                case 0:
                {
                    /* Stop here as the app exited. */
                    uint32_t PspAddrStateRegion = 0;

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, 0x3c, pThis->cbStateRegion, 0, 0, 0, &PspAddrStateRegion);
                    if (rc)
                        printf("Mapping memory region state failed with %d\n", rc);
                    PSPEmuWriteData("/home/alex/psp_state.bin", pThis->X86MappingPrivState.pvMapping, pThis->cbStateRegion);
                    rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrStateRegion, pThis->X86MappingPrivState.pvMapping, pThis->cbStateRegion);
                    if (rc)
                        printf("Syncing SEV state to privileged DRAM failed with %d\n", rc);
                    printf("APP exited\n");
                    uc_emu_stop(uc);
                    break;
                }
                case 1:
                {
                    uint32_t uSts = 0;
                    uint32_t uStackTop = 0x62000;
                    uint32_t UsrPtrStackAddr = 0;

                    /* Map stack. */
                    uc_mem_map(uc, 0x60000, 2 * 4096, UC_PROT_ALL);

                    uc_reg_read(uc, UC_ARM_REG_R2, &UsrPtrStackAddr);

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    uc_mem_write(uc, UsrPtrStackAddr, &uStackTop, sizeof(uint32_t));
                    break;
                }
                case 0x03: /* SMN network address mapping. */
                {
                    uint32_t uSmnAddr = 0;
                    uint32_t idCcdTgt = 0;
                    uint32_t uSmnAddrMapped = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &uSmnAddr);
                    uc_reg_read(uc, UC_ARM_REG_R1, &idCcdTgt);
                    printf("Mapping SMN address %#x on CCD %#x\n", uSmnAddr, idCcdTgt);

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uSmnAddr, idCcdTgt, 0, 0, &uSmnAddrMapped);
                    if (rc)
                        printf("Mapping SMN address failed with %d\n", rc);
                    uc_reg_write(uc, UC_ARM_REG_R0, &uSmnAddrMapped);
                    break;
                }
                case 0x05: /* Unmap previously mapped address. */
                {
                    uint32_t uAddr = 0;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &uAddr);
                    printf("Unmapping SMN address %#x\n", uAddr);

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uAddr, 0, 0, 0, &uSts);
                    if (rc)
                        printf("Unmapping SMN address failed with %d\n", rc);

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x06:
                {
                    /* Log the string. */
                    PSPADDR PspAddrStr = 0;
                    char achStr[512];

                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrStr);
                    uc_mem_read(uc, PspAddrStr, &achStr[0], 512);
                    achStr[512 - 1] = '\0'; /* Ensure termination. */
                    printf("PSP Log: %s\n", &achStr[0]);
                    break;
                }
                case 0x08: /* Unmap x86 memory by PSP address. */
                {
                    uint32_t uAddr = 0;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &uAddr);
                    printf("Unmapping x86 address mapped at %#x\n", uAddr);

                    /* Search for the cached mapping and sync the memory before the real unmapping call. */
                    for (uint32_t i = 0; i < ELEMENTS(pThis->aX86Mappings); i++)
                    {
                        if (pThis->aX86Mappings[i].PspAddrBase == uAddr)
                        {
                            PPSPX86MEMCACHEDMAPPING pMapping = &pThis->aX86Mappings[i];

                            /* Sync back the memory until the highest written range. */
                            if (pMapping->PspAddrHighestWritten)
                            {
                                size_t cbSync = pMapping->PspAddrHighestWritten - pMapping->PspAddrBase;

                                uint32_t offSync = pMapping->PspAddrBase - pMapping->PspAddrBase4K;
                                int rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, pMapping->PspAddrBase, (uint8_t *)pMapping->pvMapping + offSync, cbSync);
                                if (rc)
                                    printf("Error writing PSP memory at %#x\n", pMapping->PspAddrBase);
                            }

                            if (pMapping->pvMapping)
                                free(pMapping->pvMapping);

                            uc_mem_unmap(pThis->pUcEngine, pMapping->PspAddrBase4K, pMapping->cbMapped4K);
                            pMapping->PhysX86AddrBase       = NIL_X86PADDR;
                            pMapping->PspAddrBase           = 0;
                            pMapping->PspAddrCached         = 0;
                            pMapping->PspAddrHighestWritten = 0;
                            pMapping->pPspCore              = NULL;
                            pMapping->cbAlloc               = 0;
                            pMapping->cbMapped              = 0;
                            pMapping->pvMapping             = NULL;
                            break;
                        }
                    }

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uAddr, 0, 0, 0, &uSts);
                    if (rc)
                        printf("Unmapping x86 address failed with %d\n", rc);

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x25: /* Map x86 memory into PSP. */
                {
                    uint32_t uPhysX86AddrLow = 0;
                    uint32_t uPhysX86AddrHigh = 0;
                    uint32_t uMemType = 0;
                    uint32_t uAddr = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &uPhysX86AddrLow);
                    uc_reg_read(uc, UC_ARM_REG_R1, &uPhysX86AddrHigh);
                    uc_reg_read(uc, UC_ARM_REG_R2, &uMemType);

                    X86PADDR PhysX86AddrBase = (((uint64_t)uPhysX86AddrHigh << 32) | uPhysX86AddrLow);
                    printf("Mapping x86 address %#lx (memory target %u)\n", PhysX86AddrBase, uMemType);


                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uPhysX86AddrLow, uPhysX86AddrHigh, uMemType, 0, &uAddr);
                    if (rc)
                    {
                        printf("Mapping x86 address failed with %d\n", rc);
                        uAddr = 0;
                    }
                    else
                    {
                        PPSPX86MEMCACHEDMAPPING pMapping = NULL;

                        /* Search for a free mapping slot and create an MMIO mapping covering the base till the end of the 64MB slot. */
                        for (uint32_t i = 0; i < ELEMENTS(pThis->aX86Mappings); i++)
                        {
                            if (pThis->aX86Mappings[i].PhysX86AddrBase == NIL_X86PADDR)
                            {
                                pMapping = &pThis->aX86Mappings[i];
                                break;
                            }
                        }

                        if (pMapping)
                        {
                            pMapping->PhysX86AddrBase       = PhysX86AddrBase;
                            pMapping->PspAddrBase4K         = uAddr & ~(uint32_t)0xfff;
                            pMapping->PspAddrBase           = uAddr;
                            pMapping->PspAddrCached         = pMapping->PspAddrBase4K;
                            pMapping->PspAddrHighestWritten = 0;
                            pMapping->pPspCore              = pThis;
                            pMapping->cbAlloc               = 0;
                            pMapping->cbMapped              = ((PhysX86AddrBase & ~(_64M - 1)) + _64M) - PhysX86AddrBase;
                            pMapping->cbMapped4K            = (pMapping->cbMapped + _4K) & ~(uint32_t)0xfff;
                            pMapping->pvMapping             = NULL;

                            /* x86 mapping space. */
                            uc_mmio_map(pThis->pUcEngine, pMapping->PspAddrBase4K, pMapping->cbMapped4K, pspEmuX86MapRead, pspEmuX86MapWrite, pMapping);
                        }
                        else
                        {
                            /* This should never happen as the real PSP has only 8 mapping slots. */
                            /** @todo Unmap the mapping on the proxied PSP. */
                            printf("Ran out of x86 mapping slots, impossible!\n");
                            uAddr = 0;
                        }
                    }

                    uc_reg_write(uc, UC_ARM_REG_R0, &uAddr);
                    break;
                }
                case 0x28: /* Send SMU message. */
                {
                    uint32_t idMsg = 0;
                    uint32_t uArg0 = 0;
                    PSPADDR  UsrPtrReturnMsg;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &idMsg);
                    uc_reg_read(uc, UC_ARM_REG_R1, &uArg0);
                    uc_reg_read(uc, UC_ARM_REG_R2, &UsrPtrReturnMsg);

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, idMsg, uArg0,
                                                     UsrPtrReturnMsg != 0
                                                   ? 0x20000 /**@todo Query scratch buffer*/
                                                   : 0,
                                                   0, &uSts);
                    if (rc)
                        printf("Mapping x86 address failed with %d\n", rc);

                    if (UsrPtrReturnMsg != 0)
                    {
                        uint32_t u32Ret = 0;
                        rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x20000, &u32Ret, sizeof(u32Ret));
                        if (!rc)
                            uc_mem_write(pThis->pUcEngine, UsrPtrReturnMsg, &u32Ret, sizeof(u32Ret));
                        else
                            printf("Reading the returned status failed with %d\n", rc);
                    }

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x31: /* Execute request slave PSPs. */
                {
                    uint32_t uSts = 0;
                    /** @todo */
                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                }
                case 0x32: /* Unknown */
                {
                    PSPADDR  PspAddrUnk = 0;
                    uint32_t cbUnk = 0;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrUnk);
                    uc_reg_read(uc, UC_ARM_REG_R1, &cbUnk);

                    void *pvTmp = malloc(cbUnk);

                    uc_mem_read(pThis->pUcEngine, PspAddrUnk, pvTmp, cbUnk);
                    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x20000, pvTmp, cbUnk);

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x20000, cbUnk, 0, 0, &uSts);
                    if (!rc && uSts == 0)
                    {
                        /* Sync memory back. */
                        PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x20000, pvTmp, cbUnk);
                        uc_mem_write(pThis->pUcEngine, PspAddrUnk, pvTmp, cbUnk);
                    }
                    else
                    {
                        printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
                        if (rc)
                            uSts = 0x9;
                    }

                    free(pvTmp);
                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x33: /* Unknown */
                {
                    uint32_t PspAddrUnk = 0;
                    uint32_t cbUnk = 0;
                    uint32_t uSts = 0;

                    print_ctx(pThis->pUcEngine);
                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrUnk);
                    uc_reg_read(uc, UC_ARM_REG_R1, &cbUnk);
                    printf("Unknown syscall 0x33 with parameters: PspAddrUnk=%#x cbUnk=%#x\n", PspAddrUnk, cbUnk);

                    void *pvTmp = malloc(cbUnk);
                    if (pvTmp)
                    {
                        if (uc_mem_read(pThis->pUcEngine, PspAddrUnk, pvTmp, cbUnk))
                            printf("Failed to read memory from unicorn\n");
                        int rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x21e2c, pvTmp, cbUnk);
                        if (!rc)
                        {
                            rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x21e2c /*Psp scratch addr*/, cbUnk, 0, 0, &uSts);
                            if (rc || uSts != 0)
                                printf("Syscall 0x33 rc=%d uSts=%#x\n", rc, uSts);
                            else
                            {
                                rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x21e2c, pvTmp, cbUnk);
                                if (!rc)
                                {
                                    static int i = 0;
                                    char szBuf[128];
                                    snprintf(szBuf, sizeof(szBuf), "/home/alex/svc_0x33_%u.bin", i++);
                                    PSPEmuWriteData(szBuf, pvTmp, cbUnk);
                                    if (uc_mem_write(pThis->pUcEngine, PspAddrUnk, pvTmp, cbUnk))
                                        printf("Failed to write memory to unicorn\n");
                                }
                                else
                                {
                                    printf("Failed to read memory from PSP with %d\n", rc);
                                    uSts = 0x9;
                                }
                            }
                        }
                        else
                        {
                            printf("Failed writing memory to proxied PSP with %d\n", rc);
                            uSts = 0x9;
                        }
                        free(pvTmp);
                    }
                    else
                    {
                        printf("Out of memory allocating %#x bytes\n", cbUnk);
                        uSts = 0x9;
                    }

                    printf("uSts=%#x\n", uSts);
                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x34: /* Platform reset */
                {
                    uint32_t uArgUnk = 0;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &uArgUnk);
                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uArgUnk, 0, 0, 0, &uSts);
                    if (rc)
                        printf("Platform reset failed with %d\n", rc);

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x35: /* Unknown, accesses CCP */
                {
                    uint32_t au32Req[8];
                    uint32_t uSts = 0;
                    PSPADDR  PspAddrReq;

                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrReq);
                    uc_mem_read(pThis->pUcEngine, PspAddrReq, &au32Req[0], sizeof(au32Req));

                    printf("Syscall 0x35 request:\n"
                           "au32Req[0]: %#x\n"
                           "au32Req[1]: %#x\n"
                           "au32Req[2]: %#x\n"
                           "au32Req[3]: %#x\n"
                           "au32Req[4]: %#x\n"
                           "au32Req[5]: %#x\n"
                           "au32Req[6]: %#x\n"
                           "au32Req[7]: %#x\n",
                           au32Req[0], au32Req[1], au32Req[2], au32Req[3],
                           au32Req[4], au32Req[5], au32Req[6], au32Req[7]);

                    if (au32Req[2] == 0 && au32Req[3] == 0)
                    {
                        uint32_t au32ReqProxy[8];
                        uint8_t abTmp[128];
                        PSPADDR PspAddrProxy1 = 0x20000;
                        PSPADDR PspAddrProxy2 = PspAddrProxy1 + au32Req[1];
                        PSPADDR PspAddrProxy3 = PspAddrProxy2 + au32Req[5];

                        uc_mem_read(pThis->pUcEngine, au32Req[0], &abTmp[0], au32Req[1]);
                        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy1, &abTmp[0], au32Req[1]);

                        uc_mem_read(pThis->pUcEngine, au32Req[4], &abTmp[0], au32Req[5]);
                        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy2, &abTmp[0], au32Req[5]);

                        uc_mem_read(pThis->pUcEngine, au32Req[6], &abTmp[0], au32Req[7]);
                        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy3, &abTmp[0], au32Req[7]);

                        au32ReqProxy[0] = PspAddrProxy1;
                        au32ReqProxy[1] = au32Req[1];
                        au32ReqProxy[2] = au32Req[2];
                        au32ReqProxy[3] = au32Req[3];
                        au32ReqProxy[4] = PspAddrProxy2;
                        au32ReqProxy[5] = au32Req[5];
                        au32ReqProxy[6] = PspAddrProxy3;
                        au32ReqProxy[7] = au32Req[7];

                        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x23000, &au32ReqProxy[0], sizeof(au32ReqProxy));

                        int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x23000, 0, 0, 0, &uSts);
                        if (!rc && uSts == 0)
                        {
                            /* Sync memory back. */
                            PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy1, &abTmp[0], au32Req[1]);
                            uc_mem_write(pThis->pUcEngine, au32Req[0], &abTmp[0], au32Req[1]);

                            PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy2, &abTmp[0], au32Req[5]);
                            uc_mem_write(pThis->pUcEngine, au32Req[4], &abTmp[0], au32Req[5]);

                            PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy3, &abTmp[0], au32Req[7]);
                            uc_mem_write(pThis->pUcEngine, au32Req[6], &abTmp[0], au32Req[7]);
                        }
                        else
                        {
                            printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
                            if (rc)
                                uSts = 0x9;
                        }
                    }
                    else
                    {
                        printf("Request not implemented\n");
                        uSts = 0x9;
                    }

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x36: /* Unknown, accesses CCP */
                {
                    uint32_t au32Req[13];
                    uint32_t uSts = 0x9;
                    PSPADDR  PspAddrReq;

                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrReq);
                    uc_mem_read(pThis->pUcEngine, PspAddrReq, &au32Req[0], sizeof(au32Req));

                    printf("Syscall 0x36 request:\n"
                           "au32Req[0]: %#x\n"
                           "au32Req[1]: %#x\n"
                           "au32Req[2]: %#x\n"
                           "au32Req[3]: %#x\n"
                           "au32Req[4]: %#x\n"
                           "au32Req[5]: %#x\n"
                           "au32Req[6]: %#x\n"
                           "au32Req[7]: %#x\n"
                           "au32Req[8]: %#x\n"
                           "au32Req[9]: %#x\n"
                           "au32Req[10]: %#x\n"
                           "au32Req[11]: %#x\n"
                           "au32Req[12]: %#x\n",
                           au32Req[0], au32Req[1], au32Req[2], au32Req[3],
                           au32Req[4], au32Req[5], au32Req[6], au32Req[7],
                           au32Req[8], au32Req[9], au32Req[10], au32Req[11],
                           au32Req[12]);

                    uint32_t au32ReqProxy[13];
                    void *pvTmp = malloc(_256K);
                    PSPADDR PspAddrProxy1 = 0x20000;
                    PSPADDR PspAddrProxy2 = PspAddrProxy1 + au32Req[1];
                    PSPADDR PspAddrProxy3 = PspAddrProxy2 + au32Req[3];
                    PSPADDR PspAddrProxy4 = PspAddrProxy3 + au32Req[6];

                    uc_mem_read(pThis->pUcEngine, au32Req[0], pvTmp, au32Req[1]);
                    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy1, pvTmp, au32Req[1]);

                    uc_mem_read(pThis->pUcEngine, au32Req[2], pvTmp, au32Req[3]);
                    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy2, pvTmp, au32Req[3]);

                    uc_mem_read(pThis->pUcEngine, au32Req[5], pvTmp, au32Req[6]);
                    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy3, pvTmp, au32Req[6]);

                    uc_mem_read(pThis->pUcEngine, au32Req[8], pvTmp, au32Req[9]);
                    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy4, pvTmp, au32Req[9]);

                    au32ReqProxy[0] = PspAddrProxy1;
                    au32ReqProxy[1] = au32Req[1];
                    au32ReqProxy[2] = PspAddrProxy2;
                    au32ReqProxy[3] = au32Req[3];
                    au32ReqProxy[4] = au32Req[4];
                    au32ReqProxy[5] = PspAddrProxy3;
                    au32ReqProxy[6] = au32Req[6];
                    au32ReqProxy[7] = au32Req[7];
                    au32ReqProxy[8] = PspAddrProxy4;
                    au32ReqProxy[9] = au32Req[9];
                    au32ReqProxy[10] = au32Req[10];
                    au32ReqProxy[11] = au32Req[11];
                    au32ReqProxy[12] = au32Req[12];

                    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrProxy4 + au32Req[9], &au32ReqProxy[0], sizeof(au32ReqProxy));

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, PspAddrProxy4 + au32Req[9], 0, 0, 0, &uSts);
                    if (!rc && uSts == 0)
                    {
                        /* Sync memory back. */
                        PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy1, pvTmp, au32Req[1]);
                        uc_mem_write(pThis->pUcEngine, au32Req[0], pvTmp, au32Req[1]);

                        PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy2, pvTmp, au32Req[3]);
                        uc_mem_write(pThis->pUcEngine, au32Req[2], pvTmp, au32Req[3]);

                        PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy3, pvTmp, au32Req[6]);
                        uc_mem_write(pThis->pUcEngine, au32Req[5], pvTmp, au32Req[6]);

                        PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrProxy4, pvTmp, au32Req[9]);
                        uc_mem_write(pThis->pUcEngine, au32Req[8], pvTmp, au32Req[9]);
                    }
                    else
                    {
                        printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
                        if (rc)
                            uSts = 0x9;
                    }

                    free(pvTmp);
                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x3c: /* Returns pointer to state region in DRAM. */
                {
                    uint32_t uStateRegionAddr = 0;
                    uint32_t cbStateRegion = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &cbStateRegion);
                    printf("Querying state region of size %#x\n", cbStateRegion);

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, cbStateRegion, 0, 0, 0, &uStateRegionAddr);
                    if (rc)
                        printf("Querying state address failed with %d\n", rc);

                    printf("SEV app state address: %#x\n", uStateRegionAddr);

                    /* Initialize mapping if not done already. */
                    PPSPX86MEMCACHEDMAPPING pMapping = &pThis->X86MappingPrivState;
                    if (pMapping->PhysX86AddrBase == NIL_X86PADDR)
                    {
                        pMapping->PhysX86AddrBase       = 0xdeadd0d0; /* Fake value because we don't know the real address (could retrieve it but why bother). */
                        pMapping->PspAddrBase4K         = uStateRegionAddr & ~(uint32_t)0xfff;
                        pMapping->PspAddrBase           = uStateRegionAddr;
                        pMapping->PspAddrCached         = 0;
                        pMapping->PspAddrHighestWritten = 0;
                        pMapping->pPspCore              = pThis;
                        pMapping->cbMapped              = ((uStateRegionAddr & ~(_64M - 1)) + _64M) - uStateRegionAddr;
                        pMapping->cbMapped4K            = (pMapping->cbMapped + _4K) & ~(uint32_t)0xfff;
                        pMapping->cbAlloc               = pMapping->cbMapped4K;
                        pMapping->pvMapping             = malloc(pMapping->cbAlloc);
                        pThis->cbStateRegion         = cbStateRegion;
                        uc_mem_map_ptr(uc, pMapping->PspAddrBase4K, pMapping->cbMapped4K, UC_PROT_ALL, pMapping->pvMapping);
                    }

                    uc_reg_write(uc, UC_ARM_REG_R0, &uStateRegionAddr);
                    break;
                }
                case 0x37: /* Invalidate memory region. */
                {
                    uint32_t uInvOp = 0;
                    uint32_t fData = 0;
                    PSPADDR  PspAddrStart = 0;
                    uint32_t cbMem = 0;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &uInvOp);
                    uc_reg_read(uc, UC_ARM_REG_R1, &fData);
                    uc_reg_read(uc, UC_ARM_REG_R2, &PspAddrStart);
                    uc_reg_read(uc, UC_ARM_REG_R3, &cbMem);

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, uInvOp, fData, PspAddrStart, cbMem, &uSts);
                    if (rc)
                        printf("Invalidating/cleaning PSP memory failed with %d\n", rc);

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x38: /* CCP request (SHA operation?) */
                {
                    PSPADDR PspAddrReq;
                    PSPCCPREQSVC0X38 Req;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrReq);
                    uc_mem_read(pThis->pUcEngine, PspAddrReq, &Req, sizeof(Req));

                    /* Dump request structure. */
                    printf("CCP Request:\n"
                           "    PspAddrBufUnk0:  %#x\n"
                           "    cbBufUnk0:       %#x\n"
                           "    dwUnk1:          %#x\n"
                           "    PspAddrBufUnk1:  %#x\n"
                           "    cbBufUnk1:       %#x\n"
                           "    PspAddrBufUnk2:  %#x\n"
                           "    dwUnk3:          %#x\n"
                           "    dwUnk4:          %#x\n"
                           "    dwUnk5:          %#x\n",
                           Req.PspAddrBufUnk0, Req.cbBufUnk0,
                           Req.dwUnk1, Req.PspAddrBufUnk1, Req.cbBufUnk1,
                           Req.PspAddrBufUnk2, Req.dwUnk3, Req.dwUnk4, Req.dwUnk5);
                    if (   Req.dwUnk1 == 0x2
                        && Req.cbBufUnk1 == 0x20)
                    {
                        PSPCCPREQSVC0X38 ReqProxy;
                        void *pvTmp = malloc(_256K);
                        memcpy(&ReqProxy, &Req, sizeof(Req));

                        /* Sync inputs. */
                        if (Req.PspAddrBufUnk0)
                            ReqProxy.PspAddrBufUnk0 = 0x22000;
                        ReqProxy.PspAddrBufUnk1 = 0x21100;
                        if (Req.PspAddrBufUnk2)
                            ReqProxy.PspAddrBufUnk2 = 0x21200;
                        int rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x20000, &ReqProxy, sizeof(ReqProxy));
                        if (!rc && Req.PspAddrBufUnk0)
                        {
                            uc_mem_read(pThis->pUcEngine, Req.PspAddrBufUnk0, pvTmp, Req.cbBufUnk0);
                            rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk0, pvTmp, Req.cbBufUnk0);
                        }
                        if (!rc && Req.PspAddrBufUnk1)
                        {
                            uc_mem_read(pThis->pUcEngine, Req.PspAddrBufUnk1, pvTmp, Req.cbBufUnk1);
                            rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk1, pvTmp, Req.cbBufUnk1);
                        }
                        if (!rc && Req.PspAddrBufUnk2)
                        {
                            uc_mem_read(pThis->pUcEngine, Req.PspAddrBufUnk2, pvTmp, 0x20);
                            rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk2, pvTmp, 0x20);
                        }
                        if (!rc)
                        {
                            rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x20000, 0, 0, 0, &uSts);
                            if (!rc && uSts == 0)
                            {
                                /* Sync memory back. */
                                if (Req.PspAddrBufUnk0)
                                {
                                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk0, pvTmp, Req.cbBufUnk0);
                                    uc_mem_write(pThis->pUcEngine, Req.PspAddrBufUnk0, pvTmp, Req.cbBufUnk0);
                                }
                                if (Req.PspAddrBufUnk1)
                                {
                                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk1, pvTmp, Req.cbBufUnk1);
                                    uc_mem_write(pThis->pUcEngine, Req.PspAddrBufUnk1, pvTmp, Req.cbBufUnk1);
                                }
                                if (Req.PspAddrBufUnk2)
                                {
                                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, ReqProxy.PspAddrBufUnk2, pvTmp, 0x20);
                                    uc_mem_write(pThis->pUcEngine, Req.PspAddrBufUnk2, pvTmp, 0x20);
                                }
                            }
                            else
                            {
                                printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
                                if (rc)
                                    uSts = 0x9;
                            }
                        }
                        else
                        {
                            printf("Memory write failed with %d\n", rc);
                            uSts = 0x9;
                        }
                        free(pvTmp);
                    }
                    else
                    {
                        printf("CCP request not implemented, failing\n");
                        uSts = 0x9;
                    }

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x39: /* Fill buffer with RNG values */
                {
                    PSPADDR PspAddrBuf = 0;
                    uint32_t cbBuf = 0;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrBuf);
                    uc_reg_read(uc, UC_ARM_REG_R1, &cbBuf);

                    printf("Filling %#x with %#x bytes of random data\n", PspAddrBuf, cbBuf);
                    void *pvTmp = malloc(cbBuf);

                    /* Execute syscall. */
                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x20000, cbBuf, 0, 0, &uSts);
                    if (!rc && uSts == 0)
                    {
                        /* Sync stack buffers back. */
                        PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x20000, pvTmp, cbBuf);
                        uc_mem_write(pThis->pUcEngine, PspAddrBuf, pvTmp, cbBuf);
                    }
                    else
                    {
                        printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
                        if (rc)
                            uSts = 0x9;
                    }

                    free(pvTmp);
                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x41:
                {
                    PSPADDR PspAddrReq = 0;
                    uint32_t uSts = 0;
                    uint32_t au32Req[8];

                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrReq);
                    uc_mem_read(pThis->pUcEngine, PspAddrReq, &au32Req, sizeof(au32Req));
                    printf("Syscall 0x41 request:\n"
                           "au32Req[0]: %#x\n"
                           "au32Req[1]: %#x\n"
                           "au32Req[2]: %#x\n"
                           "au32Req[3]: %#x\n"
                           "au32Req[4]: %#x\n"
                           "au32Req[5]: %#x\n"
                           "au32Req[6]: %#x\n"
                           "au32Req[7]: %#x\n",
                           au32Req[0], au32Req[1], au32Req[2], au32Req[3],
                           au32Req[4], au32Req[5], au32Req[6], au32Req[7]);

                    if (au32Req[0] == 1 || au32Req[0] == 5 || au32Req[0] == 3 || au32Req[0] == 2)
                    {
                        uint32_t au32ReqProxy[8];
                        void *pvTmp = malloc(2*_4K);
                        /* Sync the stack where the buffers are living. */
                        uc_mem_read(pThis->pUcEngine, 0x60000, pvTmp, 2 * _4K);
                        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x20000, pvTmp, 2 * _4K);

                        memset(&au32ReqProxy[0], 0, sizeof(au32ReqProxy));

                        if (au32Req[0] == 1)
                        {
                            /* Sync some part of the ECDH/ECDSA curve constants it seems. */
                            uc_mem_read(pThis->pUcEngine, au32Req[2], pvTmp, 144);
                            PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22000, pvTmp, 144);

                            /* Set up the proxy request structure. */
                            au32ReqProxy[0] = 1;
                            au32ReqProxy[1] = 0x20000 + (au32Req[1] - 0x60000);
                            au32ReqProxy[2] = 0x22000;
                            au32ReqProxy[3] = 0x20000 + (au32Req[3] - 0x60000);
                            au32ReqProxy[4] = 0x20000 + (au32Req[4] - 0x60000);
                        }
                        else if (au32Req[0] == 5)
                        {
                            /* Sync some part of the ECDH/ECDSA curve constants it seems. */
                            uc_mem_read(pThis->pUcEngine, 0x1c6ac, pvTmp, 508);
                            PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22000, pvTmp, 508);

                            /* Set up the proxy request structure. */
                            au32ReqProxy[0] = 5;
                            au32ReqProxy[1] = 0x20000 + (au32Req[1] - 0x60000);
                            au32ReqProxy[2] = 0x22000 + (au32Req[2] - 0x1c6ac);
                            au32ReqProxy[3] = 0x22000 + (au32Req[3] - 0x1c6ac);
                            au32ReqProxy[4] = 0x20000 + (au32Req[4] - 0x60000);
                            au32ReqProxy[5] = 0x22000 + (au32Req[5] - 0x1c6ac);
                        }
                        else if (au32Req[0] == 3)
                        {
                            /* Sync some part of the ECDH/ECDSA curve constants it seems. */
                            uc_mem_read(pThis->pUcEngine, 0x1c6ac, pvTmp, 508);
                            PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22000, pvTmp, 508);

                            /* Set up the proxy request structure. */
                            au32ReqProxy[0] = 3;
                            au32ReqProxy[1] = 0x20000 + (au32Req[1] - 0x60000);
                            au32ReqProxy[2] = 0x22000 + (au32Req[2] - 0x1c6ac);
                            au32ReqProxy[3] = 0x20000 + (au32Req[3] - 0x60000);
                        }
                        else if (au32Req[0] == 2)
                        {
                            /* Sync some part of the ECDH/ECDSA curve constants it seems. */
                            uc_mem_read(pThis->pUcEngine, 0x1c6ac, pvTmp, 508);
                            PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22000, pvTmp, 508);

                            if (au32Req[3] < 0x60000)
                            {
                                /* Doesn't live on the stack. */
                                uc_mem_read(pThis->pUcEngine, au32Req[3], pvTmp, 1024);
                                PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x22500, pvTmp, 1024);
                                au32ReqProxy[3] = 0x22500;
                            }
                            else
                                au32ReqProxy[3] = 0x20000 + (au32Req[3] - 0x60000);

                            /* Set up the proxy request structure. */
                            au32ReqProxy[0] = 2;
                            au32ReqProxy[1] = 0x20000 + (au32Req[1] - 0x60000);
                            au32ReqProxy[2] = 0x22000 + (au32Req[2] - 0x1c6ac);
                            au32ReqProxy[4] = 0x20000 + (au32Req[4] - 0x60000);
                        }

                        printf("Proxied request:\n"
                               "au32Req[0]: %#x\n"
                               "au32Req[1]: %#x\n"
                               "au32Req[2]: %#x\n"
                               "au32Req[3]: %#x\n"
                               "au32Req[4]: %#x\n"
                               "au32Req[5]: %#x\n",
                               au32ReqProxy[0], au32ReqProxy[1], au32ReqProxy[2], au32ReqProxy[3],
                               au32ReqProxy[4], au32ReqProxy[5]);

                        PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x23000, &au32ReqProxy[0], sizeof(au32ReqProxy));

                        /* Execute syscall. */
                        int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x23000, 0, 0, 0, &uSts);
                        if (!rc && uSts == 0)
                        {
                            /* Sync stack buffers back. */
                            PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x20000, pvTmp, 2 * _4K);
                            uc_mem_write(pThis->pUcEngine, 0x60000, pvTmp, 2 * _4K);

                            if (au32Req[0] == 2 && au32Req[3] < 0x60000)
                            {
                                PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x22500, pvTmp, 1024);
                                uc_mem_write(pThis->pUcEngine, au32Req[3], pvTmp, 1024);
                            }
                        }
                        else
                        {
                            printf("Syscall failed with %d uSts=%#x\n", rc, uSts);
                            if (rc)
                                uSts = 0x9;
                        }
                        free(pvTmp);
                    }
                    else
                    {
                        printf("Request not implemented, failing\n");
                        uSts = 0x9;
                    }

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x42: /* Unknown CCP operation. */
                {
                    PSPADDR PspAddrBufUnk = 0;
                    PSPADDR PspAddrSizeUnk = 0;
                    uint32_t cbUnk = 0;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &PspAddrBufUnk);
                    uc_reg_read(uc, UC_ARM_REG_R1, &PspAddrSizeUnk);
                    uc_mem_read(pThis->pUcEngine, PspAddrSizeUnk, &cbUnk, sizeof(cbUnk));

                    void *pvTmp = malloc(cbUnk);
                    uc_mem_read(pThis->pUcEngine, PspAddrBufUnk, pvTmp, cbUnk);

                    /* Sync input. */
                    int rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x20000, pvTmp, cbUnk);
                    PSPProxyCtxPspMemWrite(pThis->hProxyCtx, 0x21000, &cbUnk, sizeof(cbUnk));

                    rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x20000, 0x21000, 0, 0, &uSts);
                    if (rc)
                        printf("Executing syscall 0x42 failed with %d\n", rc);

                    /* Sync outputs. */
                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x21000, &cbUnk, sizeof(cbUnk));
                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x20000, pvTmp, cbUnk);
                    uc_mem_write(pThis->pUcEngine, PspAddrSizeUnk, &cbUnk, sizeof(cbUnk));
                    uc_mem_write(pThis->pUcEngine, PspAddrBufUnk, pvTmp, cbUnk);

                    //PSPEmuWriteData("/home/alex/onchip_fuses.bin", pvTmp, cbUnk);

                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    break;
                }
                case 0x48:  /* Returns boundaries of SMM region. */
                {
                    uint32_t UsrPtrSmmRegionStart = 0;
                    uint32_t UsrPtrSmmRegionSize  = 0;
                    uint32_t uSts = 0;

                    uc_reg_read(uc, UC_ARM_REG_R0, &UsrPtrSmmRegionStart);
                    uc_reg_read(uc, UC_ARM_REG_R1, &UsrPtrSmmRegionSize);

                    int rc = PSPProxyCtxPspSvcCall(pThis->hProxyCtx, idxSyscall, 0x20000, 0x21000, 0, 0, &uSts);
                    if (rc)
                        printf("Querying SMM region boundaries failed with %d\n", rc);

                    uint64_t PhysX86AddrSmmRegionStart = 0;
                    uint64_t SmmRegionSize = 0;

                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x20000, &PhysX86AddrSmmRegionStart, sizeof(PhysX86AddrSmmRegionStart));
                    PSPProxyCtxPspMemRead(pThis->hProxyCtx, 0x21000, &SmmRegionSize, sizeof(SmmRegionSize));

                    uc_mem_write(uc, UsrPtrSmmRegionStart, &PhysX86AddrSmmRegionStart, sizeof(uint64_t));
                    uc_mem_write(uc, UsrPtrSmmRegionSize, &SmmRegionSize, sizeof(uint64_t));

                    break;
                }
                default:
                    printf("Syscall %#x not implemented -> error\n", idxSyscall);
                    uint32_t uSts = 0x9;
                    uc_reg_write(uc, UC_ARM_REG_R0, &uSts);
                    //uc_emu_stop(uc);
                    break;
            }
        }
    }
}

static uint64_t pspEmuMemRead(PPSPCORE pThis, PSPADDR PspAddrRead, size_t cbRead)
{
    PSPDATUM Datum;

    int rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, PspAddrRead, &Datum.ab[0], cbRead);
    if (!rc)
    {
        switch (cbRead)
        {
            case 1:
                return Datum.u8;
            case 2:
                return Datum.u16;
            case 4:
                return Datum.u32;
            case 8:
                return Datum.u64;
            default:
                printf("Invalid read size %zu\n", cbRead);
        }
    }
    else
        printf("Error reading PSP memory from %#x\n", PspAddrRead);

    return 0;
}

static void pspEmuMemWrite(PPSPCORE pThis, PSPADDR PspAddrWrite, size_t cbWrite, uint64_t uVal)
{
    PSPDATUM Datum;

    switch (cbWrite)
    {
        case 1:
            Datum.u8 = (uint8_t)uVal;
            break;
        case 2:
            Datum.u16 = (uint16_t)uVal;
            break;
        case 4:
            Datum.u32 = (uint32_t)uVal;
            break;
        case 8:
            Datum.u64 = uVal;
            break;
        default:
            printf("Invalid write size %zu\n", cbWrite);
            return;
    }

    int rc = PSPProxyCtxPspMemWrite(pThis->hProxyCtx, PspAddrWrite, &Datum.ab[0], cbWrite);
    if (rc)
        printf("Error writing PSP memory at %#x\n", PspAddrWrite);
}

static uint64_t pspEmuSmnMapRead(struct uc_struct* uc, void *pvUser, uint64_t addr, unsigned size)
{
    PPSPCORE pThis = (PPSPCORE)pvUser;

    printf(">>> SMN read at 0x%08" PRIx32 "\n", _16M + (uint32_t)addr);
    return pspEmuMemRead(pThis, _16M + (uint32_t)addr, size);
}

static void pspEmuSmnMapWrite(struct uc_struct* uc, void *pvUser, uint64_t addr, uint64_t data, unsigned size)
{
    PPSPCORE pThis = (PPSPCORE)pvUser;

    printf(">>> SMN write 0x%08" PRIx64 " at 0x%08" PRIx32 "\n", data, _16M + (uint32_t)addr);
    pspEmuMemWrite(pThis, _16M + (uint32_t)addr, size, data);
}

static int pspEmuX86MapEnsureCache(PPSPX86MEMCACHEDMAPPING pMapping, uint64_t offAccess, size_t cbAccess)
{
    PCPSPCORE pThis = pMapping->pPspCore;

    /* Check whether the data at that address is already in memory and fetch it if required. */
    if (pMapping->PspAddrBase4K + offAccess + cbAccess > pMapping->PspAddrCached)
    {
        /* We cache always at 1K aligned segments. */
        size_t cbFetch = (pMapping->PspAddrBase4K + offAccess + cbAccess) - pMapping->PspAddrCached;
        cbFetch = (cbFetch + _1K) & ~(_1K - 1);

        /* Increase the mapping memory. */
        void *pvNew = realloc(pMapping->pvMapping, pMapping->cbAlloc + cbFetch);
        if (pvNew)
        {
            pMapping->pvMapping = pvNew;
            pMapping->cbAlloc   += cbFetch;

            int rc = PSPProxyCtxPspMemRead(pThis->hProxyCtx, pMapping->PspAddrCached, pMapping->pvMapping, cbFetch);
            if (!rc)
                pMapping->PspAddrCached += cbFetch;

            return rc;
        }

        return -1;
    }

    return 0;
}

static uint64_t pspEmuX86MapRead(struct uc_struct* uc, void *pvUser, uint64_t offRead, unsigned cbRead)
{
    PPSPX86MEMCACHEDMAPPING pMapping = (PPSPX86MEMCACHEDMAPPING)pvUser;
    PSPDATUM Datum;

    int rc = pspEmuX86MapEnsureCache(pMapping, offRead, cbRead);
    if (!rc)
    {
        memcpy(&Datum.ab[0], (uint8_t *)pMapping->pvMapping + offRead, cbRead);
        switch (cbRead)
        {
            case 1:
                return Datum.u8;
            case 2:
                return Datum.u16;
            case 4:
                return Datum.u32;
            case 8:
                return Datum.u64;
            default:
                printf("Invalid read size %u\n", cbRead);
        }
    }

    return 0;
}

static void pspEmuX86MapWrite(struct uc_struct* uc, void *pvUser, uint64_t offWrite, uint64_t uVal, unsigned cbWrite)
{
    PPSPX86MEMCACHEDMAPPING pMapping = (PPSPX86MEMCACHEDMAPPING)pvUser;
    PSPDATUM Datum;

    int rc = pspEmuX86MapEnsureCache(pMapping, offWrite, cbWrite);
    if (!rc)
    {
        switch (cbWrite)
        {
            case 1:
                Datum.u8 = (uint8_t)uVal;
                break;
            case 2:
                Datum.u16 = (uint16_t)uVal;
                break;
            case 4:
                Datum.u32 = (uint32_t)uVal;
                break;
            case 8:
                Datum.u64 = uVal;
                break;
            default:
                printf("Invalid write size %u\n", cbWrite);
                return;
        }

        memcpy((uint8_t *)pMapping->pvMapping + offWrite, &Datum.ab[0], cbWrite);
        if (pMapping->PspAddrBase4K + offWrite + cbWrite > pMapping->PspAddrHighestWritten)
            pMapping->PspAddrHighestWritten = pMapping->PspAddrBase4K + offWrite + cbWrite;
    }
}
#endif


/**
 * Load the firmware from the given filename.
 *
 * @returns Status code.
 * @param   pszFilename
 * @param   ppvFw
 * @param   pcb
 */
int PSPEmuLoadFw(const char *pszFilename, void **ppvFw, size_t *pcbFw)
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
                        *ppvFw = pvFw;
                        *pcbFw = cbFw;
                        return 0;
                    }

                    free(pvFw);
                    rc = EINVAL;
                }
                else
                    rc = ENOMEM;
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

int PSPEmuCoreCreate(PPSPCORE *ppPspCore, const char *pszFw)
{
    int rc = 0;
    PPSPCORE pThis = (PPSPCORE)calloc(1, sizeof(*pThis));

    if (pThis)
    {
        rc = PSPProxyCtxCreate(&pThis->hProxyCtx, "/dev/sev");
        if (!rc)
        {
            uc_err err;

            /* Initialize unicorn engine in ARM mode. */
            err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &pThis->pUcEngine);
            if (!err)
            {
                /* Allocate the shared memory region for the proxied PSP. */
                pThis->cbShm = 2 * 1024 * 1024;
                rc = PSPProxyCtxX86MemAlloc(pThis->hProxyCtx, pThis->cbShm, &pThis->R0AddrShm, &pThis->PhysX86AddrShm);
                if (!rc)
                {
                    rc = PSPEmuLoadFw(pszFw, &pThis->pvFw, &pThis->cbFw);
                    if (!rc)
                    {
                        *ppPspCore = pThis;
                        return 0;
                    }

                    PSPProxyCtxX86MemFree(pThis->hProxyCtx, pThis->R0AddrShm);
                }

                uc_close(pThis->pUcEngine);
            }
            else
            {
                printf("not ok - Failed on uc_open() with error: %s\n", uc_strerror(err));
                rc = EINVAL;
            }

            PSPProxyCtxDestroy(pThis->hProxyCtx);
        }
        else
            rc = EPERM;

        free(pThis);
    }
    else
        rc = ENOMEM;

    return rc;
}

int PSPEmuCoreDestroy(PPSPCORE pThis)
{
    uc_close(pThis->pUcEngine);
    PSPProxyCtxX86MemFree(pThis->hProxyCtx, pThis->R0AddrShm);
    PSPProxyCtxDestroy(pThis->hProxyCtx);
    free(pThis->pvFw);
    free(pThis);

    return 0;
}

int main(int argc, char *argv[])
{
#ifdef DYNLOAD
    if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading shared library.\n");
        printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
        printf("any other dependent dll/so files.\n");
        printf("The easiest way is to place them in the same directory as this app.\n");
        return 1;
    }
#endif

    PPSPCORE pPspCore = NULL;
    int rc = PSPEmuCoreCreate(&pPspCore, argv[1]);
    if (!rc)
    {
        uc_err err;
        uc_hook trace;

#ifdef PSP_EMU_SYSTEM
        /* Map the SRAM the PSP starts from. */
        uc_mem_map(pPspCore->pUcEngine, 0x0, _256K, UC_PROT_ALL);
        if (uc_mem_write(pPspCore->pUcEngine, 0x0, pPspCore->pvFw, pPspCore->cbFw)) {
            printf("not ok - Failed to write emulation code to memory, quit!\n");
            return 1;
        }

        /* Map the FW stack. */
        uc_mem_map(pPspCore->pUcEngine, 0x50000, 2 * 4096, UC_PROT_ALL);

        /* Map the CCP MMIO region. */
        uc_mmio_map(pPspCore->pUcEngine, 0x03000000, 6 * 0x1000, pspEmuCcpMmioRead, pspEmuCcpMmioWrite, pPspCore);

        /* Unknown devices. */
        uc_mmio_map(pPspCore->pUcEngine, 0x03006000, 0x1000, pspEmuUnkDevMmioRead, pspEmuUnkDevMmioWrite, pPspCore);
        uc_mmio_map(pPspCore->pUcEngine, 0x03010000, 0x1000, pspEmuUnkDevMmioRead, pspEmuUnkDevMmioWrite, pPspCore);
        uc_mmio_map(pPspCore->pUcEngine, 0x03200000, 0x1000, pspEmuUnkDevMmioRead, pspEmuUnkDevMmioWrite, pPspCore);

        // tracing one instruction at ADDRESS with customized callback
        uc_hook_add(pPspCore->pUcEngine, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, pPspCore, 0, 0x6028);

        printf("BEGINNING EXECUTION\n");
        err = uc_emu_start(pPspCore->pUcEngine, 0x100, 0x15100, 0, 0);
        printf("Execution stopped with: %s\n", uc_strerror(err));
        print_ctx(pPspCore->pUcEngine);

#elif defined(PSP_EMU_APP) /* App mode */

        for (uint32_t i = 0; i < ELEMENTS(pPspCore->aX86Mappings); i++)
            pPspCore->aX86Mappings[i].PhysX86AddrBase = NIL_X86PADDR;

        pPspCore->X86MappingPrivState.PhysX86AddrBase = NIL_X86PADDR;

        /* SMN mapping space. */
        uc_mmio_map(pPspCore->pUcEngine, _16M, _32M, pspEmuSmnMapRead, pspEmuSmnMapWrite, pPspCore);

        uc_hook_add(pPspCore->pUcEngine, &trace, UC_HOOK_INTR, (void *)(uintptr_t)psp_emu_app_svc, pPspCore, 1, 0);

        void *pvMbx = malloc(PAGE_SIZE);
        uc_mem_map_ptr(pPspCore->pUcEngine, 0xf00d0000, PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE, pvMbx);

        uc_mem_map(pPspCore->pUcEngine, 0x15000, 172 * _1K, UC_PROT_ALL);
        if (uc_mem_write(pPspCore->pUcEngine, 0x15000, pPspCore->pvFw, pPspCore->cbFw)) {
            printf("not ok - Failed to write emulation code to memory, quit!\n");
            return 1;
        }

        int fFirstRun = 1;
        do
        {
            int r0 = 0x0;        /* R0 register, idCcd */
            int r1 = 0x8;        /* R1 register, cCcds */
            int r2 = 0xf00d0000; /* R2 register, pvCmdBuf */
            int r3 = fFirstRun;  /* R3 register, fFirstRun */

            /* Wait for work. */
            uint32_t idCmd;
            X86PADDR PhysX86AddrCmdBuf;
            rc = PSPProxyCtxEmuWaitForWork(pPspCore->hProxyCtx, &idCmd, &PhysX86AddrCmdBuf, 100/*ms*/);
            if (rc)
                continue; /** @todo Check status code for other things than timeout. */

            SEVCMDBUF CmdBuf;
            CmdBuf.idCmd                 = idCmd << 16;
            CmdBuf.PhysX86AddrCmdBufLow  = (uint32_t)(PhysX86AddrCmdBuf & 0xffffffff);
            CmdBuf.PhysX86AddrCmdBufHigh = (uint32_t)(PhysX86AddrCmdBuf >> 32);
            memcpy(pvMbx, &CmdBuf, sizeof(CmdBuf));

            uc_reg_write(pPspCore->pUcEngine, UC_ARM_REG_R0, &r0);
            uc_reg_write(pPspCore->pUcEngine, UC_ARM_REG_R1, &r1);
            uc_reg_write(pPspCore->pUcEngine, UC_ARM_REG_R2, &r2);
            uc_reg_write(pPspCore->pUcEngine, UC_ARM_REG_R3, &r3);

            uc_hook_add(pPspCore->pUcEngine, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, NULL, 0x1b730, 0x1b730);
            uc_hook_add(pPspCore->pUcEngine, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, NULL, 0x1b768, 0x1b768);
            uc_hook_add(pPspCore->pUcEngine, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, NULL, 0x1b756, 0x1b756);
            uc_hook_add(pPspCore->pUcEngine, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, NULL, 0x1b726, 0x1b726);
            uc_hook_add(pPspCore->pUcEngine, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, NULL, 0x19e26, 0x19e26);

#if 0
            uc_hook_add(uc, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, NULL, 0x1c18c, 0x1c190);
            uc_hook_add(uc, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, NULL, 0x1be4c, 0x1be50);
            uc_hook_add(uc, &trace, UC_HOOK_CODE, (void *)(uintptr_t)hook_code, NULL, 0x1bf72, 0x1bf72);
#endif

            printf("Starting execution of command %#x\n", idCmd);
            err = uc_emu_start(pPspCore->pUcEngine, 0x15100, 0x1c2a4, 0, 0);

            uint32_t u32R0Return;
            uc_reg_read(pPspCore->pUcEngine, UC_ARM_REG_R0, &u32R0Return);

            printf("Execution stopped with: %s (r0 = %#x)\n", uc_strerror(err), u32R0Return);
            print_ctx(pPspCore->pUcEngine);
            fFirstRun = 0;

            rc = PSPProxyCtxEmuSetResult(pPspCore->hProxyCtx, u32R0Return);
            if (rc)
            {
                printf("Setting result failed with %d\n", rc);
                break;
            }

        } while (1);
#endif

        PSPEmuCoreDestroy(pPspCore);
    }
    else
        printf("Failed to create PSP core instance: %d\n", rc);

#ifdef DYNLOAD
    uc_dyn_free();
#endif

    return 0;
}

