#include <Windows.h>
#include <WinHvPlatform.h>

#include <cstdint>
#include <cstdio>

#include "whvp.h"

#define PAGE_SIZE 0x1000

//#define DO_MANUAL_INIT
//#define DO_MANUAL_JMP
//#define DO_MANUAL_PAGING

uint8_t *allocateMemory(const uint32_t size) {
    LPVOID mem = VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL) {
        return NULL;
    }
    return (uint8_t *)VirtualAlloc(mem, size, MEM_COMMIT, PAGE_READWRITE);
}

void printRegs(WHvVCPU *vcpu) {
    WHV_REGISTER_NAME regs[] = {
        WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterEfer,
        WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3, WHvX64RegisterCr4, WHvX64RegisterRsp, WHvX64RegisterRbp, WHvX64RegisterGdtr,
        WHvX64RegisterDr0, WHvX64RegisterDr1, WHvX64RegisterDr2, WHvX64RegisterDr3, WHvX64RegisterDr6, WHvX64RegisterDr7, WHvX64RegisterIdtr,
        WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs, WHvX64RegisterFs, WHvX64RegisterGs, WHvX64RegisterSs, WHvX64RegisterTr, WHvX64RegisterLdtr,
        WHvX64RegisterRip, WHvX64RegisterRflags,
    };
    WHV_REGISTER_VALUE vals[sizeof(regs) / sizeof(regs[0])];

    WHvVCPUStatus vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("Failed to retrieve VCPU registers\n");
        return;
    }

    printf("EAX = %08x   EBX = %08x   ECX = %08x   EDX = %08x   ESI = %08x   EDI = %08x  EFER = %08x\n", vals[0].Reg32, vals[1].Reg32, vals[2].Reg32, vals[3].Reg32, vals[4].Reg32, vals[5].Reg32, vals[6].Reg32);
    printf("CR0 = %08x   CR2 = %08x   CR3 = %08x   CR4 = %08x   ESP = %08x   EBP = %08x   GDT = %08x:%04x\n", vals[7].Reg32, vals[8].Reg32, vals[9].Reg32, vals[10].Reg32, vals[11].Reg32, vals[12].Reg32, vals[13].Table.Base, vals[13].Table.Limit);
    printf("DR0 = %08x   DR1 = %08x   DR2 = %08x   DR3 = %08x   DR6 = %08x   DR7 = %08x   IDT = %08x:%04x\n", vals[14].Reg32, vals[15].Reg32, vals[16].Reg32, vals[17].Reg32, vals[18].Reg32, vals[19].Reg32, vals[20].Table.Base, vals[20].Table.Limit);
    printf(" CS = %04x   DS = %04x   ES = %04x   FS = %04x   GS = %04x   SS = %04x   TR = %04x   LDT = %08x:%04x\n", vals[21].Segment.Selector, vals[22].Segment.Selector, vals[23].Segment.Selector, vals[24].Segment.Selector, vals[25].Segment.Selector, vals[26].Segment.Selector, vals[27].Segment.Selector, vals[28].Table.Base, vals[28].Table.Limit);
    printf("EIP = %08x   EFLAGS = %08x\n", vals[29].Reg32, vals[30].Reg32);
}

int main() {
    // Initialize ROM and RAM
    const uint32_t romSize = PAGE_SIZE * 16;  // 64 KiB
    const uint32_t ramSize = PAGE_SIZE * 240; // 960 KiB
    const UINT64 romBase = 0xF0000;
    const UINT64 ramBase = 0x0;

    uint8_t *rom = allocateMemory(romSize);
    if (rom == NULL) {
        printf("Failed to allocate ROM memory: error code %d\n", GetLastError());
        return -1;
    }
    printf("ROM allocated: %u bytes\n", romSize);

    uint8_t *ram = allocateMemory(ramSize);
    if (ram == NULL) {
        printf("Failed to allocate RAM memory: error code %d\n", GetLastError());
        return -1;
    }
    printf("RAM allocated: %u bytes\n", ramSize);
    printf("\n");

    // Fill ROM with HLT instructions
    FillMemory(rom, romSize, 0xf4);

    // Zero out RAM
    ZeroMemory(ram, ramSize);

    {
        uint32_t addr;
#define emit(buf, code) {memcpy(&buf[addr], code, sizeof(code) - 1); addr += sizeof(code) - 1;}

        // --- Start of ROM code ----------------------------------------------------------------------------------------------

        // --- GDT and IDT tables ---------------------------------------------------------------------------------------------

        // GDT table
        addr = 0x0000;
        emit(rom, "\x00\x00\x00\x00\x00\x00\x00\x00"); // [0x0000] GDT entry 0: null
        emit(rom, "\xff\xff\x00\x00\x00\x9b\xcf\x00"); // [0x0008] GDT entry 1: code (full access to 4 GB linear space)
        emit(rom, "\xff\xff\x00\x00\x00\x93\xcf\x00"); // [0x0010] GDT entry 2: data (full access to 4 GB linear space)

        // IDT table (system)
        // All entries are present, 80386 32-bit trap gates, privilege level 0, use selector 0x8 and offset 0x10001005
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0018] Vector 0x00: Divide by zero
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0020] Vector 0x01: Reserved
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0028] Vector 0x02: Non-maskable interrupt
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0030] Vector 0x03: Breakpoint (INT3)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0038] Vector 0x04: Overflow (INTO)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0040] Vector 0x05: Bounds range exceeded (BOUND)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0048] Vector 0x06: Invalid opcode (UD2)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0050] Vector 0x07: Device not available (WAIT/FWAIT)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0058] Vector 0x08: Double fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0060] Vector 0x09: Coprocessor segment overrun
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0068] Vector 0x0A: Invalid TSS
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0070] Vector 0x0B: Segment not present
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0078] Vector 0x0C: Stack-segment fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0080] Vector 0x0D: General protection fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0088] Vector 0x0E: Page fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0090] Vector 0x0F: Reserved
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0098] Vector 0x10: x87 FPU error
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00a0] Vector 0x11: Alignment check
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00a8] Vector 0x12: Machine check
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00b0] Vector 0x13: SIMD Floating-Point Exception
        for (uint8_t i = 0x14; i <= 0x1f; i++) {
            emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00b8..0x0110] Vector 0x14..0x1F: Reserved
        }

        // IDT table (user defined)
        // All entries are present, 80386 32-bit trap gates, privilege level 0 and use selector 0x8
        emit(rom, "\x00\x10\x08\x00\x00\x8f\x00\x10"); // [0x0118] Vector 0x20: Just IRET       (offset 0x10001000)
        emit(rom, "\x02\x10\x08\x00\x00\x8f\x00\x10"); // [0x0120] Vector 0x21: HLT, then IRET  (offset 0x10001002)

        // --- 32-bit protected mode ------------------------------------------------------------------------------------------

        // Prepare memory for paging
        // 0x1000 = Page directory
        // 0x2000 = Page table (identity map RAM: 0x000xxxxx)
        // 0x3000 = Page table (identity map ROM: 0x000fxxxx)
        // 0x4000 = Page table (0x10000xxx .. 0x10001xxx -> 0x00005xxx .. 0x00006xxx)
        // 0x5000 = Data area (first dword reads 0xdeadbeef)
        // 0x6000 = Interrupt handler code area
        // 0xe000 = Page table (identity map first page of MMIO: 0xe00000xxx)

        // Load segment registers
        addr = 0xff00;
#ifdef DO_MANUAL_PAGING
        emit(rom, "\xf4");                             // [0xff00] hlt
        emit(rom, "\x90");                             // [0xff01] nop
#else
        emit(rom, "\x33\xc0");                         // [0xff00] xor    eax, eax
#endif
        emit(rom, "\xb0\x10");                         // [0xff02] mov     al, 0x10
        emit(rom, "\x8e\xd8");                         // [0xff04] mov     ds, eax
        emit(rom, "\x8e\xc0");                         // [0xff06] mov     es, eax
        emit(rom, "\x8e\xd0");                         // [0xff08] mov     ss, eax

        // Clear page directory
        emit(rom, "\xbf\x00\x10\x00\x00");             // [0xff0a] mov    edi, 0x1000
        emit(rom, "\xb9\x00\x10\x00\x00");             // [0xff0f] mov    ecx, 0x1000
        emit(rom, "\x31\xc0");                         // [0xff14] xor    eax, eax
        emit(rom, "\xf3\xab");                         // [0xff16] rep    stosd

        // Write 0xdeadbeef at physical memory address 0x5000
        emit(rom, "\xbf\x00\x50\x00\x00");             // [0xff18] mov    edi, 0x5000
        emit(rom, "\xb8\xef\xbe\xad\xde");             // [0xff1d] mov    eax, 0xdeadbeef
        emit(rom, "\x89\x07");                         // [0xff22] mov    [edi], eax

        // Identity map the RAM to 0x00000000
        emit(rom, "\xb9\x00\x01\x00\x00");             // [0xff24] mov    ecx, 0xf0
        emit(rom, "\xbf\x00\x20\x00\x00");             // [0xff29] mov    edi, 0x2000
        emit(rom, "\xb8\x03\x00\x00\x00");             // [0xff2e] mov    eax, 0x0003
                                                       // aLoop:
        emit(rom, "\xab");                             // [0xff33] stosd
        emit(rom, "\x05\x00\x10\x00\x00");             // [0xff34] add    eax, 0x1000
        emit(rom, "\xe2\xf8");                         // [0xff39] loop   aLoop

        // Identity map the ROM
        emit(rom, "\xb9\x10\x00\x00\x00");             // [0xff3b] mov    ecx, 0x10
        emit(rom, "\xbf\xc0\x3f\x00\x00");             // [0xff40] mov    edi, 0x3fc0
        emit(rom, "\xb8\x03\x00\x0f\x00");             // [0xff45] mov    eax, 0xf0003
                                                       // bLoop:
        emit(rom, "\xab");                             // [0xff4a] stosd
        emit(rom, "\x05\x00\x10\x00\x00");             // [0xff4b] add    eax, 0x1000
        emit(rom, "\xe2\xf8");                         // [0xff50] loop   bLoop

        // Map physical address 0x5000 to virtual address 0x10000000
        emit(rom, "\xbf\x00\x40\x00\x00");             // [0xff52] mov    edi, 0x4000
        emit(rom, "\xb8\x03\x50\x00\x00");             // [0xff57] mov    eax, 0x5003
        emit(rom, "\x89\x07");                         // [0xff5c] mov    [edi], eax

        // Map physical address 0x6000 to virtual address 0x10001000
        emit(rom, "\xbf\x04\x40\x00\x00");             // [0xff5e] mov    edi, 0x4004
        emit(rom, "\xb8\x03\x60\x00\x00");             // [0xff63] mov    eax, 0x6003
        emit(rom, "\x89\x07");                         // [0xff68] mov    [edi], eax

        // Map physical address 0xe0000000 to virtual address 0xe0000000 (for MMIO)
        emit(rom, "\xbf\x00\xe0\x00\x00");             // [0xff6a] mov    edi, 0xe000
        emit(rom, "\xb8\x03\x00\x00\xe0");             // [0xff6f] mov    eax, 0xe0000003
        emit(rom, "\x89\x07");                         // [0xff74] mov    [edi], eax

        // Add page tables into page directory
        emit(rom, "\xbf\x00\x10\x00\x00");             // [0xff76] mov    edi, 0x1000
        emit(rom, "\xb8\x03\x20\x00\x00");             // [0xff7b] mov    eax, 0x2003
        emit(rom, "\x89\x07");                         // [0xff80] mov    [edi], eax
        emit(rom, "\xbf\xfc\x1f\x00\x00");             // [0xff82] mov    edi, 0x1ffc
        emit(rom, "\xb8\x03\x30\x00\x00");             // [0xff87] mov    eax, 0x3003
        emit(rom, "\x89\x07");                         // [0xff8c] mov    [edi], eax
        emit(rom, "\xbf\x00\x11\x00\x00");             // [0xff8e] mov    edi, 0x1100
        emit(rom, "\xb8\x03\x40\x00\x00");             // [0xff93] mov    eax, 0x4003
        emit(rom, "\x89\x07");                         // [0xff98] mov    [edi], eax
        emit(rom, "\xbf\x00\x1e\x00\x00");             // [0xff9a] mov    edi, 0x1e00
        emit(rom, "\xb8\x03\xe0\x00\x00");             // [0xff9f] mov    eax, 0xe003
        emit(rom, "\x89\x07");                         // [0xffa4] mov    [edi], eax

        // Load the page directory register
        emit(rom, "\xb8\x00\x10\x00\x00");             // [0xffa6] mov    eax, 0x1000
        emit(rom, "\x0f\x22\xd8");                     // [0xffab] mov    cr3, eax

        // Enable paging
        emit(rom, "\x0f\x20\xc0");                     // [0xffae] mov    eax, cr0
        emit(rom, "\x0d\x00\x00\x00\x80");             // [0xffb1] or     eax, 0x80000000
        emit(rom, "\x0f\x22\xc0");                     // [0xffb6] mov    cr0, eax

        // Clear EAX
        emit(rom, "\x31\xc0");                         // [0xffb9] xor    eax, eax

        // Load using virtual memory address; EAX = 0xdeadbeef
        emit(rom, "\xbe\x00\x00\x00\x10");             // [0xffbb] mov    esi, 0x10000000
        emit(rom, "\x8b\x06");                         // [0xffc0] mov    eax, [esi]

        // First stop
        emit(rom, "\xf4");                             // [0xffc2] hlt

        // Jump to RAM
        emit(rom, "\xe9\x3c\x00\xf0\x0f");             // [0xffc3] jmp    0x10000004
                                                       // .. ends at 0xffc7

        // --- 16-bit real mode transition to 32-bit protected mode -----------------------------------------------------------

        // Load GDT and IDT tables
        addr = 0xffd0;
        emit(rom, "\x66\x2e\x0f\x01\x16\xf2\xff");     // [0xffd0] lgdt   [cs:0xfff2]
        emit(rom, "\x66\x2e\x0f\x01\x1e\xf8\xff");     // [0xffd7] lidt   [cs:0xfff8]

        // Enter protected mode
        emit(rom, "\x0f\x20\xc0");                     // [0xffde] mov    eax, cr0
        emit(rom, "\x0c\x01");                         // [0xffe1] or      al, 1
        emit(rom, "\x0f\x22\xc0");                     // [0xffe3] mov    cr0, eax
#ifdef DO_MANUAL_JMP
        emit(rom, "\xf4")                              // [0xffe6] hlt
        // Fill the rest with HLTs
            while (addr < 0xfff0) {
                emit(rom, "\xf4");                         // [0xffe7..0xffef] hlt
            }
#else
        emit(rom, "\x66\xea\x00\xff\x0f\x00\x08\x00"); // [0xffe6] jmp    dword 0x8:0x000fff00
        emit(rom, "\xf4");                             // [0xffef] hlt
#endif

        // --- 16-bit real mode start -----------------------------------------------------------------------------------------

        // Jump to initialization code and define GDT/IDT table pointer
        addr = 0xfff0;
#ifdef DO_MANUAL_INIT
        emit(rom, "\xf4");                             // [0xfff0] hlt
        emit(rom, "\x90");                             // [0xfff1] nop
#else
        emit(rom, "\xeb\xde");                         // [0xfff0] jmp    short 0x1d0
#endif
        emit(rom, "\x18\x00\x00\x00\x0f\x00");         // [0xfff2] GDT pointer: 0x000f0000:0x0018
        emit(rom, "\x10\x01\x18\x00\x0f\x00");         // [0xfff8] IDT pointer: 0x000f0018:0x0110
        // There's room for two bytes at the end, so let's fill it up with HLTs
        emit(rom, "\xf4");                             // [0xfffe] hlt
        emit(rom, "\xf4");                             // [0xffff] hlt

        // --- End of ROM code ------------------------------------------------------------------------------------------------

        // --- Start of RAM code ----------------------------------------------------------------------------------------------
        addr = 0x5004; // Addresses 0x5000..0x5003 are reserved for 0xdeadbeef
        // Note that these addresses are mapped to virtual addresses 0x10000000 through 0x10000fff

        // Do some basic stuff
        emit(ram, "\xba\x78\x56\x34\x12");             // [0x5004] mov    edx, 0x12345678
        emit(ram, "\xbf\x00\x00\x00\x10");             // [0x5009] mov    edi, 0x10000000
        emit(ram, "\x31\xd0");                         // [0x500e] xor    eax, edx
        emit(ram, "\x89\x07");                         // [0x5010] mov    [edi], eax
        emit(ram, "\xf4");                             // [0x5012] hlt

        // Setup a proper stack
        emit(ram, "\x31\xed");                         // [0x5013] xor    ebp, ebp
        emit(ram, "\xbc\x00\x00\x0f\x00");             // [0x5015] mov    esp, 0xf0000

        // Test the stack
        emit(ram, "\x68\xfe\xca\x0d\xf0");             // [0x501a] push   0xf00dcafe
        emit(ram, "\x5a");                             // [0x501f] pop    edx
        emit(ram, "\xf4");                             // [0x5020] hlt

        // -------------------------------

        // Call interrupts
        emit(ram, "\xcd\x20");                         // [0x5021] int    0x20
        emit(ram, "\xcd\x21");                         // [0x5023] int    0x21
        emit(ram, "\xf4");                             // [0x5025] hlt

        // -------------------------------

        // Basic PMIO
        emit(ram, "\x66\xba\x00\x10");                 // [0x5026] mov     dx, 0x1000
        emit(ram, "\xec");                             // [0x502a] in      al, dx
        emit(ram, "\x66\x42");                         // [0x502b] inc     dx
        emit(ram, "\x34\xff");                         // [0x502d] xor     al, 0xff
        emit(ram, "\xee");                             // [0x502f] out     dx, al
        emit(ram, "\x66\x42");                         // [0x5030] inc     dx
        emit(ram, "\x66\xed");                         // [0x5032] in      ax, dx
        emit(ram, "\x66\x42");                         // [0x5034] inc     dx
        emit(ram, "\x66\x83\xf0\xff");                 // [0x5036] xor     ax, 0xffff
        emit(ram, "\x66\xef");                         // [0x503a] out     dx, ax
        emit(ram, "\x66\x42");                         // [0x503c] inc     dx
        emit(ram, "\xed");                             // [0x503e] in     eax, dx
        emit(ram, "\x66\x42");                         // [0x503f] inc     dx
        emit(ram, "\x83\xf0\xff");                     // [0x5041] xor    eax, 0xffffffff
        emit(ram, "\xef");                             // [0x5044] out     dx, eax

        // -------------------------------

        // Basic MMIO
        emit(ram, "\xbf\x00\x00\x00\xe0");             // [0x5045] mov    edi, 0xe0000000
        emit(ram, "\x8b\x1f");                         // [0x504a] mov    ebx, [edi]
        emit(ram, "\x83\xc7\x04");                     // [0x504c] add    edi, 4
        emit(ram, "\x89\x1f");                         // [0x504f] mov    [edi], ebx

        // Advanced MMIO
        emit(ram, "\xb9\x00\x00\x00\x10");             // [0x5051] mov    ecx, 0x10000000
        emit(ram, "\x85\x0f");                         // [0x5056] test   [edi], ecx

        // -------------------------------

        // End
        emit(ram, "\xf4");                             // [0x5058] hlt

        // -------------------------------

        addr = 0x6000; // Interrupt handlers
        // Note that these addresses are mapped to virtual addresses 0x10001000 through 0x10001fff
        // 0x20: Just IRET
        emit(ram, "\xfb");                             // [0x6000] sti
        emit(ram, "\xcf");                             // [0x6001] iretd

        // 0x21: HLT, then IRET
        emit(ram, "\xf4");                             // [0x6002] hlt
        emit(ram, "\xfb");                             // [0x6003] sti
        emit(ram, "\xcf");                             // [0x6004] iretd

        // 0x00 .. 0x1F: Clear stack then IRET
        emit(ram, "\x83\xc4\x04");                     // [0x6005] add    esp, 4
        emit(ram, "\xfb");                             // [0x6008] sti
        emit(ram, "\xcf");                             // [0x6009] iretd

#undef emit
    }

    // ----- Hypervisor platform initialization -------------------------------------------------------------------------------

    // Initialize the hypervisor platform
    WinHvPlatform whvp;
    if (whvp.IsPresent()) {
        printf("Hyper-V platform present\n");
    }
    else {
        printf("Hyper-V platform absent\n");
        return -1;
    }

    // Check CPU vendor
    WHV_CAPABILITY cap;
    WHvStatus status = whvp.GetCapability(WHvCapabilityCodeProcessorVendor, &cap);
    if (WHVS_SUCCESS == status) {
        printf("CPU vendor: ");
        switch (cap.ProcessorVendor) {
        case WHvProcessorVendorAmd: printf("AMD\n"); break;
        case WHvProcessorVendorIntel: printf("Intel\n"); break;
        default: printf("Unknown: 0x%x\n", cap.ProcessorVendor); break;
        }
    }

    printf("\n");

    // Create a partition
    WHvPartition *partition;
    WHvPartitionStatus partStatus = whvp.CreatePartition(&partition);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to create partition\n");
        return -1;
    }
    printf("Partition created\n");

    // Give one processor to the partition
    WHV_PARTITION_PROPERTY partitionProperty;
    partitionProperty.ProcessorCount = 1;
    partStatus = partition->SetProperty(WHvPartitionPropertyCodeProcessorCount, &partitionProperty);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to set processor count to partition\n");
        return -1;
    }
    printf("Set processor count to %u\n", partitionProperty.ProcessorCount);

    // Setup the partition
    partStatus = partition->Setup();
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to setup partition\n");
        return -1;
    }
    printf("Partition setup completed\n");

    // Map ROM to the top of the 32-bit address range
    partStatus = partition->MapGpaRange(rom, romBase, romSize, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to map guest physical address range for ROM\n");
        return -1;
    }
    printf("Mapped ROM to top of 32-bit address range\n");

    // Map RAM to the bottom of the 32-bit address range
    partStatus = partition->MapGpaRange(ram, ramBase, ramSize, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to map guest physical address range for RAM\n");
        return -1;
    }
    printf("Mapped RAM to bottom of 32-bit address range\n");

    // Create a VCPU
    WHvVCPU *vcpu;
    const UINT32 vpIndex = 0;
    WHvVCPUStatus vcpuStatus = partition->CreateVCPU(&vcpu, vpIndex);
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("Failed to create VCPU\n");
        return -1;
    }
    printf("VCPU created with virtual processor index %u\n", vpIndex);

#ifdef DO_MANUAL_INIT
    {
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterGdtr,
            WHvX64RegisterIdtr,
            WHvX64RegisterCr0,
            WHvX64RegisterRip,
        };
        WHV_REGISTER_VALUE vals[sizeof(regs) / sizeof(regs[0])];

        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }

        // Load GDT table
        vals[0].Table.Base = romBase;
        vals[0].Table.Limit = 0x0018;

        // Load IDT table
        vals[1].Table.Base = romBase + 0x18;
        vals[1].Table.Limit = 0x0110;

        // Enter protected mode
        vals[2].Reg32 |= 1;

        // Skip initialization code
        vals[3].Reg32 = 0xffe6;

        vcpuStatus = vcpu->SetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to set VCPU registers\n");
            return -1;
        }
    }
#endif

    printf("\nInitial CPU register state:\n");
    printRegs(vcpu);
    printf("\n");

    // ----- Start of emulation -----------------------------------------------------------------------------------------------

    // The CPU starts in 16-bit real mode.
    // Memory addressing is based on segments and offsets, where a segment is basically a 16-byte offset.
    
    // Run the CPU!
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

#ifdef DO_MANUAL_JMP
    {
        // Do the jmp dword 0x8:0xffffff00 manually
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterCs,
            WHvX64RegisterRip,
            WHvX64RegisterGdtr,
        };
        WHV_REGISTER_VALUE vals[sizeof(regs) / sizeof(regs[0])];

        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }

        // Set basic register data
        vals[0].Segment.Selector = 0x0008;
        vals[1].Reg32 = 0xfff00;

        // Find GDT entry in memory
        uint64_t gdtEntry;
        if (vals[2].Table.Base >= ramBase && vals[2].Table.Base <= ramBase + ramSize - 1) {
            // GDT is in RAM
            gdtEntry = *(uint64_t *)&ram[vals[2].Table.Base - ramBase + vals[0].Segment.Selector];
        }
        else if (vals[2].Table.Base >= romBase && vals[2].Table.Base <= romBase + romSize - 1) {
            // GDT is in ROM
            gdtEntry = *(uint64_t *)&rom[vals[2].Table.Base - romBase + vals[0].Segment.Selector];
        }

        // Fill in the rest of the CS info with data from the GDT entry
        vals[0].Segment.Attributes = ((gdtEntry >> 40) & 0xf0ff);
        vals[0].Segment.Base = ((gdtEntry >> 16) & 0xfffff) | (((gdtEntry >> 56) & 0xff) << 20);
        vals[0].Segment.Limit = ((gdtEntry & 0xffff) | (((gdtEntry >> 48) & 0xf) << 16));
        if (vals[0].Segment.Attributes & 0x8000) {
            // 4 KB pages
            vals[0].Segment.Limit = (vals[0].Segment.Limit << 12) | 0xfff;
        }

        vcpuStatus = vcpu->SetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to set VCPU registers\n");
            return -1;
        }
    }

    // Run the CPU again!
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }
#endif

#ifdef DO_MANUAL_PAGING
    {
        // Prepare the registers
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterRax,
            WHvX64RegisterRsi,
            WHvX64RegisterRip,
            WHvX64RegisterCr0,
            WHvX64RegisterCr3,
            WHvX64RegisterSs,
            WHvX64RegisterDs,
            WHvX64RegisterEs,
        };
        WHV_REGISTER_VALUE vals[sizeof(regs) / sizeof(regs[0])];

        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }
        vals[0].Reg32 = 0;
        vals[1].Reg32 = 0x10000000;
        vals[2].Reg32 = 0xfffc0;
        vals[3].Reg32 = 0xe0000011;
        vals[4].Reg32 = 0x1000;
        vals[5].Segment.Selector = vals[6].Segment.Selector = vals[7].Segment.Selector = 0x0010;
        vals[5].Segment.Limit = vals[6].Segment.Limit = vals[7].Segment.Limit = 0xffffffff;
        vals[5].Segment.Base = vals[6].Segment.Base = vals[7].Segment.Base = 0;
        vals[5].Segment.Attributes = vals[6].Segment.Attributes = vals[7].Segment.Attributes = 0xc093;

        vcpuStatus = vcpu->SetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to set VCPU registers\n");
            return -1;
        }

        // Clear page directory
        memset(&ram[0x1000], 0, 0x1000);

        // Write 0xdeadbeef at physical memory address 0x5000
        *(uint32_t *)&ram[0x5000] = 0xdeadbeef;

        // Identity map the RAM to 0x00000000
        for (uint32_t i = 0; i < 0xf0; i++) {
            *(uint32_t *)&ram[0x2000 + i * 4] = 0x0003 + i * 0x1000;
        }

        // Identity map the ROM
        for (uint32_t i = 0; i < 0x10; i++) {
            *(uint32_t *)&ram[0x3fc0 + i * 4] = 0xf0003 + i * 0x1000;
        }

        // Map physical address 0x5000 to virtual address 0x10000000
        *(uint32_t *)&ram[0x4000] = 0x5003;

        // Map physical address 0x6000 to virtual address 0x10001000
        *(uint32_t *)&ram[0x4004] = 0x6003;

        // Map physical address 0xe0000000 to virtual address 0xe0000000
        *(uint32_t *)&ram[0xe000] = 0xe0000003;

        // Add page tables into page directory
        *(uint32_t *)&ram[0x1000] = 0x2003;
        *(uint32_t *)&ram[0x1ffc] = 0x3003;
        *(uint32_t *)&ram[0x1100] = 0x4003;
        *(uint32_t *)&ram[0x1e00] = 0xe003;

        // Run the CPU again!
        vcpuStatus = vcpu->Run();
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("VCPU failed to run\n");
            return -1;
        }
    }
#endif

    // ----- First part -------------------------------------------------------------------------------------------------------
    
    printf("Testing data in virtual memory\n\n");

    // Validate first stop output
    auto exitCtx = vcpu->ExitContext();
    {
        // Get CPU registers
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterCs,
            WHvX64RegisterRip,
            WHvX64RegisterRax,
        };
        WHV_REGISTER_VALUE out[sizeof(regs) / sizeof(regs[0])];
        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), out);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }

        // Validate
        if (out[1].Reg32 == 0xfffc3 && out[0].Segment.Selector == 0x0008) {
            printf("Emulation stopped at the right place!\n");
            if (out[2].Reg32 == 0xdeadbeef) {
                printf("And we got the right result!\n");
            }
        }
    }
    
    printf("\nFirst stop CPU register state:\n");
    printRegs(vcpu);
    printf("\n");

    // ----- Second part ------------------------------------------------------------------------------------------------------

    printf("Testing code in virtual memory\n\n");

    // Run CPU once more
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64Halt:
        printf("Emulation exited due to HLT instruction as expected!\n");
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    // Validate second stop output
    {
        // Get CPU registers
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterRip,
            WHvX64RegisterRax,
            WHvX64RegisterRdx,
        };
        WHV_REGISTER_VALUE out[sizeof(regs) / sizeof(regs[0])];
        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), out);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }
       
        // Validate
        if (out[0].Reg32 == 0x10000013) {
            printf("Emulation stopped at the right place!\n");
            uint32_t memValue = *(uint32_t *)&ram[0x5000];
            if (out[1].Reg32 == 0xcc99e897 && out[2].Reg32 == 0x12345678 && memValue == 0xcc99e897) {
                printf("And we got the right result!\n");
            }
        }
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");
    
    // ----- Stack ------------------------------------------------------------------------------------------------------------

    printf("Testing the stack\n\n");

    // Run CPU once more
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64Halt:
        printf("Emulation exited due to HLT instruction as expected!\n");
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    // Validate stack results
    {
        // Get CPU registers
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterRip,
            WHvX64RegisterRdx,
            WHvX64RegisterRsp,
        };
        WHV_REGISTER_VALUE out[sizeof(regs) / sizeof(regs[0])];
        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), out);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }

        // Validate
        if (out[0].Reg32 == 0x10000021) {
            printf("Emulation stopped at the right place!\n");
            uint32_t memValue = *(uint32_t *)&ram[0xefffc];
            if (out[1].Reg32 == 0xf00dcafe && out[2].Reg32 == 0x000f0000 && memValue == 0xf00dcafe) {
                printf("And we got the right result!\n");
            }
        }
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");

    // ----- Interrupts -------------------------------------------------------------------------------------------------------

    printf("Testing interrupts\n\n");

    // First stop at the HLT inside INT 0x21
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64Halt:
        printf("Emulation exited due to HLT instruction as expected!\n");
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    // Validate registers
    {
        // Get CPU registers
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterRip,
        };
        WHV_REGISTER_VALUE out[sizeof(regs) / sizeof(regs[0])];
        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), out);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }

        // Validate
        if (out[0].Reg32 == 0x10001003) {
            printf("Emulation stopped at the right place!\n");
        }
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");


    // Now we should hit the HLT after INT 0x21
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64Halt:
        printf("Emulation exited due to HLT instruction as expected!\n");
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    // Validate registers
    {
        // Get CPU registers
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterRip,
        };
        WHV_REGISTER_VALUE out[sizeof(regs) / sizeof(regs[0])];
        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), out);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }

        // Validate
        if (out[0].Reg32 == 0x10000026) {
            printf("Emulation stopped at the right place!\n");
        }
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");


    // Enable interrupts
    {
        WHV_REGISTER_NAME regs[] = {
            WHvX64RegisterRflags,
        };
        WHV_REGISTER_VALUE vals[sizeof(regs) / sizeof(regs[0])];

        vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to retrieve VCPU registers\n");
            return -1;
        }

        // Enable interrupts
        vals[0].Reg32 |= 0x200;

        vcpuStatus = vcpu->SetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("Failed to set VCPU registers\n");
            return -1;
        }
    }

    // Do an INT 0x21 from the host
    vcpuStatus = vcpu->Interrupt(0x21);
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("Failed to inject interrupt\n");
        return -1;
    }
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64Halt:
        printf("Emulation exited due to HLT instruction as expected!\n");
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");

    // ----- PMIO -------------------------------------------------------------------------------------------------------------

    printf("Testing PMIO\n\n");

    // Set callbacks to validate inputs and outputs
    vcpu->SetIoPortCallback([](WHV_EMULATOR_IO_ACCESS_INFO *io) -> HRESULT {
        // 8-bit operations
        if (io->Direction == 0 && io->Port == 0x1000 && io->AccessSize == 1) {
            printf("Received I/O port callback for reading 8 bits from the correct address!\n");
            io->Data = 0xac;
            return S_OK;
        }
        if (io->Direction == 1 && io->Port == 0x1001 && io->AccessSize == 1) {
            printf("Received I/O port callback for writing 8 bits to the correct address!\n");
            if (io->Data == 0x53) {
                printf("And the value was correct!\n");
            }
            return S_OK;
        }

        // 16-bit operations
        if (io->Direction == 0 && io->Port == 0x1002 && io->AccessSize == 2) {
            printf("Received I/O port callback for reading 16 bits from the correct address!\n");
            io->Data = 0xfade;
            return S_OK;
        }
        if (io->Direction == 1 && io->Port == 0x1003 && io->AccessSize == 2) {
            printf("Received I/O port callback for writing 16 bits to the correct address!\n");
            if (io->Data == 0x0521) {
                printf("And the value was correct!\n");
            }
            return S_OK;
        }

        // 32-bit operations
        if (io->Direction == 0 && io->Port == 0x1004 && io->AccessSize == 4) {
            printf("Received I/O port callback for reading 32 bits from the correct address!\n");
            io->Data = 0xfeedbabe;
            return S_OK;
        }
        if (io->Direction == 1 && io->Port == 0x1005 && io->AccessSize == 4) {
            printf("Received I/O port callback for writing 32 bits to the correct address!\n");
            if (io->Data == 0x01124541) {
                printf("And the value was correct!\n");
            }
            return S_OK;
        }

        return E_INVALIDARG;
    });


    // Run CPU until 8-bit IN
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64IoPortAccess:
        printf("Emulation exited due to PMIO as expected!\n");
        if (exitCtx->IoPortAccess.AccessInfo.IsWrite == FALSE && exitCtx->IoPortAccess.PortNumber == 0x1000 && exitCtx->IoPortAccess.AccessInfo.AccessSize == 1) {
            printf("And we got the right address and direction!\n");
        }
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");


    // Run CPU until 8-bit OUT
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64IoPortAccess:
        printf("Emulation exited due to PMIO as expected!\n");
        if (exitCtx->IoPortAccess.AccessInfo.IsWrite == TRUE && exitCtx->IoPortAccess.PortNumber == 0x1001 && exitCtx->IoPortAccess.AccessInfo.AccessSize == 1) {
            printf("And we got the right address and direction!\n");
        }
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");


    // Run CPU until 16-bit IN
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64IoPortAccess:
        printf("Emulation exited due to PMIO as expected!\n");
        if (exitCtx->IoPortAccess.AccessInfo.IsWrite == FALSE && exitCtx->IoPortAccess.PortNumber == 0x1002 && exitCtx->IoPortAccess.AccessInfo.AccessSize == 2) {
            printf("And we got the right address and direction!\n");
        }
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");


    // Run CPU until 16-bit OUT
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64IoPortAccess:
        printf("Emulation exited due to PMIO as expected!\n");
        if (exitCtx->IoPortAccess.AccessInfo.IsWrite == TRUE && exitCtx->IoPortAccess.PortNumber == 0x1003 && exitCtx->IoPortAccess.AccessInfo.AccessSize == 2) {
            printf("And we got the right address and direction!\n");
        }
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");


    // Run CPU until 32-bit IN
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64IoPortAccess:
        printf("Emulation exited due to PMIO as expected!\n");
        if (exitCtx->IoPortAccess.AccessInfo.IsWrite == FALSE && exitCtx->IoPortAccess.PortNumber == 0x1004 && exitCtx->IoPortAccess.AccessInfo.AccessSize == 4) {
            printf("And we got the right address and direction!\n");
        }
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");


    // Run CPU until 32-bit OUT
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    switch (exitCtx->ExitReason) {
    case WHvRunVpExitReasonX64IoPortAccess:
        printf("Emulation exited due to PMIO as expected!\n");
        if (exitCtx->IoPortAccess.AccessInfo.IsWrite == TRUE && exitCtx->IoPortAccess.PortNumber == 0x1005 && exitCtx->IoPortAccess.AccessInfo.AccessSize == 4) {
            printf("And we got the right address and direction!\n");
        }
        break;
    default:
        printf("Emulation exited for another reason: %d\n", exitCtx->ExitReason);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(vcpu);
    printf("\n");

    // ----- Cleanup ----------------------------------------------------------------------------------------------------------

    printf("\n");
    
    // Free RAM
    if (!VirtualFree(ram, 0, MEM_RELEASE)) {
        printf("Failed to free RAM memory: error code %d\n", GetLastError());
    }
    else {
        printf("RAM memory freed\n");
    }

    // Free ROM
    if (!VirtualFree(rom, 0, MEM_RELEASE)) {
        printf("Failed to free ROM memory: error code %d\n", GetLastError());
    }
    else {
        printf("ROM memory freed\n");
    }

    return 0;
}
