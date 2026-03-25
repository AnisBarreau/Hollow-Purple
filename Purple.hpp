#pragma once

#include <Windows.h>
#include <cstdint>

#define IOCTL_CORMEM_MAP_POOL                   0x222000
#define IOCTL_CORMEM_MAP_BUFFER                 0x22200C
#define IOCTL_CORMEM_UNMAP_BUFFER               0x222010
#define IOCTL_CORMEM_GET_POOL_BLOCK_COUNT       0x22205C 


#define CORMEM_DEVICE_NAME "\\\\.\\CORMEM"
#define CORMEM_MAX_POOL_BLOCKS 0x101

#define PSB_SIGNATURE_OFFSET    0x000
#define PSB_KERNEL_ENTRY_OFFSET 0x070
#define PSB_PML4_OFFSET         0x0A0
#define PSB_SIGNATURE_MASK      0xffffffffffff00ffULL
#define PSB_SIGNATURE_VALUE     0x00000001000600E9ULL
#define KERNEL_VA_MASK          0xfffff80000000003ULL
#define KERNEL_VA_EXPECTED      0xfffff80000000000ULL
#define PML4_INVALID_BITS_MASK  0xffffff0000000fffULL

#define PAGE_PRESENT    0x1
#define PAGE_LARGE      0x80
#define PAGE_4KB        0x1000ULL
#define PAGE_2MB        0x200000ULL
#define PAGE_1GB        0x40000000ULL


#pragma pack(push, 1)
struct CORMEM_MAP_BUFFER_IN { uint64_t Address; uint64_t Size; uint64_t Param2; };
struct CORMEM_MAP_POOL_OUT { uint64_t UserAddress; uint64_t KernelAddress; uint64_t PhysicalAddress; uint32_t Size; };
#pragma pack(pop)

struct PoolBlock {
    uint64_t UserAddress;
    uint64_t KernelAddress;
    uint64_t PhysicalAddress;
    uint64_t Size;
};

class Purple {
public:
    Purple() = default;
    ~Purple();

    Purple(const Purple&) = delete;
    Purple& operator=(const Purple&) = delete;
    Purple(Purple&&) noexcept;
    Purple& operator=(Purple&&) noexcept;

    bool Initialize();
    void Close();
    bool IsValid() const { return m_Device != INVALID_HANDLE_VALUE; }

    uint64_t MapBuffer(uint64_t Address, uint64_t Size, uint64_t Param);
    bool UnmapBuffer(uint64_t MappedAddress);
    bool GetPoolBlockCount(uint32_t* Count);


    bool ReadPhysicalMemory(uint64_t PhysicalAddress, void* Buffer, size_t Size);
    bool WritePhysicalMemory(uint64_t PhysicalAddress, const void* Buffer, size_t Size);

    uint64_t FindSystemDTB();
    uint64_t FindProcessDTB(DWORD Pid, uint64_t& OutBaseAddress);
    uint64_t TranslateVirtualAddress(uint64_t DTB, uint64_t VirtualAddress);



    bool ReadProcessMemory(uint64_t DTB, uint64_t VirtualAddress, void* Buffer, size_t Size);
    bool WriteProcessMemory(uint64_t DTB, uint64_t VirtualAddress, const void* Buffer, size_t Size);

    uint64_t GetSystemDTB() const { return m_SystemDTB; }

private:
    bool SendIoctl(DWORD IoControlCode, void* InBuffer, DWORD InSize, void* OutBuffer, DWORD OutSize, DWORD* BytesReturned = nullptr);
    bool MapPoolBlock(uint32_t Index);
    static bool TryFindDTBFromLowStub(uint8_t* LowStub1M, uint64_t& OutDTB, uint64_t& OutKernelEntry);
    bool ValidatePML4Page(uint64_t DTB, uint64_t MaxPhysAddr);

    HANDLE m_Device = INVALID_HANDLE_VALUE;
    uint32_t m_PoolBlockCount = 0;
    PoolBlock m_PoolBlocks[CORMEM_MAX_POOL_BLOCKS] = {};
    uint64_t m_SystemDTB = 0;
};