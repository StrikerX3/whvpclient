#pragma once

#include <Windows.h>
#include <WinHvPlatform.h>

#include <vector>

enum WHvStatus {
    WHVS_SUCCESS = 0,                    // The operation completed successfully

    WHVS_FAILED = 0x80000000,            // The operation failed
    WHVS_INVALID_CAPABILITY,             // An invalid capability code was passed
};

enum WHvPartitionStatus {
    WHVPS_SUCCESS = 0,                   // Partition created successfully

    WHVPS_FAILED = 0x80000000,           // The operation failed
    WHVPS_CREATE_FAILED,                 // Failed to create partition
    WHVPS_DELETE_FAILED,                 // Failed to delete a partition
    WHVPS_SETUP_FAILED,                  // Failed to setup a partition
    WHVPS_ALREADY_CREATED,               // Attempted to create a partition that was already created
    WHVPS_ALREADY_DELETED,               // Attempted to delete a partition that was already deleted
    WHVPS_INVALID_OWNER,                 // Attempted to delete a partition that does not belong to the platform object
    WHVPS_INVALID_POINTER,               // An invalid pointer to a partition was passed to a function
    WHVPS_UNINITIALIZED,                 // The partition is not initialized
};

enum WHvVCPUStatus {
    WHVVCPUS_SUCCESS = 0,                // VCPU created successfully

    WHVVCPUS_FAILED = 0x80000000,        // The operation failed
    WHVVCPUS_CREATE_FAILED,              // Failed to create VCPU
    WHVVCPUS_NOT_INITIALIZED,            // Attempted to delete an uninitialized VCPU
    WHVVCPUS_ALREADY_INITIALIZED,        // Attempted to create an initialized VCPU
    WHVVCPUS_INVALID_POINTER,            // An invalid pointer to a VCPU was passed to a function
    WHVVCPUS_INVALID_OWNER,              // Attempted to delete a VCPU that does not belong to the partition
};


class WHvPartition;
class WHvVCPU;

class WinHvPlatform {
public:
    WinHvPlatform();
    ~WinHvPlatform();

    const bool IsPresent() const { return m_present; }

    WHvStatus GetCapability(WHV_CAPABILITY_CODE code, WHV_CAPABILITY *pCap);

    WHvPartitionStatus CreatePartition(WHvPartition **ppPartition);
    WHvPartitionStatus DeletePartition(WHvPartition **ppPartition);

private:
    bool m_present;

    std::vector<WHvPartition *> m_partitions;
};


class WHvPartition {
public:
    WHvPartitionStatus GetProperty(WHV_PARTITION_PROPERTY_CODE code, WHV_PARTITION_PROPERTY *ppProperty);
    WHvPartitionStatus SetProperty(WHV_PARTITION_PROPERTY_CODE code, WHV_PARTITION_PROPERTY *ppProperty);
    
    WHvPartitionStatus Setup();

    WHvPartitionStatus MapGpaRange(void *memory, WHV_GUEST_PHYSICAL_ADDRESS address, UINT64 size, WHV_MAP_GPA_RANGE_FLAGS flags);
    WHvPartitionStatus UnmapGpaRange(WHV_GUEST_PHYSICAL_ADDRESS address, UINT64 size);

    WHvVCPUStatus CreateVCPU(WHvVCPU **ppVcpu, UINT32 vpIndex);
    WHvVCPUStatus DeleteVCPU(WHvVCPU **ppVcpu);

    WHvPartitionStatus Close();

private:
    WHvPartition(WinHvPlatform *platform);
    ~WHvPartition();

    WHvPartitionStatus Initialize();

    WinHvPlatform *m_platform;
    WHV_PARTITION_HANDLE m_handle;

    std::vector<WHvVCPU *> m_vcpus;

    friend class WinHvPlatform;
};


class WHvVCPU {
public:
    WHvVCPUStatus Run();

    WHvVCPUStatus Close();

    const WHV_RUN_VP_EXIT_CONTEXT * ExitContext() const { return &m_exitContext; }

private:
    WHvVCPU(WHV_PARTITION_HANDLE hPartition, UINT32 vpIndex);
    ~WHvVCPU();

    WHvVCPUStatus Initialize();

    WHV_PARTITION_HANDLE m_partitionHandle;
    UINT32 m_vpIndex;
    WHV_RUN_VP_EXIT_CONTEXT m_exitContext;

    bool m_initialized;

    friend class WHvPartition;
};
