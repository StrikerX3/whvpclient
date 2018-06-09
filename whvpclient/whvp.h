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

    WHVPS_CREATE_FAILED = 0x80000000,    // Failed to create partition
    WHVPS_DELETE_FAILED,                 // Failed to delete a partition
    WHVPS_SETUP_FAILED,                  // Failed to setup a partition
    WHVPS_ALREADY_CREATED,               // Attempted to create a partition that was already created
    WHVPS_ALREADY_DELETED,               // Attempted to delete a partition that was already deleted
    WHVPS_INVALID_OWNER,                 // Attempted to delete a partition that does not belong to the platform object
    WHVPS_INVALID_PARTITION,             // An invalid pointer to a partition was passed
    WHVPS_UNINITIALIZED,                 // The partition is not initialized
};


class WHvPartition;


class WinHvPlatform {
public:
    WinHvPlatform();
    ~WinHvPlatform();

    const bool IsPresent() const { return m_present; }

    WHvStatus GetCapability(WHV_CAPABILITY_CODE code, WHV_CAPABILITY *pCap);

    WHvPartitionStatus CreatePartition(WHvPartition **partition);
    WHvPartitionStatus DeletePartition(WHvPartition **partition);

private:
    bool m_present;

    std::vector<WHvPartition *> m_partitions;
};


class WHvPartition {
public:
    WHvPartitionStatus Setup();

    WHvPartitionStatus Close();

private:
    WHvPartition(WinHvPlatform *platform);
    ~WHvPartition();

    WHvPartitionStatus Initialize();

    WinHvPlatform *m_platform;
    WHV_PARTITION_HANDLE m_handle;

    friend class WinHvPlatform;
};
