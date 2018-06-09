#include "whvp.h"

WinHvPlatform::WinHvPlatform() {
    WHV_CAPABILITY cap;
    UINT32 size;
    HRESULT hr;
    int result = 0;

    // Check for Hyper-V presence
    hr = WHvGetCapability(WHvCapabilityCodeHypervisorPresent, &cap, sizeof(WHV_CAPABILITY), &size);
    if (S_OK != hr) {
        m_present = false;
        return;
    }

    m_present = cap.HypervisorPresent;
}

WinHvPlatform::~WinHvPlatform() {
    // Delete all partitions created with this object
    for (auto it = m_partitions.begin(); it != m_partitions.end(); it++) {
        delete (*it);
    }
    m_partitions.clear();
}

WHvPartitionStatus WinHvPlatform::CreatePartition(WHvPartition **pPartition) {
    // Create and initialize the partition
    WHvPartition *partition = new WHvPartition(this);
    WHvPartitionStatus status = partition->Initialize();
    if (status != WHVPS_SUCCESS) {
        delete partition;
        return status;
    }

    // Add it to the vector so that we can clean up later
    m_partitions.push_back(partition);
    *pPartition = partition;

    return WHVPS_SUCCESS;
}

WHvPartitionStatus WinHvPlatform::DeletePartition(WHvPartition **pPartition) {
    // Null check the pointers
    if (pPartition == nullptr) {
        return WHVPS_INVALID_PARTITION;
    }
    if (*pPartition == nullptr) {
        return WHVPS_INVALID_PARTITION;
    }

    // Make sure the partition was created by this platform object
    if ((*pPartition)->m_platform != this) {
        return WHVPS_INVALID_OWNER;
    }

    // Try to close the partition
    WHvPartitionStatus closeStatus = (*pPartition)->Close();
    if (closeStatus != WHVPS_SUCCESS) {
        return closeStatus;
    }

    // Remove it from the clean up vector
    for (auto it = m_partitions.begin(); it != m_partitions.end(); it++) {
        if (*it == *pPartition) {
            m_partitions.erase(it);
            break;
        }
    }
    
    // Delete and clear the pointer
    delete *pPartition;
    *pPartition = nullptr;
    
    return WHVPS_SUCCESS;
}


WHvPartition::WHvPartition(WinHvPlatform *platform)
    : m_platform(platform)
    , m_handle(INVALID_HANDLE_VALUE)
{
}

WHvPartition::~WHvPartition() {
    Close();
}

WHvPartitionStatus WHvPartition::Close() {
    // Check if the handle is valid
    if (m_handle == INVALID_HANDLE_VALUE) {
        return WHVPS_ALREADY_DELETED;
    }

    // Delete the partition
    HRESULT hr = WHvDeletePartition(m_handle);
    if (S_OK != hr) {
        return WHVPS_DELETE_FAILED;
    }
    
    // Clear the handle
    m_handle = INVALID_HANDLE_VALUE;

    return WHVPS_SUCCESS;
}

WHvPartitionStatus WHvPartition::Initialize() {
    // Check if the handle is valid
    if (m_handle != INVALID_HANDLE_VALUE) {
        return WHVPS_ALREADY_CREATED;
    }

    // Create the partition
    HRESULT hr = WHvCreatePartition(&m_handle);
    if (S_OK != hr) {
        m_handle = INVALID_HANDLE_VALUE;
        return WHVPS_CREATE_FAILED;
    }

    return WHVPS_SUCCESS;
}

WHvPartitionStatus WHvPartition::Setup() {
    // Check if the handle is valid
    if (m_handle == INVALID_HANDLE_VALUE) {
        return WHVPS_UNINITIALIZED;
    }

    // Setup the partition
    HRESULT hr = WHvSetupPartition(m_handle);
    if (S_OK != hr) {
        return WHVPS_SETUP_FAILED;
    }

    return WHVPS_SUCCESS;
}
