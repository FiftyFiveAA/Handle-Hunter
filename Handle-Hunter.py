import ctypes
from ctypes import wintypes

# Here are all the handle types on win 11, x64
##Event 0x130000
##IRTimer 0x180000
##Semaphore 0x160000
##IoCompletion 0x260000
##Key 0x300000
##File 0x280000
##WindowStation 0x1b0000
##Section 0x2e0000
##Thread 0x80000
##ALPC Port 0x330000
##WaitCompletionPacket 0x270000
##Timer 0x170000
##TpWorkerFactory 0x210000
##Mutant 0x140000
##Token 0x50000
##Desktop 0x1c0000
##Process 0x70000
##IoCompletionReserve 0xb0000
##DxgkCompositionObject 0x460000
##Directory 0x30000
##UserApcReserve 0xa0000
##Composition 0x1d0000
##Job 0x60000
##DxgkSharedSyncObject 0x410000
##DxgkSharedResource 0x3f0000
##WmiGuid 0x360000
##Unknown 0x370000

# We'll be utilizing these DLLs
ntdll = ctypes.WinDLL("ntdll.dll")
kernel32 = ctypes.WinDLL("kernel32.dll")

# Define the necessary data types
PVOID = ctypes.c_void_p
HANDLE = wintypes.HANDLE

# Open Process Access options
PROCESS_ALL_ACCESS = 0xffff
PROCESS_CREATE_THREAD = 0x0002
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_INFORMATIO = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", PVOID),
        ("UniqueProcessId", HANDLE),
        ("HandleValue", HANDLE),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.ULONG),
        ("ObjectTypeIndex", wintypes.ULONG),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", ctypes.c_ulonglong),
    ]

class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
        # Assume the system won't have more than 10,000,000 handles
        # my win 11 machine had ~200,000
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 10000000),
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort),
                ("MaximumLength", ctypes.c_ushort),
                ("Buffer", ctypes.c_wchar_p)]

class OBJECT_TYPE_INFORMATION(ctypes.Structure):
    _fields_ = [("Name", UNICODE_STRING),
                ("TotalNumberOfObjects", ctypes.c_ulong),
                ("TotalNumberOfHandles", ctypes.c_ulong),
                ("TotalPagedPoolUsage", ctypes.c_ulong),
                ("TotalNonPagedPoolUsage", ctypes.c_ulong),
                ("TotalNamePoolUsage", ctypes.c_ulong),
                ("TotalHandleTableUsage", ctypes.c_ulong),
                ("HighWaterNumberOfObjects", ctypes.c_ulong),
                ("HighWaterNumberOfHandles", ctypes.c_ulong),
                ("HighWaterPagedPoolUsage", ctypes.c_ulong),
                ("HighWaterNonPagedPoolUsage", ctypes.c_ulong),
                ("HighWaterNamePoolUsage", ctypes.c_ulong),
                ("HighWaterHandleTableUsage", ctypes.c_ulong),
                ("InvalidAttributes", ctypes.c_ulong),
                ("GenericMapping", ctypes.c_ulong * 4),
                ("ValidAccessMask", ctypes.c_ulong),
                ("SecurityRequired", ctypes.c_ulong),
                ("MaintainHandleCount", ctypes.c_ulong),
                ("MaintainTypeList", ctypes.c_ulong),
                ("ObjectTypeFlags", ctypes.c_ulong),
                ("ObjectTypeCode", ctypes.c_ulong),
                ("InvalidAttributes", ctypes.c_ulong),
                ("GenericMapping", ctypes.c_ulong * 4),
                ("ValidAccessMask", ctypes.c_ulong),
                ("SecurityRequired", ctypes.c_ulong),
                ("MaintainHandleCount", ctypes.c_ulong),
                ("MaintainTypeList", ctypes.c_ulong),
                ("ObjectTypeFlags", ctypes.c_ulong)]

def handleHunter(pid):
    handles = {}
    handle_types = {}
    # For some reason calling NtQuerySystemInformation once
    # doesn't get all the handles for the process?
    # So call it 100 times to increase probablility you get
    # all the handles
    for i in range(1,100):
        # Go through all handles on the system
        # create a buffer to store all the handles, just guessing it's less
        #    than 20,000,000 bytes
        # On win 11 it was returning about 8,073,856 bytes
        buffer_size = 20000000
        buffer = ctypes.create_string_buffer(buffer_size)
        bytes_returned = ctypes.c_ulong()
        # Call NtQuerySystemInformation
        # NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, Return Length)
        SystemExtendedHandleInformation = 64
        status = ntdll.NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, buffer_size, ctypes.byref(bytes_returned))

        if(status != 0):
            print("NtQuerySystemInformation Failed: ", status)
            return
        
        handle_info = ctypes.cast(buffer, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION_EX)).contents

        # Iterate through the handle information list
        for i in range(handle_info.NumberOfHandles):
            handle_entry = handle_info.Handles[i]
            process_id = handle_entry.UniqueProcessId
            handle_value = handle_entry.HandleValue
            granted_access = handle_entry.GrantedAccess
            creator_back_trace_index = handle_entry.CreatorBackTraceIndex
            object_type_index = handle_entry.ObjectTypeIndex
            handle_attributes = handle_entry.HandleAttributes

            # save the handle if it's in our target process
            if(process_id == pid):
                handles[handle_value] = [granted_access, creator_back_trace_index]

            try:
                # for every handle type on the system get more info about it
                if(creator_back_trace_index not in handle_types):
                    # duplicate handle
                    dupHandle = HANDLE()
                    target_process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
                    status = ntdll.NtDuplicateObject(target_process_handle, handle_value, HANDLE(-1), ctypes.byref(dupHandle), 0, 0, 0)
                    if(status == 0):                  
                        # call NtQueryObject
                        # Define a buffer to receive the information
                        buffer_size = ctypes.sizeof(OBJECT_TYPE_INFORMATION)
                        # allocate extra space just in case
                        buffer = ctypes.create_string_buffer(buffer_size*100)
                        # 2 = OBJECT_TYPE_INFORMATION
                        status = ntdll.NtQueryObject(dupHandle, 2, ctypes.byref(buffer), buffer_size, None)
                        if(status == 0):
                            obj_type_info = ctypes.cast(buffer, ctypes.POINTER(OBJECT_TYPE_INFORMATION)).contents
                            print(obj_type_info.Name.Buffer, hex(creator_back_trace_index))
                        # Save the handle type info
                        handle_types[creator_back_trace_index] = obj_type_info.Name.Buffer
                    # close process handle
                    kernel32.CloseHandle(target_process_handle)
                    kernel32.CloseHandle(dupHandle)
            except Exception as e:
                pass          
    return handles, handle_types

pid = input("Get handles for Process ID: ")
handles, handle_types = handleHunter(int(pid))
for i in handles:
    try:
        print("Handle Value: ", hex(i), "\tHandle Type: ", handle_types[handles[i][1]])
    except:
        print("Handle Value: ", hex(i), "\tHandle Type: ", "unknown (" + hex(handles[i][1]) + ")")
