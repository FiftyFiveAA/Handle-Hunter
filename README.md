# Handle-Hunter

Handle-Hunter is a python script for Windows which extract all handles for the target process and all handle types on the system.

### Usage

* Run the python script and enter the Process ID for the target process whose handles we'll extract
* The script usually takes a couple minutes
  
```
python3 Handle-Hunter.py
```

### Compatibility

This was only tested on Windows 11 x64. Changes to the structs will probably be required on other OS versions.

### Windows Functions Used

* ntdll.NtQuerySystemInformation  // Gets all handles on the system
* ntdll.NtDuplicateObject  // Duplicate the handles from other processes so we can get their info
* ntdll.NtQueryObject  // Get the OBJECT_TYPE_INFORMATION for the handle (this includes the handle type name)
* kernel32.OpenProcess  // NtDuplicateObject requires a handle to the target process

### Windows 11 x64 Handle Types (August 2023)

Event 0x130000
IRTimer 0x180000
Semaphore 0x160000
IoCompletion 0x260000
Key 0x300000
File 0x280000
WindowStation 0x1b0000
Section 0x2e0000
Thread 0x80000
ALPC Port 0x330000
WaitCompletionPacket 0x270000
Timer 0x170000
TpWorkerFactory 0x210000
Mutant 0x140000
Token 0x50000
Desktop 0x1c0000
Process 0x70000
IoCompletionReserve 0xb0000
DxgkCompositionObject 0x460000
Directory 0x30000
UserApcReserve 0xa0000
Composition 0x1d0000
Job 0x60000
DxgkSharedSyncObject 0x410000
DxgkSharedResource 0x3f0000
WmiGuid 0x360000
Unknown 0x370000
