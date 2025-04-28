#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <string.h>  


DWORD GetProcessIdByName(const char* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &processEntry)) {
            do {
                // Process32First/Process32Next returns names in wide char format
                // Convert process name to match format for comparison
                char currentProcessName[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, processEntry.szExeFile, -1,
                    currentProcessName, MAX_PATH, NULL, NULL);

                if (strcmp(currentProcessName, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    return processId;
}
 boolean FixRelloc(PVOID BaseOfAllocation, IMAGE_NT_HEADERS* ImageNtHeader, IMAGE_BASE_RELOCATION* RellocTable, HANDLE pHandle) {
     DWORD Delta = (DWORD)((BYTE*)BaseOfAllocation - ImageNtHeader->OptionalHeader.ImageBase);
     DWORD* bufferread = malloc(sizeof(DWORD));
     if (!bufferread) return FALSE;

     while (RellocTable->SizeOfBlock) {
         DWORD BlockSize = RellocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
         DWORD AmountOfEntries = BlockSize / sizeof(WORD);
         WORD* relocEntries = (WORD*)((BYTE*)RellocTable + sizeof(IMAGE_BASE_RELOCATION));

         for (DWORD i = 0; i < AmountOfEntries; i++) {
             WORD entry = relocEntries[i];
             int type = entry >> 12;
             int offset = entry & 0xFFF;

             if (type != IMAGE_REL_BASED_HIGHLOW) // Process only type 3 entries
                 continue;

             SIZE_T sizeread = 0;
             DWORD addressToPatch = RellocTable->VirtualAddress + offset;
             if (!ReadProcessMemory(pHandle, (BYTE*)BaseOfAllocation + addressToPatch, bufferread, sizeof(DWORD), &sizeread) || sizeread != sizeof(DWORD)) {
                 free(bufferread);
                 return FALSE;
             }

             *bufferread += Delta;

             if (!WriteProcessMemory(pHandle, (BYTE*)BaseOfAllocation + addressToPatch, bufferread, sizeof(DWORD), &sizeread) || sizeread != sizeof(DWORD)) {
                 free(bufferread);
                 return FALSE;
             }
         }

         RellocTable = (IMAGE_BASE_RELOCATION*)((BYTE*)RellocTable + RellocTable->SizeOfBlock);
     }

     free(bufferread);
     return TRUE;
 }
 DWORD AddressOnDisk(DWORD virtualAddress, BYTE* peFileBase) {
     // Get DOS header
     PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peFileBase;
     if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
         return 0; // Invalid PE file

     // Get NT headers
     PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(peFileBase + dosHeader->e_lfanew);
     if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
         return 0; // Invalid PE file

     // Get first section header
     PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

     // Iterate through sections to find the one containing the virtual address
     for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++) {
         // Check if the virtual address is within this section
         if (virtualAddress >= section->VirtualAddress &&
             virtualAddress < (section->VirtualAddress + section->Misc.VirtualSize)) {

             // Calculate the offset from the start of the section
             DWORD offset = virtualAddress - section->VirtualAddress;

             // If offset is beyond the section's raw data size, it might be in zero-filled area
             if (offset > section->SizeOfRawData)
                 return 0; // Virtual address points to zero-filled area with no file representation

             // Return file offset
             return section->PointerToRawData + offset;
         }
     }

     // Check if address is in headers (before first section)
     if (virtualAddress < ntHeader->OptionalHeader.SizeOfHeaders) {
         return virtualAddress;
     }

     // Virtual address not found in any section
     return 0;
 }
 DWORD GetRemoteModuleBase(HANDLE hProcess, const char* moduleName) {
     HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
     if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

     MODULEENTRY32 me = { .dwSize = sizeof(MODULEENTRY32) };
     if (Module32First(hSnapshot, &me)) {
         do {
             if (_stricmp(me.szModule, moduleName) == 0) {
                 CloseHandle(hSnapshot);
                 return (DWORD)me.modBaseAddr;
             }
         } while (Module32Next(hSnapshot, &me));
     }

     CloseHandle(hSnapshot);
     return 0; // Module not found
 }
 boolean FixIAT(HANDLE pHandle, IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor, BYTE* BaseOfAllocation, BYTE* PeBase) {
     while (ImportDescriptor->Name) {
         char* moduleName = (char*)(PeBase + AddressOnDisk(ImportDescriptor->Name, PeBase));
         DWORD remoteModuleBase = GetRemoteModuleBase(pHandle, moduleName);
         if (!remoteModuleBase) {
             // Handle module not loaded (e.g., load it via LoadLibrary)
             // This requires injecting LoadLibrary call which is more complex
             printf("Module %s not loaded in target process!\n", moduleName);
             return FALSE;
         }

         IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(PeBase + AddressOnDisk(ImportDescriptor->OriginalFirstThunk, PeBase));
         IMAGE_THUNK_DATA* iatThunk = (IMAGE_THUNK_DATA*)(BaseOfAllocation + ImportDescriptor->FirstThunk);

         while (thunk->u1.AddressOfData) {
             if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                 // Handle ordinal import
                 DWORD ordinal = IMAGE_ORDINAL(thunk->u1.Ordinal);
                 // Manually resolve ordinal from remote module's export table (complex)
                 // For simplicity, assume function address is same as local (not reliable)
                 iatThunk->u1.Function = GetProcAddress(GetModuleHandleA(moduleName), (LPCSTR)ordinal);
             }
             else {
                 IMAGE_IMPORT_BY_NAME* import = (IMAGE_IMPORT_BY_NAME*)(PeBase + AddressOnDisk(thunk->u1.AddressOfData, PeBase));
                 // Resolve function from remote module
                 iatThunk->u1.Function = GetProcAddress((HMODULE)remoteModuleBase, import->Name);
             }

             // Write resolved address to target process
             WriteProcessMemory(pHandle, &iatThunk->u1.Function, &iatThunk->u1.Function, sizeof(DWORD), NULL);
             thunk++;
             iatThunk++;
         }

         ImportDescriptor++;
     }
     return TRUE;
 }

















int main(int argc, char* argv[]) {
    HANDLE pHandle = NULL;
    FILE* OpenStream = NULL;
    BYTE* buffer = NULL;
    PVOID BaseOfAllocation = NULL;
    int result = 1; // Default to error
    // Load needed DLLs in your injector process
    LoadLibraryA("USER32.dll");
    LoadLibraryA("msvcrt.dll");
    LoadLibraryA("libgcc_s_dw2-1.dll");
    if (argc != 3) {
        printf("You haven't provided a DLL name or a process name\nargs: name of DLL\nexiting...\n");
        return 1;  // Exit with error code
    }
    char* ProcessName = argv[1];
    char* DllName = argv[2];

    printf("injecting %s in process %s....\n", DllName, ProcessName);


    //open handle to target process
    DWORD ProcessID = GetProcessIdByName(argv[1]);
    pHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ| PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, 0, ProcessID);
    if (!pHandle) {
        printf("Failed to open a Handle to the process with ID: %d", ProcessID);
        goto cleanup;
    }

    //Allocate mem to the targer process
    BaseOfAllocation = NULL;

    //open DLL to read 
    char FullPathExe[] = "C:\\WINDOWS\\system32\\";

    strcat(FullPathExe, ProcessName);
    OpenStream = fopen(DllName, "rb");
    if (!OpenStream) {
        printf("Failed to fopen the file\nexiting....\n");
        goto cleanup;
    }

    //get size of DLL
    fseek(OpenStream, 0, SEEK_END);
    long file_size = ftell(OpenStream);

    fseek(OpenStream, 0, SEEK_SET); // Rewind to start
    if (file_size <= 0) {
        printf("Reading the bytes of DLL from disk went wrong\nexiting....\n");
        goto cleanup;
    }

    buffer = malloc(file_size);
    if (buffer == NULL)
    {
        printf("buffer malloc returned null\nExiting....");
        goto cleanup;
    }

    if (fread(buffer, 1, file_size, OpenStream) != file_size) {
        printf("Some error happened durning read DLL from disk\nexiting....\n");
        goto cleanup;
    }
    fclose(OpenStream);
    OpenStream = NULL;


    // Buffer contains the raw disk and mem is allocted, time to walk 

    //get size of image to allocate 
    IMAGE_DOS_HEADER* ImageDosHeader = (IMAGE_DOS_HEADER*)buffer;
    IMAGE_NT_HEADERS* ImageNtHeader = (IMAGE_NT_HEADERS*)(buffer + ImageDosHeader->e_lfanew);
    DWORD SizOfImage = ImageNtHeader->OptionalHeader.SizeOfImage;


    BaseOfAllocation = VirtualAllocEx(pHandle,NULL, SizOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (BaseOfAllocation == NULL) {
        printf("Failed to allocate memory in the target process\n");
        goto cleanup;
    }
    //Copy sections

    SIZE_T readsize = 0;
    BYTE* RellocTable = NULL;
    IMAGE_SECTION_HEADER* ImageSectionHeaderArray = (IMAGE_SECTION_HEADER*)((BYTE*)ImageNtHeader + sizeof(IMAGE_NT_HEADERS));
    WORD NumberOfSections = ImageNtHeader->FileHeader.NumberOfSections;
    for (int i = 0;i < NumberOfSections;i++) {
        if (ImageSectionHeaderArray[i].SizeOfRawData == 0) continue;
        //read into a buffer the section, write it in target process memory at location base+VirtualAddress
        BYTE* Section = (BYTE*)(buffer + ImageSectionHeaderArray[i].PointerToRawData);
        if (!WriteProcessMemory(pHandle, (LPVOID)((BYTE*)BaseOfAllocation + ImageSectionHeaderArray[i].VirtualAddress), (LPCVOID)(Section), ImageSectionHeaderArray[i].SizeOfRawData, &readsize) || readsize == 0) {
            printf("WriteProcessMemoryfail\nexiting....\n");
            goto cleanup;
        }
        if (!strcmp(ImageSectionHeaderArray[i].Name, ".reloc"))
             RellocTable = buffer + ImageSectionHeaderArray[i].PointerToRawData;
    }
    if (RellocTable == NULL)
        goto cleanup;



    if (FixRelloc(BaseOfAllocation, ImageNtHeader, (IMAGE_BASE_RELOCATION*)RellocTable, pHandle) == FALSE) {
        printf("FixRelloc retuned False\nexiting.....\n");
        goto cleanup;
    }

    if (FixIAT(
        pHandle,
        (IMAGE_IMPORT_DESCRIPTOR*)(buffer + AddressOnDisk(ImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,buffer)),
         (BYTE*)BaseOfAllocation
    ,buffer) == FALSE) {
        printf("Failed to fix IAT\nexiting.....");
        goto cleanup;
    }


    // After your FixIAT function succeeds

    // Get the entry point address
    DWORD entryPoint = ImageNtHeader->OptionalHeader.AddressOfEntryPoint;
    LPVOID dllMain = (LPVOID)((BYTE*)BaseOfAllocation + entryPoint);

    // Create shellcode to call DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
    BYTE shellcode[] = {
        0x68, 0x00, 0x00, 0x00, 0x00,       // push 0 (NULL)
        0x68, 0x01, 0x00, 0x00, 0x00,       // push 1 (DLL_PROCESS_ATTACH)
        0x68, 0x00, 0x00, 0x00, 0x00,       // push BaseOfAllocation
        0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, DllMain
        0xFF, 0xD0,                         // call eax
        0xC3                                // ret
    };

    // Fill in the address values
    *(DWORD*)&shellcode[5] = 1;  // DLL_PROCESS_ATTACH
    *(DWORD*)&shellcode[10] = (DWORD)BaseOfAllocation;
    *(DWORD*)&shellcode[16] = (DWORD)dllMain;

    // Allocate memory for shellcode
    LPVOID shellcodeAddr = VirtualAllocEx(pHandle, NULL, sizeof(shellcode),
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!shellcodeAddr) {
        printf("Failed to allocate memory for shellcode\n");
        goto cleanup;
    }

    // Write shellcode to target process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pHandle, shellcodeAddr, shellcode, sizeof(shellcode), &bytesWritten)) {
        printf("Failed to write shellcode\n");
        VirtualFreeEx(pHandle, shellcodeAddr, 0, MEM_RELEASE);
        goto cleanup;
    }

    // Execute shellcode
    HANDLE hThread = CreateRemoteThread(pHandle, NULL, 0,
        (LPTHREAD_START_ROUTINE)shellcodeAddr,
        NULL, 0, NULL);
    if (!hThread) {
        DWORD err = GetLastError();
        printf("Failed to create remote thread. Error code: %d\n", err);
        VirtualFreeEx(pHandle, shellcodeAddr, 0, MEM_RELEASE);
        goto cleanup;
    }

    // Wait for shellcode to complete
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(pHandle, shellcodeAddr, 0, MEM_RELEASE);

    printf("DLL successfully manually mapped and initialized\n");

cleanup:
    // Clean up resources
    if (buffer != NULL) {
        free(buffer);
    }
    if (OpenStream != NULL) {
        fclose(OpenStream);
    }
    if (pHandle != NULL) {
        CloseHandle(pHandle);
    }
    if (BaseOfAllocation != NULL && result != 0) {
        VirtualFree(BaseOfAllocation, 0, MEM_RELEASE);
    }

    return result;
}