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



 boolean FixRelloc(PVOID BaseOfAllocation, PVOID buffer, IMAGE_NT_HEADERS* ImageNtHeader,IMAGE_BASE_RELOCATION* RellocTable,HANDLE pHandle) {

    WORD currblock;
    WORD offset;
    SIZE_T sizeread = 0;

    DWORD Delta = (DWORD)((BYTE*)BaseOfAllocation - ImageNtHeader->OptionalHeader.ImageBase);

    DWORD* bufferread = malloc(sizeof(DWORD));
    if (bufferread == NULL)
        return 1;
    WORD* relocEntries = (WORD*)((BYTE*)RellocTable + sizeof(IMAGE_BASE_RELOCATION));
    while (RellocTable->SizeOfBlock) {

        DWORD BlockSize = RellocTable->SizeOfBlock - sizeof(RellocTable->SizeOfBlock) - sizeof(RellocTable->VirtualAddress); //by subtracting the size of these 2 fields from the SizeOfblock we can know the size of blocks 
        DWORD AmountOfBlocks = BlockSize / sizeof(WORD);
            for (WORD i = 0;i < AmountOfBlocks;i++) {
                currblock = relocEntries + i;
                offset = currblock & 0xFFF;

                   if (!ReadProcessMemory(pHandle, (LPCVOID)((BYTE*)BaseOfAllocation + RellocTable->VirtualAddress + offset), bufferread, sizeof(DWORD), &sizeread) || sizeread == 0 ) {
                       printf("ReadProcessMemory failed in function FixRelloc\nexiting.....\n");
                       free(bufferread);
                       return FALSE;

                   }
                   sizeread = 0;
                   *bufferread = *bufferread + Delta;
                   if (!WriteProcessMemory(pHandle, (LPCVOID)((BYTE*)BaseOfAllocation + RellocTable->VirtualAddress + offset), bufferread, sizeof(DWORD), &sizeread) || sizeread == 0) {
                       printf("WriteProcessMemory failed in function FixRelloc\nexiting.....\n");
                       free(bufferread);
                       return FALSE;
                   }
                   sizeread = 0;
              }
            RellocTable++;



        }
    free(bufferread);
    return TRUE;
}















int main(int argc, char* argv[]) {
    HANDLE pHandle = NULL;
    FILE* OpenStream = NULL;
    BYTE* buffer = NULL;
    PVOID BaseOfAllocation = NULL;
    int result = 1; // Default to error

    if (argc != 3) {
        printf("You haven't provided a DLL name or a process name\nargs: name of DLL\nexiting...\n");
        return 1;  // Exit with error code
    }
    char* ProcessName = argv[1];
    char* DllName = argv[2];

    printf("injecting %s in process %s....\n", DllName, ProcessName);


    //open handle to target process
    DWORD ProcessID = GetProcessIdByName(argv[1]);
    pHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ| PROCESS_VM_OPERATION, 0, ProcessID);
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



    if (FixRelloc(BaseOfAllocation, buffer, ImageNtHeader, (IMAGE_BASE_RELOCATION*)RellocTable, pHandle) == FALSE) {
        printf("FixRelloc retuned False\nexiting.....\n");
        goto cleanup;
    }






    result = 0; // Success

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