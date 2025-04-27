// Dll2.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"

#include "Dll2.h"



// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        // Code to run when DLL is loaded
        break;
    case DLL_PROCESS_DETACH:
        // Code to run when DLL is unloaded
        break;
    case DLL_THREAD_ATTACH:
        // Code to run when a thread starts
        break;
    case DLL_THREAD_DETACH:
        // Code to run when a thread ends
        break;
    }
    return TRUE;
}