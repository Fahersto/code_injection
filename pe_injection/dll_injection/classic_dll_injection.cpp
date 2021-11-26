/**
* Injects a .dll file into a running process
* Supports 32- and 64 Bit applications.
*/

#include <Windows.h>
#include <string>
#include <cstdio>
#include <tlhelp32.h>


int main(int argc, char* argv[])
{
	char* processName;
	char* dllPath;

	if (argc != 3)
	{
		printf("Usage: *.exe processName absolutePath\n");
		return 1;
	}

	processName = argv[1];
	dllPath = argv[2];
	
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

	printf("[Info] - Found Process %s with id %d\n", processName, processEntry.th32ProcessID);

	// acquire a handle to the target process
	HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (!targetProcessHandle)
	{
		printf("Error %d - Failed to acquire process handle\n", GetLastError());
		return 1;
	}

	// allocate memory in target process
	LPVOID remoteMemory = VirtualAllocEx(targetProcessHandle, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!remoteMemory)
	{
		printf("Error %d - Failed to allocate memory in target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Allocated remote memory at %p\n", remoteMemory);

	// write path of .dll to target process
	if (!WriteProcessMemory(targetProcessHandle, remoteMemory, dllPath, strlen(dllPath), nullptr))
	{
		printf("Error %d - Failed to write .dll path to target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Wrote dll path %s to target process %s \n", dllPath, processName);

	// get handle to kernel32.dll (which is loaded by default)
	HMODULE kernel32ModuleHandle = GetModuleHandle("kernel32.dll");
	if (!kernel32ModuleHandle)
	{
		printf("Error %d - Failed to get kernel32 module handle\n", GetLastError());
		return 1;
	}

	// resolve address of LoadLibraryA
	FARPROC kernel32LoadLibrary = GetProcAddress(kernel32ModuleHandle, "LoadLibraryA");
	if (!kernel32LoadLibrary)
	{
		printf("Error %d - Failed to resolve LoadLibraryA\n", GetLastError());
		return 1;
	}

	printf("[Info] - Found LoadLibraryA at %p\n", kernel32LoadLibrary);

	// create a thread in the target process which loads the .dll
	HANDLE remoteThreadHandle = CreateRemoteThread(
		targetProcessHandle,
		nullptr,
		NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(kernel32LoadLibrary),
		remoteMemory,
		NULL,
		nullptr
	);

	if (!remoteThreadHandle)
	{
		printf("Error %d - Failed to CreateRemoteThread\n", GetLastError());
		return 1;
	}

	printf("[Info] - Created remote thread at %p\n", kernel32LoadLibrary);

	CloseHandle(remoteThreadHandle);
	CloseHandle(targetProcessHandle);
}