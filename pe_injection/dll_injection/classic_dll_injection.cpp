#include <Windows.h>
#include <string>
#include <cstdio>


/**
* Injects a .dll file into a running process
*
*/
int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("Usage: *.exe processId dllPath\n");
		return 1;
	}

	int processId = atoi(argv[1]);
	char* dllPath = argv[2];

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!processHandle)
	{
		printf("Error %d - Failed to aquire process handle\n", GetLastError());
		return 1;
	}

	// allocate memory in target process
	LPVOID remoteMemory = VirtualAllocEx(processHandle, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!remoteMemory)
	{
		printf("Error %d - Failed to allocate memory in target process\n", GetLastError());
		return 1;
	}

	// write path of .dll to target process
	if (!WriteProcessMemory(processHandle, remoteMemory, dllPath, strlen(dllPath), nullptr))
	{
		printf("Error %d - Failed to write .dll path to target process\n", GetLastError());
		return 1;
	}

	HMODULE kernel32ModuleHandle = GetModuleHandle("kernel32.dll");
	if (!kernel32ModuleHandle)
	{
		printf("Error %d - Failed to get kernel32 module handle\n", GetLastError());
		return 1;
	}

	FARPROC kernel32LoadLibrary = GetProcAddress(kernel32ModuleHandle, "LoadLibraryA");
	if (!kernel32LoadLibrary)
	{
		printf("Error %d - Failed to resolve LoadLibraryA\n", GetLastError());
		return 1;
	}

	// create a thread in the target process which loads the .dll
	HANDLE remoteThreadHandle = CreateRemoteThread(
		processHandle,
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

	CloseHandle(remoteThreadHandle);
	CloseHandle(processHandle);
}