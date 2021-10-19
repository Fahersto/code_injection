#include <Windows.h>
#include <cstdint>
#include "winternl.h"
#include <iostream>
#include <shlobj.h>
#include <wchar.h>
#include <fstream>

using fnNtCreateFile = NTSTATUS(NTAPI*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);


int main()
{
	// get path to desktop
	char desktopPath[MAX_PATH + 1];
	SHGetSpecialFolderPathA(HWND_DESKTOP, desktopPath, CSIDL_DESKTOP, FALSE);

	// construct path absolute file path
	static char path[MAX_PATH + 1];
	strcat(path, "\\??\\");
	strcat(path, desktopPath);
	strcat(path, "\\syscall_NtCreateFile.txt");

	// convert path to wchar
	wchar_t wPath[MAX_PATH + 1];
	mbstowcs(wPath, path, strlen(path) + 1);

#ifdef _WIN64
	/*
	| 4C:8BD1				| mov r10,rcx
	| B8 55000000			| mov eax,55
	| F60425 0803FE7F 01	| test byte ptr ds:[7FFE0308],1
	| 75 03					| jne ntdll.7FFD821AD815
	| 0F05					| syscall
	| C3					| ret
	| CD 2E					| int 2E
	| C3					| ret
	*/
	const int SYSCALLSTUB_LENGTH = 0x18;
#else
	/* 32 bit
	| B8 8C010000	| mov eax,18C
	| BA 0003FE7F	| mov edx,<&KiFastSystemCall>
	| FF12			| call dword ptr ds:[edx]
	| C2 2400		| ret 24
	*/
	/* WoW
	| B8 55000000	| mov eax, 55
	| BA 70880477	| mov edx, ntdll.77048870
	| FFD2			| call edx
	| C2 2C00		| ret 2C
	*/
	const int SYSCALLSTUB_LENGTH = 15;
#endif
	int8_t syscallStub[SYSCALLSTUB_LENGTH];

	// resolve syscall address
	HMODULE ntdllHandle = LoadLibraryA("ntdll.dll");
	if (!ntdllHandle)
	{
		printf("Error %d - Failed to acquire ntdll.dll handle\n", GetLastError());
		return 1;
	}

	auto ntCreateFileAddress = GetProcAddress(ntdllHandle, "NtCreateFile");
	if (!ntCreateFileAddress)
	{
		printf("Error %d - Failed to resolve NtCreateFile\n", GetLastError());
		return 1;
	}

	printf("[Info] - Found NtCreateFile at %p\n", ntCreateFileAddress);

	// copy syscall stub
	memcpy(syscallStub, ntCreateFileAddress, SYSCALLSTUB_LENGTH);

	printf("[Info] - Copied %d bytes from NtCreateFile (%p) to stub (%p)\n", SYSCALLSTUB_LENGTH, ntCreateFileAddress, syscallStub);

	// make stub executable
	DWORD oldProtection;
	if (!VirtualProtect(syscallStub, SYSCALLSTUB_LENGTH, PAGE_EXECUTE_READWRITE, &oldProtection))
	{
		printf("Error %d - Failed to make syscall stub executable\n", GetLastError());
		return 1;
	}

	fnNtCreateFile directSyscallCreateFile = (fnNtCreateFile)(void*)syscallStub;

	// setup parameters
	HANDLE fileHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	NTSTATUS status = NULL;
	UNICODE_STRING fileName;
	RtlInitUnicodeString(&fileName, wPath);
	IO_STATUS_BLOCK osb;
	ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
	InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	
	// invoke syscallstub
	if (NT_SUCCESS(directSyscallCreateFile(&fileHandle, FILE_GENERIC_WRITE, &objectAttributes, &osb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
	{
		printf("[Info] - Successfully executed syscall stub, creating file %wS\n", wPath);
	}
	else
	{
		printf("Error %d - Failed to create file\n", GetLastError());
		return 1;
	}

	return 0;
}