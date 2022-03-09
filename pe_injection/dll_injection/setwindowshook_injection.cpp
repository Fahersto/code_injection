/**
* DLL injection using SetWindowsHookEx. Triggering the injection requires key presses.
* Ensure you trigger injection on a program with the correct architecture (x86, x64).
* Supports 32- and 64 Bit applications.
* [Requirements]
*	- target process must load user32.dll
*/

#include <Windows.h>
#include <cstdio>


int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("Usage: *.exe dllPath\n");
		return 1;
	}

	char absoluteDllPath[MAX_PATH + 1];
	GetFullPathNameA(argv[1], MAX_PATH + 1, absoluteDllPath, NULL);

	// load library to be injected
	HMODULE dllHandle = LoadLibrary(absoluteDllPath);
	if (!dllHandle) 
	{
		printf("[Error] %d - Failed to load dll %s\n", GetLastError(), absoluteDllPath);
		return 1;
	}

	printf("[Info] - Loaded library %s\n", absoluteDllPath);

	// resolve SetWindowsHookCallback
	HOOKPROC windowsHookCallback = (HOOKPROC)GetProcAddress(dllHandle, "SetWindowsHookCallback");
	if (!windowsHookCallback)
	{
		printf("[Error] %d - Failed to resolve the SetWindowsHookCallback\n", GetLastError());
		return 1;
	}

	printf("[Info] - Resolved SetWindowsHook callback\n");

	// install the hook
	HHOOK hookHandle = SetWindowsHookExA(WH_KEYBOARD, windowsHookCallback, dllHandle, 0);
	if (!hookHandle)
	{
		printf("[Error] %d - Failed to install hook\n", GetLastError());
		return 1;
	}

	printf("[Info] - Installed hook\n");
	printf("[Info] - Press any key to uhook\n");

	// wait for a character press to unhook
	getchar();

	// unhook
	UnhookWindowsHookEx(hookHandle);

	return 0;
}