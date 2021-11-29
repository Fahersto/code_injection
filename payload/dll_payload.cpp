/**
* Spawns a MessageBox and then unloads itself from the process it has been loaded into.
*
*/

#include <Windows.h>

// export for SetWindowsHook injection
extern "C" __declspec(dllexport) int SetWindowsHookCallback(int code, WPARAM wParam, LPARAM lParam)
{
	Beep(300, 200);
	return(CallNextHookEx(NULL, code, wParam, lParam));
}

// exports for shim injection
extern "C" __declspec(dllexport) int GetHookAPIs(PVOID a, PVOID b, PVOID c)
{
	return 0x01;
}

extern "C" __declspec(dllexport) int NotifyShims(PVOID a, PVOID b)
{
	return 0x01;
}

DWORD __stdcall Run(LPVOID hModule)
{
	MessageBoxA(NULL, "Message from payload", "Injected payload", MB_OK);
	FreeLibraryAndExitThread(static_cast<HMODULE>(hModule), 0);
	return TRUE;
}

BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, 0, Run, hModule, 0, nullptr);
		break;
	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}
	return TRUE;
}