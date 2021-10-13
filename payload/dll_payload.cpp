#include <Windows.h>


/**
* Spawns a MessageBox and then unloads itself from the process it has been loaded into. 
*
*/
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