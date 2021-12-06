/**
* Injects a .dll into every process that uses user32.dll by writing it to the AppInit_DLLs registry key.
* Supports 32- and 64 Bit applications.
* [Warning] Feature is disabled on Windows 8 and newer with secure boot enabled: https://docs.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls.
* [Requirements] https://docs.microsoft.com/en-us/windows/win32/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2?redirectedfrom=MSDN
* - elevated priviledges
*/

#include <Windows.h>
#include <iostream>


bool IsElevated()
{
	HANDLE tokenHandle = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
	{
		return false;
	}

	TOKEN_ELEVATION tokenInformation;
	DWORD returnLength;
	if (!GetTokenInformation(tokenHandle, TokenElevation, &tokenInformation, sizeof(tokenInformation), &returnLength))
	{
		CloseHandle(tokenHandle);
		return false;
	}

	CloseHandle(tokenHandle);
	return tokenInformation.TokenIsElevated;
}

bool IsOsVersionBelowWindows8()
{
	using fnRtlGetVersion = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW lpVersionInformation);

	HMODULE ntdllHandle = GetModuleHandleA("ntdll.dll");
	if (!ntdllHandle)
	{
		printf("[Warning] %d - Failed to get ntdll handle\n", GetLastError());
		return false;
	}

	fnRtlGetVersion RtlGetVersion = (fnRtlGetVersion)GetProcAddress(ntdllHandle, "RtlGetVersion");

	RTL_OSVERSIONINFOW osInfo;
	RtlGetVersion(&osInfo);
	return osInfo.dwMajorVersion < 8 ? true : false;
}

int main(int argc, char* argv[])
{
	bool wowInjeciton = false;
	if (argc >= 2)
	{
		argc == 3 ? wowInjeciton = atoi(argv[2]) : wowInjeciton = false;
	}
	else
	{
		printf("Usage: *.exe dllPath [bWoW64Injection]\n");
		return 1;
	}

	if (!IsElevated())
	{
		printf("[Error] - Writing AppInit_DLLs requires elevated privileges\n");
		return 1;
	}

	if (!IsOsVersionBelowWindows8())
	{
		printf("[Warning] - Could not determine if Windows version is below 8. Starting with Windows 8 and secure boot enabled this method does not work.\n");
	}

	DWORD loadDlls = 1;
	char absoluteDllPath[MAX_PATH + 1];
	GetFullPathNameA(argv[1], MAX_PATH + 1, absoluteDllPath, NULL);

	if (!wowInjeciton)
	{
		HKEY keyHandle;
		RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", &keyHandle);

		if (!keyHandle)
		{
			printf("[Error] - Failed to open registry key\n");
			return 1;
		}

		// 32bit/64bit
		
		if (RegSetValueExA(keyHandle, "LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE*)&loadDlls, sizeof(DWORD)) != ERROR_SUCCESS)
		{
			printf("[Error] - Failed to write dll path to AppInit_DLLs\n");
			return 1;
		}

		printf("[Info] - Wrote LoadAppInit_DLLs for 32bit/64bit\n");

		
		if (RegSetValueExA(keyHandle, "AppInit_DLLs", 0, REG_SZ, (const BYTE*)absoluteDllPath, strlen(absoluteDllPath) + 1) != ERROR_SUCCESS)
		{
			printf("[Error] - Failed to write dll path to AppInit_DLLs\n");
			return 1;
		}

		printf("[Info] - Wrote AppInit_DLLs for 32bit/64bit\n");
	}
#ifdef _WIN64
	if (wowInjeciton)
	{
		// WoW64
		HKEY wow64KeyHandle;
		RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", &wow64KeyHandle);

		if (!wow64KeyHandle)
		{
			printf("[Error] - Failed to open registry key\n");
			return 1;
		}

		if (RegSetValueExA(wow64KeyHandle, "LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE*)&loadDlls, sizeof(DWORD)) != ERROR_SUCCESS)
		{
			printf("[Error] - Failed to write dll path to AppInit_DLLs\n");
			return 1;
		}

		printf("[Info] - Wrote LoadAppInit_DLLs for WoW64\n");

		if (RegSetValueExA(wow64KeyHandle, "AppInit_DLLs", 0, REG_SZ, (const BYTE*)absoluteDllPath, strlen(absoluteDllPath) + 1) != ERROR_SUCCESS)
		{
			printf("[Error] - Failed to write dll path to AppInit_DLLs\n");
			return 1;
		}

		printf("[Info] - Wrote AppInit_DLLs for WoW64\n");
	}
#endif
	

	return 0;
}