cmake_minimum_required (VERSION 3.4)
project (code_injection)

include_directories(common)

# Mitigation
file(GLOB_RECURSE COPYSYSCALLSTUB_MITIGATION LIST_DIRECTORIES true mitigation/evasion/copysyscallstub.cpp)
add_executable(copysyscallstub_mitigation ${COPYSYSCALLSTUB_MITIGATION})
target_link_libraries(copysyscallstub_mitigation ntdll)

# Payload
file(GLOB_RECURSE DLL_PAYLOAD LIST_DIRECTORIES true payload/dll_payload.cpp)
add_library(dll_payload SHARED ${DLL_PAYLOAD})

file(GLOB_RECURSE EXECUTABLE_PAYLOAD LIST_DIRECTORIES true payload/executable_payload.cpp)
add_executable(executable_payload ${EXECUTABLE_PAYLOAD})

# PE Injection
file(GLOB_RECURSE PE_INJECTION LIST_DIRECTORIES true pe_injection/pe_inject.cpp)
add_executable(pe_injection ${PE_INJECTION})

file(GLOB_RECURSE PROCESS_HOLLOWING LIST_DIRECTORIES true pe_injection/process_hollowing.cpp)
add_executable(process_hollowing ${PROCESS_HOLLOWING})

file(GLOB_RECURSE PROCESS_DOPPELGANGING LIST_DIRECTORIES true pe_injection/process_doppelganging.cpp)
add_executable(process_doppelganging ${PROCESS_DOPPELGANGING} common/ntddk.h)
target_link_libraries(process_doppelganging ntdll Userenv KtmW32)

file(GLOB_RECURSE PROCESS_GHOSTING LIST_DIRECTORIES true pe_injection/process_ghosting.cpp)
add_executable(process_ghosting ${PROCESS_GHOSTING} common/ntddk.h)
target_link_libraries(process_ghosting ntdll Userenv KtmW32)

file(GLOB_RECURSE TRANSACTED_HOLLOWING LIST_DIRECTORIES true pe_injection/transacted_hollowing.cpp)
add_executable(transacted_hollowing ${TRANSACTED_HOLLOWING} common/ntddk.h)
target_link_libraries(transacted_hollowing ntdll KtmW32)

	#DLL Injection
	file(GLOB_RECURSE CLASSIC_DLL_INJECTION LIST_DIRECTORIES true pe_injection/dll_injection/classic_dll_injection.cpp)
	add_executable(classic_dll_injection ${CLASSIC_DLL_INJECTION})

	file(GLOB_RECURSE SETWINDOWHOOK_INJECTION LIST_DIRECTORIES true pe_injection/setwindowshook_injection.cpp)
	add_executable(setwindowhook_dll_injection ${SETWINDOWHOOK_INJECTION})


# Shellcode Injection
file(GLOB_RECURSE CLASSIC_SHELLCODE_INJECTION LIST_DIRECTORIES true shellcode_injection/shellcode.hpp shellcode_injection/classic_shellcode_injection.cpp)
add_executable(classic_shellcode_injection ${CLASSIC_SHELLCODE_INJECTION})

file(GLOB_RECURSE ENTRYPOINT_INJECTION LIST_DIRECTORIES true shellcode_injection/shellcode.hpp shellcode_injection/entrypoint_injection.cpp)
add_executable(entrypoint_injection ${ENTRYPOINT_INJECTION})

file(GLOB_RECURSE QUEUEAPC_INJECTION LIST_DIRECTORIES true shellcode_injection/queueapc_injection.cpp)
add_executable(queueapc_injection ${QUEUEAPC_INJECTION})

file(GLOB_RECURSE THREADCONTEXT_INJECTION LIST_DIRECTORIES true shellcode_injection/threadcontext_injection.cpp)
add_executable(threadcontext_injection ${THREADCONTEXT_INJECTION})