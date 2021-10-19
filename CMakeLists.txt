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

	#DLL Injection
	file(GLOB_RECURSE CLASSIC_DLL_INJECTION LIST_DIRECTORIES true pe_injection/dll_injection/classic_dll_injection.cpp)
	add_executable(classic_dll_injection ${CLASSIC_DLL_INJECTION})


# Shellcode Injection
file(GLOB_RECURSE CLASSIC_SHELLCODE_INJECTION LIST_DIRECTORIES true shellcode_injection/shellcode.hpp shellcode_injection/classic_shellcode_injection.cpp)
add_executable(classic_shellcode_injection ${CLASSIC_SHELLCODE_INJECTION})

file(GLOB_RECURSE ENTRYPOINT_INJECTION LIST_DIRECTORIES true shellcode_injection/shellcode.hpp shellcode_injection/entrypoint_injection.cpp)
add_executable(entrypoint_injection ${ENTRYPOINT_INJECTION})

file(GLOB_RECURSE QUEUEAPC_INJECTION LIST_DIRECTORIES true shellcode_injection/queueapc_injection.cpp)
add_executable(queueapc_injection ${QUEUEAPC_INJECTION})