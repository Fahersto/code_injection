# Code injections
This repository contains 22 implementations of Host-Based Code Injection Attacks (HBCIAs).

<br/><br/>

## PE injections
Feature | 		Classic		|	 Process Doppelgänging 	| Process Hollowing 	| Transacted Hollowing  | Process Ghosting
--------| 		:-: 		|    :-: 					| :-: 			        | :-:               	| :-: 
32 Bit			| 	   ✔	|		✔					|       ✔		 		|   	✔				|	✔
64 Bit			| 	 ✔		|		✔		            |		✔	 			|		✔				|	✔
WoW64			| 	 ✔		|		➖					|		✔		 		|		✔				|	➖
Windows 7		| 	 ✔     |		✔					|		✔		 		|		✔				|	✔
Windows 10		| 	 ✔     |		❌					|		✔		 		|		✔		 		|	✔

<br/><br/>

## DLL injections
Feature | 		Classic		|	 AppCertDLLs 	| AppInitDLLs 	| KnownDLLs Cache  	| SetWindowsHookEx	| Shim
--------| 		:-: 		|    :-: 			| :-: 			| :-:       		| :-: 				| :-: 
32 Bit			| 	 ✔		|		✔			|       ✔		|   	➖			|	✔				|	➖
64 Bit			| 	 ✔		|		✔		    |		✔	 	|		✔			|	✔				|	✔
WoW64			| 	 ✔		|		✔			|		✔		|		➖			|	✔				|	➖
Windows 7		| 	 ✔     |		✔			|		✔		|		✔			|	✔				|	✔
Windows 10		| 	 ✔     |		✔			|		✔		|		✔			|	✔				|	➖
Unpriviledged 	| 	 ✔     |		❌			|		❌		|		✔			|	✔				|	❌

<br/><br/>

## Shellcode injections
Feature | 		Classic		|	 Entrypoint 	| Extra Window Memory 	| GhostWriting  	| PROPagate			| TLS Callback | Kernel Callback Table
--------| 		:-: 		|    :-: 			| :-: 					| :-:       		| :-: 				| :-: 			| :-: 
32 Bit			| 	 ✔		|		✔			|       ✔				|   	✔			|	✔				|	✔			|	✔
64 Bit			| 	 ✔		|		✔		    |		✔	 			|		✔			|	✔				|	✔			|	✔
WoW64			| 	 ✔		|		✔			|		✔				|		✔			|	✔				|	✔			|	✔
Windows 7		| 	 ✔     |		✔			|		✔				|		➖			|	✔				|	✔			|	✔
Windows 10		| 	 ✔     |		✔			|		✔				|		✔			|	✔				|	✔			|	✔