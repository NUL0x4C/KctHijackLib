#pragma once
#include <Windows.h>


#define FAILEDTO_GET_DLL_OR_API  100
#define FAILEDTO_PLACE_JMPSHELL  200
#define KCT_PNTR_IS_NULL		 300
#define VIRTUAL_API_ERROR		 400
#define NO_ERROR_RETURNED		 500


extern BOOL RunViaKctHijack(PVOID pAddress, PDWORD Error);
extern HANDLE TriggerShellcode();
extern BOOL CleanUp();
