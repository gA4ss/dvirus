extrn	CreateToolhelp32Snapshot:PROC
extrn	Process32First:PROC
extrn	lstrcmpA:PROC
extrn	Process32Next:PROC
extrn	CloseHandle:PROC

MAX_PATH = 128h
INVALID_HANDLE_VALUE = -1
TRUE = 1
FALSE = 0
NULL = 0

PROCESSENTRY32 STRUCT
    dwSize              DWORD ?
    cntUsage            DWORD ?
    th32ProcessID       DWORD ?
    th32DefaultHeapID   DWORD ?
    th32ModuleID        DWORD ?
    cntThreads          DWORD ?
    th32ParentProcessID DWORD ?
    pcPriClassBase      DWORD ?
    dwFlags             DWORD ?
    szExeFile           db MAX_PATH dup(?)
PROCESSENTRY32 ENDS
TH32CS_SNAPPROCESS      equ 2

GetPidFromProcessNameStackSize = size PROCESSENTRY32 + 10h
szProcessName1 = 08h
hProcessSnap = 0Ch
pe32 = GetPidFromProcessNameStackSize

.586p
.model flat, stdcall
.data
	szName db	'winlogon.exe',0
.code
Start:

	push offset szName
	call GetPidFromProcessName
	ret
GetPidFromProcessName:		;第一个参数为进程名
	push ebp
	mov ebp, esp
	sub esp, GetPidFromProcessNameStackSize
	mov eax, dword ptr [ebp+08h]
	mov dword ptr [ebp-szProcessName1], eax
	mov eax, INVALID_HANDLE_VALUE
	mov dword ptr [ebp-hProcessSnap], eax
	lea esi, [ebp-pe32]
	push 0
	push TH32CS_SNAPPROCESS
	call CreateToolhelp32Snapshot
	cmp eax, INVALID_HANDLE_VALUE
	jz Error_GetPidFromProcessName
	mov dword ptr [ebp-hProcessSnap], eax
	mov dword ptr [esi.dwSize], size PROCESSENTRY32
	push esi
	push dword ptr [ebp-hProcessSnap]
	call Process32First
	test eax, eax
	jz Error_GetPidFromProcessName
Enum_Process:
	lea eax, [esi.szExeFile]
	push eax
	push dword ptr [ebp-szProcessName1]
	call lstrcmpA
	test eax, eax
	jnz Next_Process
	mov eax, dword ptr [esi.th32ProcessID]
	jmp CloseHandle_GetPidFromProcessName
Next_Process:
	push esi
	push dword ptr [ebp-hProcessSnap]
	call Process32Next
	test eax, eax
	jnz Enum_Process
Error_GetPidFromProcessName:
	xor eax, eax
	jmp Exit_GetPidFromProcessName	
CloseHandle_GetPidFromProcessName:
	cmp dword ptr [ebp-hProcessSnap], INVALID_HANDLE_VALUE
	jz Error_GetPidFromProcessName
	push eax
	push dword ptr [ebp-hProcessSnap]
	call CloseHandle
	pop eax	
Exit_GetPidFromProcessName:	
	mov esp, ebp
	pop ebp
	ret
EndGetPidFromProcessName:
end Start