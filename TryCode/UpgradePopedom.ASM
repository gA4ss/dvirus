;提升本进程的到调试权限
;UpgradePopedom.ASM
extrn	OpenProcessToken:PROC
extrn	GetCurrentProcess:PROC
extrn	LookupPrivilegeValueA:PROC
extrn	AdjustTokenPrivileges:PROC
extrn	GetCurrentThread:PROC
extrn	CloseHandle:PROC

SE_PRIVILEGE_ENABLED                 equ 2h
ANYSIZE_ARRAY                        equ 1
TOKEN_ADJUST_PRIVILEGES              equ 20h
TOKEN_QUERY 						 equ (0008h)

LUID STRUCT
  LowPart   DWORD      ?
  HighPart  DWORD      ?
LUID ENDS

LUID_AND_ATTRIBUTES STRUCT
    Luid LUID <>
    Attributes dd ?
LUID_AND_ATTRIBUTES ENDS

TOKEN_PRIVILEGES STRUCT
  PrivilegeCount    DWORD      ?
  Privileges        LUID_AND_ATTRIBUTES ANYSIZE_ARRAY dup(<>)
TOKEN_PRIVILEGES ENDS

TOKENPRIVILEGESIZE = size TOKEN_PRIVILEGES

UPSTACKSIZE = TOKENPRIVILEGESIZE + 04h
uphToken = 04h
uptp = UPSTACKSIZE

.586p
.model flat, stdcall
.code
Start:
	call UpgradePopedomProcess
	ret
UpgradePopedomProcess:
	push ebp
	mov ebp, esp
	sub esp, UPSTACKSIZE
	lea eax, [ebp-uphToken]
	push eax
	push TOKEN_ADJUST_PRIVILEGES + TOKEN_QUERY
	call GetCurrentProcess
	push eax
	call OpenProcessToken
	lea esi, [ebp-UPSTACKSIZE]
	mov eax, 1
	mov dword ptr [esi.PrivilegeCount], eax
	push dword ptr [esi.PrivilegeCount]
	lea eax, [esi.Privileges[0].Luid]
	push eax
	call PushUUPSE_DEBUG_NAMEStr
		db	'SeDebugPrivilege',0
	PushUUPSE_DEBUG_NAMEStr:
	push 0
	call LookupPrivilegeValueA
	mov eax, SE_PRIVILEGE_ENABLED
	mov dword ptr [esi.Privileges[0].Attributes], eax
	push 0
	push 0
	push TOKENPRIVILEGESIZE
	push esi
	push 0
	push dword ptr [ebp-uphToken]
	call AdjustTokenPrivileges
	push dword ptr [ebp-uphToken]
	call CloseHandle
	mov esp, ebp
	pop ebp
	ret
EndUpgradePopedomProcess:
end Start
