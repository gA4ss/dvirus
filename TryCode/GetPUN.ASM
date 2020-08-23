extrn	OpenProcess:PROC
extrn	OpenProcessToken:PROC
extrn	GetTokenInformation:PROC
extrn	LookupAccountSidA:PROC
ACCOUNTSIZE	= 100h
DOMAINSIZE = 100h
INFOBUFFER = 200h
GetProcessUserNameStackSize = INFOBUFFER + 30h
hAccessToken1 = 08h
snu = 0Ch
pId1 = 10h
hRemoteProcess1 = 14h
dwInfoBufferSize = 18h
szAccountName = 1Ch
dwAccountName = 20h
szDomainName = 24h
dwDomainName = 28h
InfoBuf = GetProcessUserNameStackSize 
ACCOUNTSIZE	= 100h
DOMAINSIZE = 100h
INFOBUFFER = 200h
SID_AND_ATTRIBUTES STRUCT
  Sid           DWORD      ?
  Attributes    DWORD      ?
SID_AND_ATTRIBUTES ENDS

TOKEN_USER STRUCT
    User SID_AND_ATTRIBUTES <>
TOKEN_USER ENDS

TH32CS_SNAPPROCESS      				equ 2
PROCESS_QUERY_INFORMATION 	     		equ (0400h)  
TOKEN_QUERY 			     			equ (0008h)
TokenUser                            	equ 1
PROCESS_QUERY_INFORMATION 				equ (0400h)
TOKEN_QUERY 							equ (0008h)	

.586p
.model flat, stdcall

.data
	szName	db	100 dup(?)
	szDomain db	100 dup(?)
	pid	dd	3FCh
.code
Start:
	push offset szDomain
	push offset szName
	push pid
	call GetProcessUserName
	ret
GetProcessUserName:			;第一个参数为进程ID;第二个为用户缓冲,第三个为域名缓冲
	push ebp
	mov ebp, esp
	sub esp, GetProcessUserNameStackSize
	mov eax, dword ptr [ebp+08h]
	mov dword ptr [ebp-pId1], eax
	mov eax, dword ptr [ebp+0Ch]
	mov dword ptr [ebp-szAccountName], eax
	mov eax, dword ptr [ebp+10h]
	mov dword ptr [ebp-szDomainName], eax
	
	mov eax, 100h
	mov dword ptr [ebp-dwDomainName], eax
	mov dword ptr [ebp-dwAccountName], eax
	
	push dword ptr [ebp-pId1]
	push 0
	push PROCESS_QUERY_INFORMATION
	call OpenProcess
	mov dword ptr [ebp-hRemoteProcess1], eax
	lea eax, [ebp-hAccessToken1]
	push eax
	push TOKEN_QUERY
	push dword ptr [ebp-hRemoteProcess1]
	call OpenProcessToken
	lea eax, [ebp-dwInfoBufferSize]
	push eax
	push INFOBUFFER
	lea esi, [ebp-InfoBuf]
	push esi
	push 1
	push dword ptr [ebp-hAccessToken1]
	call GetTokenInformation
	lea eax, [ebp-snu]
	push eax
	lea eax, [ebp-dwDomainName]
	push eax
	push dword ptr [ebp-szDomainName]
	lea eax, [ebp-dwAccountName]
	push eax
	push dword ptr [ebp-szAccountName]
	push dword ptr [esi.User.Sid]
	push 0
	call LookupAccountSidA
	mov esp, ebp
	pop ebp
	ret
EndGetProcessUserName:
end Start