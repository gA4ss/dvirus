
extern	LoadLibraryA:PROC
extern  WSAStartup:PROC
extern  WSACleanup:PROC
extern  socket:PROC
extern  htons:PROC
extern  inet_addr:PROC
extern	inet_ntoa:PROC
extern	connect:PROC
extern	closesocket:PROC
extern	WSACleanup:PROC
extern	send:PROC
extern	recv:PROC
extern	ExitProcess:PROC

INVALID_SOCKET              equ NOT 0
WSADESCRIPTION_LEN          equ 256
WSASYS_STATUS_LEN           equ 128
WSADATA STRUCT
  wVersion      WORD      ?
  wHighVersion  WORD      ?
  szDescription BYTE WSADESCRIPTION_LEN + 1 dup (?)
  szSystemStatus  BYTE WSASYS_STATUS_LEN + 1 dup (?)
  iMaxSockets   WORD      ?
  iMaxUdpDg     WORD      ?
  lpVendorInfo  DWORD      ?
WSADATA ENDS


S_UN_B STRUCT
  s_b1 BYTE ?
  s_b2 BYTE ?
  s_b3 BYTE ?
  s_b4 BYTE ?
S_UN_B ENDS

S_UN_W STRUCT 
  s_w1 WORD ?
  s_w2 WORD ?
S_UN_W ENDS

ADDRESS_UNION UNION 
   S_un_b S_UN_B <>
   S_un_w S_UN_W <>
   S_addr DWORD ?
ADDRESS_UNION ENDS

in_addr STRUCT
  S_un ADDRESS_UNION <>
in_addr ENDS

sockaddr_in STRUCT
  sin_family    WORD      ?
  sin_port      WORD      ?
  sin_addr      in_addr <>
  sin_zero      BYTE 8 dup (?)
sockaddr_in ENDS

StackSize = 1500h
Buffer = StackSize
BufferSize = 1000h
wsaData = Buffer - BufferSize
s = wsaData - size WSADATA
ServerAddr = s - 04h

.586p
.model flat,stdcall

.code
Start:
	call PushKnlStr
			db	'kernel32.dll',0
	PushKnlStr:
	call LoadLibraryA
	push ebp
	mov ebp, esp
	sub esp, StackSize
Run:
	lea eax, [ebp-wsaData]
	push eax
	push 202h
	call WSAStartup
	test eax, eax
	jnz Run
	push 06h
	push 01h
	push 02h
	call socket
	cmp eax, INVALID_SOCKET
	jz Run
	mov dword ptr [ebp-s], eax
	lea esi, [ebp-ServerAddr]
	mov ax, 02h 
	mov word ptr [esi.sin_family], ax
	mov eax, offset tPort
	push word ptr [eax]
	call htons
	mov word ptr [esi.sin_port], ax
	mov eax, offset tIP
	push eax
	call inet_addr
	mov dword ptr [esi.sin_addr.S_un.S_addr], eax
	
	push size sockaddr_in
	lea eax, [ebp-ServerAddr]
	push eax
	push dword ptr [ebp-s]
	call connect
	cmp eax, -1
	jnz RecvData
	push dword ptr [ebp-s]
	call closesocket
	call WSACleanup
	jmp Exit
RecvData:
	push 0
	push 05h
	mov eax, offset tHello
	push eax
	push dword ptr [ebp-s]
	call send
	
	push dword ptr [ebp-s]
	call closesocket
	call WSACleanup
Exit:	
	mov esp, ebp
	pop ebp
	ret
tHello:
	db	'Hello',0	
tIP:
	db	'127.0.0.1',0
tPort:
	dw	50h	
end Start