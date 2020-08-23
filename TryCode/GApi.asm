.586p
.model flat, stdcall
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
    Name1 				db IMAGE_SIZEOF_SHORT_NAME dup(?)
    VirtualSize 			dd     	?
    VirtualAddress_Section_Header	dd     	?
    SizeOfRawData 			dd     	?
    PointerToRawData 			dd     	?
    PointerToRelocations 		dd 		?
    PointerToLinenumbers 		dd 		?
    NumberOfRelocations 		dw  	?
    NumberOfLinenumbers 		dw  	?
    Characteristics_Section_Header 	dd      ?
IMAGE_SECTION_HEADER ENDS
.code
Start:
	call GetApiAddress
	push ebp
	mov ebp, esp
	sub esp, 100h
	mov dword ptr [ebp-04h], ebx
	;得到LoadLibraryA的地址
	call PushLoadLibraryA
		db	'LoadLibraryA',0
	PushLoadLibraryA:
	push esi
	call ebx
	mov dword ptr [ebp-08h], eax
	mov dword ptr [ebp-100h], esi

	mov ecx, esp
	call Push1
		db	'CreateFileA',0
	Push1:
	call Push2
		db	'ReadFile',0
	Push2:
	call Push3
		db	'WriteFile',0
	Push3:
	call Push4
		db	'CreateProcessA',0
	Push4:
	sub ecx, esp
	shr ecx, 2
	
	lea edi, [ebp-0Ch]
	cld
	LOOP1:
	push dword ptr [ebp-100h]
	call dword ptr [ebp-04h]
	lodsd
	loop LOOP1
	nop
	nop
	nop
	nop
	ret
GetApiAddress:
	push ebp
	mov ebp, esp
	sub esp, 10h
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
EndGetApiAddress:
end Start