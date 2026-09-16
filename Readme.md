# About
This is part two of a position independent shellcode improvement write up. The first can be found, [here](https://github.com/wizardy0ga/improving-my-x64-PIC-shellcode-windows-peb-walk).

In the previous write up, an issue with staticly dereferencing dlls from the InLoadOrderModuleList of the [PEB_LDR_DATA](https://ntdoc.m417z.com/peb_ldr_data) structure was addressed by using string comparison to determine if the BaseDllName member of the [LDR_DATA_TABLE_ENTRY](https://ntdoc.m417z.com/ldr_data_table_entry) was L"KERNEL32.DLL". This ensures any canary dlls put in place by EDR solutions are not accessed by our shellcode.

In this write up, we will replace the string comparison using a djb2 hashing function i created within another, [write-up](https://github.com/wizardy0ga/djb2-hash-x64-assembly).

# The Problem
String comparison is a nice tool however it does a few negative things:
- Requires more opcodes in comparison to hashing, increasing shellcode blob size
- Strings easily give away intention and other patterns to analysts
- Raw strings also increase the final size of the shellcode blob

```asm
strcmp:
    mov rax, 1
    mov r10b, [rcx + rsi]
    mov r11b, [rdx + rsi] 
    cmp r10b, r11b
    jne strcmp_not_found
    cmp r10b, 0
    jne strcmp_epilogue
    cmp r11b, 0
    je strcmp_found
strcmp_epilogue:
    inc rsi
    jmp strcmp
strcmp_not_found:
    xor rsi, rsi
    ret
strcmp_found:
    xor rsi, rsi
    xor rax, rax
    ret

```

# The Solution
A lightweight hashing algorithm such as djb2 allows us to use 4 byte integers to compare strings against known hashes. This may not be the most cryptographically secure however we only need to parse function names from the export table of a dll so something like djb2 will suffice. 

Using hashes over strings, we gain the following benefits:
- Less code overhead meaning less size (algorithm dependant)
- Strings are represented as fixed data buffers meaning less shellcode size
- Analysts need to must work harder to determine original string

This technique is known as **API Hashing**. Mitre identifies this technique as [T1027.007 - Obfuscated Files or Information: Dynamic API Resolution](https://attack.mitre.org/techniques/T1027/007/).

###### x64 djb2 hashing
```
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
```

# Demo

## Kernel32 Dynamic Parsing
A demonstration of the [pebwalk-hash-k32-parse](/pebwalk-hash-k32-parse.x64.asm) shellcode where kernel32 is dynamically parsed from the InLoadOrderModuleList via BaseDllName analysis.

![demo](/img/k32-parse-demo.gif)

## Kernel32 Static Parsing
A demonstration of the [pebwalk-hash-k32-deref](/pebwalk-hash-k32-deref.x64.asm) shellcode where kernel32 is statically dereferenced from the InLoadOrderModuleList without verifying that the LDR_DATA_TABLE_ENTRY structure is actually kernel32.

![demo](/img/k32-deref-demo.gif)