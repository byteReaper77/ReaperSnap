/*
 * -----------------------------------------------------------------------------
 *  Project       : reaperSnap
 *  Author        : Byte Reaper
 *  Contact       : @ByteReaper0 (Telegram)
 *  License       : MIT 
 *

 *  Description   : 
 *      A single-entry CPUID‑based diagnostic snapshot tool for x86_64 Linux.
 *      Captures detailed CPU information, topology, cache parameters,
 *      general-purpose and SIMD register states (XMM/YMM), memory map ranges
 *      (heap/stack), protection permissions, and auxiliary vector data.
 *
 *  Features      :
 *    - Inline assembly + direct syscalls (write, uname, getcpu, etc.)
 *    - CPUID leaves: 0, 1, 0x0B (extended topology), 0x8000_0002..4 (brand)
 *    - Stack & heap memory range via /proc/self/maps
 *    
 *    - AuxV values: AT_PAGESZ, AT_HWCAP, AT_BASE, AT_UID/EUID/GID/EGID, AT_CLKTCK, AT_EXECFN
 *    - General registers (RAX–RFLAGS–RIP) in hex & binary, with flag decode (CF, PF, ZF…)
 *    - SIMD registers (XMM0–XMM15, YMM0–YMM7)
 *    - Segment selectors (CS, DS, SS, ES, FS, GS)
 *

 *  Usage         :
 *    1. Compile: gcc  ReaperSnap.c -o reaperSnap -mavx2
 *    2. Run:     ./reaperSnap
 *    3. Invoke `reaperSnap("Label")` before and after your inline-assembly block
 *
 *

 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <immintrin.h>

void reaperSnap(const char *lable)
{   
    struct utsname obJ;
    const char *errorU = "\e[1;31m[-] Failed Syscall sys_uname, Exit...\n";
    const char *pidMes = "\e[1;36m[PID] : ";
    static char newLineBuf[] = "\n";
    size_t errorUlen = strlen(errorU);
    size_t pidMesLen = strlen(pidMes);
    pid_t pid;
    char pidS[32];
    static int show = 0;
    const char *m1 = "\e[1;33m\n============================================ [ Snapshot Before Inline Assembly ] ============================================"; 
    size_t m1Len = strlen(m1) - 1;
    printf("\e[1;37m-------------------------------------------------------------------------------------------------------------------------\n");
    printf("[+] System information : \n");
    __asm__ volatile 
    (
        "cmp $0, %[show]\n\t"
        "jne printfMessage\n\t"
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[m1], %%rsi\n\t"
        "mov %[m1Len], %%rdx\n\t"
        "syscall\n\t"
        "mov $63, %%rax\n\t"
        "mov %[name], %%rdi\n\t"
        "syscall\n\t"
        "cmp $0, %%rax\n\t"
        "jl 1f\n\t"            
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[nl], %%rsi\n\t"
        "mov $1, %%rdx\n\t"
        "syscall\n\t"
        "mov $39, %%rax\n\t"
        "syscall\n\t"
        "mov %%eax, %[pid]\n\t"   
        "jmp 2f\n\t"
        "1:\n\t"
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[errorU], %%rsi\n\t"
        "mov %[errorUlen], %%rdx\n\t"
        "syscall\n\t"
        "mov $60, %%rax\n\t"
        "xor %%rdi, %%rdi\n\t"
        "syscall\n\t"
        "movl $1, %[show]\n\t"
        "printfMessage:\n\t"
        "2:\n\t"
        :
        [pid] "=r"(pid),
        [show] "+r" (show)
        :
        [m1] "r" (m1),
        [m1Len] "r" (m1Len), 
        [name] "r"(&obJ), 
        [errorU] "r"(errorU),
        [errorUlen] "r"(errorUlen),
        [nl] "r"(newLineBuf)
        :
        "rax",
        "rdi",
        "rsi",
        "rdx",
        "memory"
    );
    snprintf(pidS,
        sizeof(pidS),
        "%d",
        pid);
    size_t pidSlen = strlen(pidS);
    __asm__ volatile 
    (
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[pidMes], %%rsi\n\t"
        "mov %[pidMesLen], %%rdx\n\t"
        "syscall\n\t"
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[pidS], %%rsi\n\t"
        "mov %[pidSlen], %%rdx\n\t"
        "syscall\n\t"
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[newLine], %%rsi\n\t"
        "mov $1, %%rdx\n\t"
        "syscall\n\t"
        : 
        : [pidMes] "r" (pidMes),
          [pidMesLen] "r" (pidMesLen),
          [pidS] "r" (pidS),
          [pidSlen] "r" (pidSlen),
          [newLine] "r" (newLineBuf)
        :"rax",
         "rdi",
         "rsi",
         "rdx",
         "memory"
    );
    
    pid_t tid;
    const char *tidS = "\e[1;36m\n[TID] : ";
    size_t tidSLen = strlen(tidS);
    char tidF[32];
    __asm__ volatile
    (
        "mov $186, %%rax\n\t"
        "syscall\n\t"
        "mov %%eax, %[tid]"
        : [tid] "=r" (tid)
        : 
        : "rax"
    );
    snprintf(tidF,
        sizeof(tidF),
        "%d",
        tid);
    size_t tidFL = strlen(tidF) - 1;
    __asm__ volatile
    (
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[tidMessage], %%rsi\n\t"
        "mov %[tidMessageLen], %%rdx\n\t"
        "syscall\n\t"
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[tidsn], %%rsi\n\t"
        "mov %[tidsnLen], %%rdx\n\t"
        "syscall\n\t"
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov %[newLine], %%rsi\n\t"
        "mov $1, %%rdx\n\t"
        "syscall\n\t"
        :
        : [tidMessage] "r" (tidS),
          [tidMessageLen] "r" (tidSLen),
          [tidsn]  "r" (tidF),
          [tidsnLen] "r" (tidFL),
          [newLine] "r" (newLineBuf)
        : "rax",
          "rdi",
          "rsi",
          "rdx",
          "memory"
    );
    unsigned  cpu,node;
    if (syscall(SYS_getcpu,
            &cpu,
            &node,
            NULL) == 0)
    {
        printf("\e[1;34m\n[RUNNING CPU] :  %u\n", 
            cpu);
        printf("\e[1;34m[NUMA NODE]  : %u\n", 
            node);
    }
    else 
    {
        perror("\e[1;31m[-] SYSCALL SYS_getcpu Faild Call !\n");
        exit(1);
    }
    int showInfo = 0;
   
    printf("\e[1;34m[release]  : %s\n", 
        obJ.release);
    printf("\e[1;34m[version]  : %s\n", 
        obJ.version);
    printf("\e[1;34m[OS] :  %s\n", 
        obJ.machine);
    uint64_t  rax,
        rbx,
        rcx, 
        rdx,
        rsp,
        rbp, 
        rip, 
        rflags;
    uint64_t stack[16];
    __asm__ __volatile__ 
    (
        "mov %%rax, %0\n\t"
        "mov %%rbx, %1\n\t"
        "mov %%rcx, %2\n\t"
        "mov %%rdx, %3\n\t"
        "mov %%rsp, %4\n\t"
        "mov %%rbp, %5\n\t"
        "pushfq\n\tpop %6\n\t"
        "lea (%%rip), %7\n\t"
        : "=r"(rax), 
          "=r"(rbx), 
          "=r"(rcx), 
          "=r"(rdx),
          "=r"(rsp), 
          "=r"(rbp), 
          "=r"(rflags), 
          "=r"(rip)
        :
        : "memory"
    );
    FILE *file = fopen("/proc/self/maps", "r");
    if (!file) 
    {
        perror("[-] Error OPEN FILE\n");
        __asm__ volatile
        (
            "mov $60, %%rax\n\t"
            "xor %%rdi, %%rdi\n\t"
            "syscall\n\t"
            :
            :
            :"rax",
             "rdi"
        );
    }

    char line[256];
    unsigned long stack_start = 0, stack_end = 0;
    unsigned long heap_start = 0, heap_end = 0;
    int found_stack = 0, found_heap = 0;
    
    while (fgets(line,
            sizeof(line),
            file))
    {
        if (strstr(line,"[stack]") != NULL)
        {
            sscanf(line,
                "%lx-%lx",
                &stack_start,
                &stack_end);
            found_stack = 1;
        }
        else if (strstr(line, "[heap]") != NULL)
        {
            sscanf(line, 
                "%lx-%lx", 
                &heap_start, 
                &heap_end);
            found_heap = 1;
        }
        if (found_stack && found_heap)
            break;  
    }
    fclose(file);

    if (found_stack)
    {
        printf("\e[1;34m[+] Stack Range: %lx - %lx\n",
            stack_start,
            stack_end);
    }
    else
    {
        printf("\e[1;31m[-] Stack not found\n");
    }

    if (found_heap)
    {
        printf("\e[1;34m[+] Heap Range: %lx - %lx\n",
            heap_start,
            heap_end);
    }
    else
    {
        printf("\e[1;31m[-] Heap not found\n");
    }
    memset(line, 0,sizeof(line));
    unsigned long pageS = getauxval(AT_PAGESZ);
    unsigned long hr = getauxval(AT_HWCAP);
    unsigned long base = getauxval(AT_BASE);
    unsigned long uid = getauxval(AT_UID);
    unsigned long euid = getauxval(AT_EUID);
    unsigned long gid = getauxval(AT_GID);
    unsigned long egid = getauxval(AT_EGID);
    unsigned long clk = getauxval(AT_CLKTCK);
    char *execfn = (char *)getauxval(AT_EXECFN);
    if (pageS == 0 || hr == 0 || base == 0)
    {
        printf("\e[1;31m[-] Error Get Info !!\n");
        printf("\e[1;31m[-] getauxval() Return Value is 0, Exit...\n");
        __asm__ volatile
        (
            "mov $60, %%rax\n\t"
            "xor %%rdi, %%rdi\n\t"
            "syscall\n\t"
            :
            :
            : "rax", "rdi"
        );
    }

    printf("\e[1;34m[+] Page size: %lu bytes\n",
        pageS);
    printf("\e[1;34m[+] Hardware capabilities: 0x%lx\n",
        hr);
    printf("\e[1;34m[+] Base address of program interpreter: 0x%lx\n",
        base);
    printf("\e[1;34m[+] UID : %lu, EUID: %lu\n",
        uid, euid);
    printf("\e[1;34m[+] GID : %lu, EGID: %lu\n",
        gid, 
        egid);
    printf("\e[1;34m[+] Clock ticks per second: %lu\n",
        clk);
    if (execfn) 
    {
        printf("\e[1;33m[+] Executable filename: %s\n",
            execfn);
    }
    printf("\e[1;37m--------------------------------------------------\n");
    printf("\e[1;35m[+] INFO CPUID : \n");
    uint32_t eax,
        ebx,
        ecx,
        edx;
    uint32_t leaf = 0; 
    __asm__ volatile 
    (
        "cpuid"
        : "=a" (eax),
          "=b" (ebx),
          "=c" (ecx),
          "=d" (edx)
        : "a" (leaf)
    );
    char vendor[13]; 
    memcpy(&vendor[0],
        &ebx,
        4);
    memcpy(&vendor[4],
        &edx,
        4);
    memcpy(&vendor[8],
        &ecx,
        4);    
    vendor[12] = '\0';
    printf("\e[1;34m[+] Vendore String : %s\n",
        vendor);
     __asm__ volatile 
     (
        "cpuid"
        : "=a" (eax),
          "=b" (ebx),
          "=c" (ecx),
          "=d" (edx)
        : "a" (1)
    );
    uint8_t steppingId = eax & 0xF;
    uint8_t model = (eax >> 4) & 0xF;
    uint8_t familyId = (eax >> 8) & 0xF;
    uint8_t processorType = (eax >> 12) & 0x3;
    uint8_t extendedModel = (eax >> 16) & 0xF;
    uint8_t extendedFamily = (eax >> 20) & 0xFF; 
    if (familyId == 0xF)
    {
        familyId += extendedFamily;
    }
    if (familyId == 0x6 || familyId == 0xF)
    {
        model += (extendedModel << 4);
    }
    printf("\e[1;34m[+] Family: %u\n",
        familyId);
    printf("\e[1;34m[+] Model: %u\n",
        model);
    printf("\e[1;34m[+] Stepping: %u\n",
        steppingId);
    printf("\e[1;34m[+] Processor Type: %u\n",
        processorType);
    eax = 0x80000006;
    __asm__ volatile
    (
        "cpuid"
        : "=a"(eax),
          "=b"(ebx),
          "=c"(ecx),
          "=d"(edx)
        : "a"(eax)
    );

    uint8_t lineSize      =  ecx        & 0xFF;      
    uint8_t assoc_code    = (ecx >> 12) & 0x0F;      
    uint16_t cacheSizeKB  = (ecx >> 16) & 0xFFFF;    

    printf("\e[1;35m[+] Information L2 Cache : \n");
    printf("\e[1;34m-> Line Size in Bytes : %u\n",lineSize);
    printf("\e[1;34m-> L2 Cache Associativity : 0x%X\n",assoc_code);
    printf("\e[1;34m-> L2 Cache Descrideb: %u\n",cacheSizeKB);
    switch (assoc_code) 
    {
        case 0x00:
            printf("\e[1;34m-> L2 Cache Associativity: Disabled\n");
            break;
        case 0x01:
            printf("\e[1;34m-> L2 Cache Associativity: Direct Mapped\n");
            break;
        case 0x02:
            printf("\e[1;34m-> L2 Cache Associativity: 2-Way\n");
            break;
        case 0x04:
            printf("\e[1;34m-> L2 Cache Associativity: 4-Way\n");
            break;
        case 0x06:
            printf("\e[1;34m-> L2 Cache Associativity: 8-Way\n");
            break;
        case 0x08:
            printf("\e[1;34m-> L2 Cache Associativity: 16-Way\n");
            break;
        case 0x0F:
            printf("\e[1;34m-> L2 Cache Associativity: Fully Associative\n");
            break;
        default:
            printf("\e[1;34m-> L2 Cache Associativity: Unknown (0x%X)\n", assoc_code);
            break;
    }
    printf("\e[1;35m\e[1;34m[+] Extended Topology : \n");
    uint32_t level = 0;
     uint32_t maxBasic;
    __asm__ volatile (
        "cpuid"
        : "=a"(maxBasic),
          "=b"(ebx),
          "=c"(ecx), 
          "=d"(edx)
        : "a"(0)
    );

    printf("\e[1;34m[*] Max basic CPUID leaf   : 0x%X\n",
        maxBasic);

    if (maxBasic <  0x0B) 
    {
        printf("\e[1;31m[-] Extended Topology (leaf 0x0B) not supported on this CPU.\n");
    } 
    else 
    {
        printf("\e[1;34m[+] Extended Topology:\n");
        uint32_t level = 0;
        while (1) 
        {
            eax = 0x0B;
            ecx = level;
            __asm__ volatile (
                "cpuid"
                : "=a"(eax),
                  "=b"(ebx),
                  "=c"(ecx),
                  "=d"(edx)
                : "a"(eax),
                  "c"(ecx)
            );

            uint32_t level_type = (ecx >> 8) & 0xFF;
            uint32_t level_number = ecx & 0xFF;

            if (level_type == 0)
            {
                break;
            }

            printf("\e[1;34m-> Level %u: ",
                level_number);
            if (level_type == 1)
                printf("\e[1;34m[+] SMT\n");
            else if (level_type == 2)
                printf("\e[1;34m[+] Core\n");
            else
                printf("\e[1;31m[-] Unknown (type %u)",
                    level_type);

            printf("\e[1;34m-> Logical Processors: %u",
                ebx);
            printf("\e[1;34m-> Shift Right: %u",
                eax);
            printf("\e[1;34m-> x2APIC ID: %u\n",
                edx);

            level++;
        }
    }
    uint32_t maxExtended;
    char brand[49] = { 0 };

   
    __asm__ volatile
    (
        "cpuid"
        : "=a"(maxExtended),
          "=b"(ebx),
          "=c"(ecx),
          "=d"(edx)
        : "a"(0x80000000)
    );

    if (maxExtended >= 0x80000004)
    {
        for (uint32_t i = 0; i < 3; i++)
        {
            __asm__ volatile
            (
                "cpuid"
                : "=a"(eax),
                  "=b"(ebx),
                  "=c"(ecx),
                  "=d"(edx)
                : "a"(0x80000002 + i)
            );
            memcpy(brand + i * 16 + 0,
                &eax,
                4);
            memcpy(brand + i * 16 + 4,
                &ebx,
                4);
            memcpy(brand + i * 16 + 8,
                &ecx,
                4);
            memcpy(brand + i * 16 + 12, 
                &edx,
                4);
        }
        printf("[+] Processor Brand String: %s\n",
            brand);
    }
    else 
    {
        printf("[-] Processor Brand String not supported on this CPU.\n");
    }
    printf("\e[1;37m[+] Value YMM : ------------------------------------\n");
    eax = 1;
    __asm__ volatile
    (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );

    if (ecx & (1 << 28)) 
    {
        printf("\e[1;34m[+] AVX Supported\n");
    }
    else 
    {
        printf("\e[1;31m[-] AVX Not Supported\n");
    }
    
    int32_t  ymmResult[8];
    __m256i ymm1 = _mm256_set_epi32(8,
            7,
            6,
            5,
            4,
            3,
            2,
            1);
    __m256i ymm2 = _mm256_set_epi32(8,
            7,
            6,
            5,
            4,
            3,
            2,
            1);
    __m256i  ymm0 = _mm256_cmpeq_epi32(ymm1,
            ymm2); 
    _mm256_storeu_si256((__m256i *)ymmResult,
            ymm0);   
    printf("\e[1;33m[+] YMM Result:\n");
    for (int i = 0; i < 8; i++) 
    {
        printf("\e[1;34m[+] Element %d: 0x%X\n",
                i,
                ymmResult[i]);
        if (ymmResult[i] == 0xFFFFFFFF)
        {
            printf("\e[1;36m-> Element %d : There is a value match\n",
                i);
        }
        else 
        {
            printf("\e[1;31m-> Element %d : Not value match !\n",
                i);
        }
    }
   printf("\e[1;37m-----------------------------------------------------\n");
    for (int i = 0; i < 18; i++)
    {
        stack[i] = *((uint64_t *)(rsp + i * 8));
    }
    printf("\e[1;35m\n=============================================== [Value Regester] ===============================================\n");
    printf("\e[1;37m+----------+-------------------------+\n");
    printf("\e[1;37m| Register |          Value          |\n");
    printf("\e[1;37m+----------+-------------------------+\n");
    printf("\e[1;37m| %-8s | 0x%016lx      |\n",
        "RAX",
        rax);
    printf("\e[1;37m| %-8s | 0x%016lx      |\n",
        "RBX",
        rbx);
    printf("\e[1;37m| %-8s | 0x%016lx      |\n",
        "RCX",
        rcx);
    printf("\e[1;37m| %-8s | 0x%016lx      |\n", 
        "RDX",
        rdx);
    printf("\e[1;37m| %-8s | 0x%016lx      |\n", "RSP",
        rsp);
    printf("\e[1;37m| %-8s | 0x%016lx      |\n",
        "RBP",
        rbp);
    printf("\e[1;37m| %-8s | 0x%016lx      |\n",
        "RIP" ,
        rip);
    printf("\e[1;37m| %-8s | 0x%016lx      |\n", 
        "FLAGS",
        rflags);
    printf("\e[1;37m+----------+-------------------------+\n");
    printf("================================ [Value Register (Binary)] ================================\n");
    printf("-----------+------------------------------------------------------------------------------+\n");
    printf("\e[1;37m| %-8s | %064b \t\t  |\n", "RAX",
        rax);
    printf("\e[1;37m| %-8s | %064b \t\t  |\n", "RBX",
        rbx);
    printf("\e[1;37m| %-8s | %064b \t\t  |\n", "RCX",
        rcx);
    printf("\e[1;37m| %-8s | %064b \t\t  |\n", "RDX",
        rdx);
    printf("\e[1;37m| %-8s | %064b \t\t  |\n", "RSP",
        rsp);
    printf("\e[1;37m| %-8s | %064b \t\t  |\n", "RBP",
        rbp);
    printf("\e[1;37m| %-8s | %064b \t\t  |\n", "RIP",
        rip);
    printf("\e[1;37m| %-8s | %064b \t\t  |\n", "FLAGS",
        rflags);
    printf("-----------+------------------------------------------------------------------------------+\n");
    printf("\e[1;35m[Flag cases]-----------------------------------------------------------------------\n");
    if (rflags & (1 << 0))
    {
         printf("\e[1;36m-> Carry Flag (CF) is set\n");
    }
    else
    {
        printf("\e[1;31m-> Carry Flag (CF) is clear\n");
    }
    if (rflags & (1 << 2))
    {
        printf("\e[1;36m-> Parity Flag (PF) is set\n");
    }
    else
    {
        printf("\e[1;31m-> Parity Flag (PF) is clear\n");
    }
    if (rflags & (1 << 6))
    {
        printf("\e[1;36m-> Zero Flag (ZF) is set\n");
    }
    else
    {
        printf("\e[1;31m-> Zero Flag (ZF) is clear\n");
    }

    if (rflags & (1 << 7))
    {
        printf("\e[1;36m-> Sign Flag (SF) is set\n");
    }
    else
    {
        printf("\e[1;31m-> Sign Flag (SF) is clear\n");
    }
    if (rflags & (1 << 8))
    {
        printf("\e[1;36m-> Trap Flag (TF) is set\n");
    }
    else
    {
        printf("\e[1;31m-> Trap Flag (TF) is clear\n");
    }
    if (rflags & (1 << 11))
    {
        printf("\e[1;36m-> Overflow Flag (OF) is set\n");
    }
    else
    {
        printf("\e[1;31m-> Overflow Flag (OF) is clear\n");
    }

    printf("\e[1;36m\n--------------------------------------------------- [Stack Snapshot] ---------------------------------------------------\n");
    fflush(stdout);
    printf("\e[1;37m"); 
    printf("+----------------+-------------------+\n");
    printf("|   Offset       |       Value       |\n");
    printf("+----------------+-------------------+\n");
    for (int i = 0; i < 16; ++i) 
    {
        char offset[16];
        snprintf(offset, 
            sizeof(offset),
            "RSP+%-3d",
            i * 8);
        printf("| %-14s | 0x%016lx|\n",
            offset,
            stack[i]);
    }
    printf("+----------------+-------------------+\n");
    printf("\e[0m"); 
    float xmm0Val[4],xmm1Val[4],
        xmm2Val[4], xmm3Val[4];
    float xmm4Val[4], xmm5Val[4],
        xmm6Val[4], xmm7Val[4],
        xmm8Val[4], xmm9Val[4],
        xmm10Val[4],xmm11Val[4],
        xmm12Val[4], xmm13Val[4],
        xmm14Val[4], xmm15Val[4];
    float iniValue0[4]  = {  1.1f,  2.2f,  3.3f,  4.4f};  
    float iniValue1[4]  = {  5.5f,  6.6f,  7.7f,  8.8f};  
    float iniValue2[4]  = {  9.9f, 10.1f, 11.1f, 12.1f};  
    float iniValue3[4]  = { 13.3f, 14.4f, 15.5f, 16.6f};  
    float iniValue4[4]  = { 17.7f, 18.8f, 19.9f, 20.0f};  
    float iniValue5[4]  = { 21.1f, 22.2f, 23.3f, 24.4f};  
    float iniValue6[4]  = { 25.5f, 26.6f, 27.7f, 28.8f};  
    float iniValue7[4]  = { 29.9f, 31.0f, 32.1f, 33.2f}; 
    float iniValue8[4]  = { 34.3f, 35.4f, 36.5f, 37.6f};  
    float iniValue9[4]  = { 38.7f, 39.8f, 40.9f, 42.0f};  
    float iniValue10[4] = { 43.1f, 44.2f, 45.3f, 46.4f};  
    float iniValue11[4] = { 47.5f, 48.6f, 49.7f, 50.8f};  
    float iniValue12[4] = { 51.9f, 53.0f, 54.1f, 55.2f};  
    float iniValue13[4] = { 56.3f, 57.4f, 58.5f, 59.6f};  
    float iniValue14[4] = { 60.7f, 61.8f, 62.9f, 64.0f};  
    float iniValue15[4] = { 65.1f, 66.2f, 67.3f, 68.4f};  

    __asm__ volatile 
    (
        "movaps %8, %%xmm0\n\t"
        "movaps %%xmm0, %0\n\t"
        "movaps %9, %%xmm1\n\t"
        "movaps %%xmm1, %1\n\t"
        "movaps %10, %%xmm2\n\t"
        "movaps %%xmm2, %2\n\t"
        "movaps %11, %%xmm3\n\t"
        "movaps %%xmm3, %3\n\t"
        "movaps %12, %%xmm4\n\t"
        "movaps %%xmm4, %4\n\t"
        "movaps %13, %%xmm5\n\t"
        "movaps %%xmm5, %5\n\t"
        "movaps %14, %%xmm6\n\t"
        "movaps %%xmm6, %6\n\t"
        "movaps %15, %%xmm7\n\t"
        "movaps %%xmm7, %7\n\t"
        : "=m"(xmm0Val),
          "=m"(xmm1Val), 
          "=m"(xmm2Val), 
          "=m"(xmm3Val),
          "=m"(xmm4Val), 
          "=m"(xmm5Val), 
          "=m"(xmm6Val), 
          "=m"(xmm7Val)
        : "m"(iniValue0), 
          "m"(iniValue1),
          "m"(iniValue2),
          "m"(iniValue3),
          "m"(iniValue4),
          "m"(iniValue5),
          "m"(iniValue6),
          "m"(iniValue7)
        : "xmm0",
          "xmm1",
          "xmm2",
          "xmm3",
          "xmm4",
          "xmm5",
          "xmm6",
          "xmm7"
    );

    __asm__ volatile 
    (
        "movaps %8, %%xmm8\n\t"
        "movaps %%xmm8, %0\n\t"
        "movaps %9, %%xmm9\n\t"
        "movaps %%xmm9, %1\n\t"
        "movaps %10, %%xmm10\n\t"
        "movaps %%xmm10, %2\n\t"
        "movaps %11, %%xmm11\n\t"
        "movaps %%xmm11, %3\n\t"
        "movaps %12, %%xmm12\n\t"
        "movaps %%xmm12, %4\n\t"
        "movaps %13, %%xmm13\n\t"
        "movaps %%xmm13, %5\n\t"
        "movaps %14, %%xmm14\n\t"
        "movaps %%xmm14, %6\n\t"
        "movaps %15, %%xmm15\n\t"
        "movaps %%xmm15, %7\n\t"
        : "=m"(xmm8Val),
          "=m"(xmm9Val),
          "=m"(xmm10Val),
          "=m"(xmm11Val),
          "=m"(xmm12Val),
          "=m"(xmm13Val),
          "=m"(xmm14Val),
          "=m"(xmm15Val)
        : "m"(iniValue8),
          "m"(iniValue9),
          "m"(iniValue10),
          "m"(iniValue11),
          "m"(iniValue12),
          "m"(iniValue13),
          "m"(iniValue14),
          "m"(iniValue15)
        : "xmm8",
          "xmm9",
          "xmm10",
          "xmm11",
          "xmm12",
          "xmm13", 
          "xmm14",
          "xmm15"
    );
    printf("[+] XMM Value (0-15)\n");
    printf("[XMM0] : %f %f %f %f\n",
        xmm0Val[0],
        xmm0Val[1],
        xmm0Val[2],
        xmm0Val[3]);
    printf("[XMM1] : %f %f %f %f\n",
        xmm1Val[0],
        xmm1Val[1],
        xmm1Val[2],
        xmm1Val[3]);
    printf("[XMM2] : %f %f %f %f\n",
        xmm2Val[0],
        xmm2Val[1],
        xmm2Val[2],
        xmm2Val[3]);
    printf("[XMM3] : %f %f %f %f\n",
        xmm3Val[0],
        xmm3Val[1],
        xmm3Val[2],
        xmm3Val[3]);
    printf("[XMM4] : %f %f %f %f\n",
        xmm4Val[0],
        xmm4Val[1],
        xmm4Val[2], 
        xmm4Val[3]);
    printf("[XMM5] : %f %f %f %f\n",
        xmm5Val[0],
        xmm5Val[1],
        xmm5Val[2],
        xmm5Val[3]);
    printf("[XMM6] : %f %f %f %f\n",
        xmm6Val[0],
        xmm6Val[1],
        xmm6Val[2],
        xmm6Val[3]); 
    printf("[XMM7] : %f %f %f %f\n",
        xmm7Val[0],
        xmm7Val[1],
        xmm7Val[2], 
        xmm7Val[3]);
    printf("[XMM8] : %f %f %f %f\n",
        xmm8Val[0],
        xmm8Val[1],
        xmm8Val[2],
        xmm8Val[3]);
    printf("[XMM9] : %f %f %f %f\n",
        xmm9Val[0],
        xmm9Val[1],
        xmm9Val[2],
        xmm9Val[3]);
    printf("[XMM10] : %f %f %f %f\n",
        xmm10Val[0],
        xmm10Val[1],
        xmm10Val[2],
        xmm10Val[3]);
    printf("[XMM11] : %f %f %f %f\n",
        xmm11Val[0],
        xmm11Val[1],
        xmm11Val[2],
        xmm11Val[3]);     
    printf("[XMM12] : %f %f %f %f\n",
        xmm12Val[0],
        xmm12Val[1],
        xmm12Val[2],
        xmm12Val[3]);   
    printf("[XMM13] : %f %f %f %f\n",
        xmm13Val[0],
        xmm13Val[1],
        xmm13Val[2],
        xmm13Val[3]);   
    printf("[XMM14] : %f %f %f %f\n",
        xmm14Val[0],
        xmm14Val[1],
        xmm14Val[2],
        xmm14Val[3]);      
   printf("[XMM15] : %f %f %f %f\n",
        xmm15Val[0],
        xmm15Val[1],
        xmm15Val[2],
        xmm15Val[3]);   
    printf("\e[1;35m------------------------------- [Segment Register] -------------------------------\n");
    
   uint16_t csV, dsV, ssV, esV, fsV, gsV;
    __asm__ volatile 
    (
        "mov %%cs, %%ax\n\t"
        "mov %%ax, %[csValue]\n\t"
        "mov %%ds, %%ax\n\t"
        "mov %%ax, %[dsValue]\n\t"
        "mov %%ss, %%ax\n\t"
        "mov %%ax, %[ssValue]\n\t"
        "mov %%es, %%ax\n\t"
        "mov %%ax, %[esValue]\n\t"
        "mov %%fs, %%ax\n\t"
        "mov %%ax, %[fsValue]\n\t"
        "mov %%gs, %%ax\n\t"
        "mov %%ax, %[gsValue]\n\t"
        : [csValue] "=m" (csV),
          [dsValue] "=m" (dsV),
          [ssValue] "=m" (ssV),
          [esValue] "=m" (esV),
          [fsValue] "=m" (fsV),
          [gsValue] "=m" (gsV)
        :
        : "ax"
    );

    printf("\e[1;34m[CS] : 0x%04x\e[0m  -> Code Segment Register, contains the segment selector for code.\n",
        csV);
    printf("\e[1;34m[DS] : 0x%04x\e[0m  -> Data Segment Register, used to access general data.\n",
        dsV);
    printf("\e[1;34m[SS] : 0x%04x\e[0m  -> Stack Segment Register, dedicated to the stack.\n",
        ssV);
    printf("\e[1;34m[ES] : 0x%04x\e[0m  -> Extra Segment Register, used for additional purposes.\n",
        esV);
    printf("\e[1;34m[FS] : 0x%04x\e[0m  -> FS Segment Register, often used for thread-specific data.\n",
        fsV);
    printf("\e[1;34m[GS] : 0x%04x\e[0m  -> GS Segment Register, similar to FS, for special purposes.\n",
        gsV);
    
}

int main(int argc,
    const char **argv)
{
    printf(
    "\e[1;31m"
    "\t\t\t\t\t\t\t┳┓          ┏┓       \n"     
    "\t\t\t\t\t\t\t┣┫┏┓┏┓┏┓┏┓┏┓┗┓┏┓┏┓┏┓ \n"
    "\t\t\t\t\t\t\t┛┗┗ ┗┻┣┛┗ ┛ ┗┛┛┗┗┻┣┛ \n"
    "    \t\t\t\t\t\t\t      ┛           ┛  \n"
    "\e[1;31m\t\t\t\t\t\t\t    [Byte Reaper]\n" 
    "\t\t\t\t\t\t       [Inline Assembly Debugging]\n"
    );
    printf("\e[1;31m\n-------------------------------------------------------------------------------------------------------------------------------------\n");
    reaperSnap("[+] Debug Start...\n");
    __asm__ volatile
    (
        "nop\n\t"
    );
    reaperSnap("[+] After assembly block");
    printf("\e[1;31m\n-------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("\e[1;37m We meet again...\n");
    return 0;

}