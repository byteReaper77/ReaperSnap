
![Reaper Image](reaper.png)

# reaperSnap

**Author:** Byte Reaper
**Contact:** [Telegram @ByteReaper0](https://t.me/ByteReaper0)
**License:** MIT

---

## Description

`reaperSnap` is a single-function, inline-assembly debugging helper for x86\_64 Linux. By calling `reaperSnap("<label>")` before and after an inline assembly block, it captures a detailed snapshot of the process environment and CPU state, including:

* **Process Info**: PID, TID, running CPU, NUMA node
* **Kernel/OS Info**: kernel release, version, machine
* **Memory Ranges**: stack and heap addresses from `/proc/self/maps`
* **Auxiliary Vector**: AT\_PAGESZ, AT\_HWCAP, AT\_BASE, AT\_UID/EUID/GID/EGID, AT\_CLKTCK, AT\_EXECFN
* **General-Purpose Registers**: RAX, RBX, RCX, RDX, RSP, RBP, RIP, RFLAGS (hex and binary), with flag decoding (CF, PF, ZF, SF, TF, OF)
* **SIMD Registers**: XMM0–XMM15 and YMM0–YMM7 results for equality test
* **CPUID Information**:

  * Vendor string
  * Family, model, stepping, processor type
  * L2 cache line size, associativity, capacity
  * Extended topology (leaf 0x0B) for SMT and core levels
  * Processor brand string (leaf 0x80000002–4)
* **Segment Registers**: CS, DS, SS, ES, FS, GS

All output is printed with ANSI color codes and formatted tables for readability.

---

## Installation

Compile with GCC on x86\_64 Linux:


gcc  -o reaperSnap reaperSnap.c -mavx2


No external dependencies are required.

---

## Usage

In your C program, include or declare `reaperSnap` and invoke it as follows:

```c
#include <stdio.h>
void reaperSnap(const char *label);

int main() {
    printf("Starting debug...\n");
    reaperSnap("[Before ASM]");

    __asm__ volatile (
        "nop\n\t"
    );

    reaperSnap("[After ASM]");
    return 0;
}
```

Alternatively, run the compiled binary directly to see a built-in demo:


./reaperSnap


---

## Example Output

```
┳┓          ┏┓
┣┫┏┓┏┓┏┓┏┓┏┓┗┓┏┓┏┓┏┓
┛┗┗ ┗┻┣┛┗ ┛ ┗┛┛┗┗┻┣┛
      ┛           ┛
    [Byte Reaper]
   [Inline Assembly Debugging]

[+] System information :
[PID] : 1234
[TID] : 1234
[RUNNING CPU] :  2
[NUMA NODE]  : 0
[release]  : 6.12.25-amd64
[version]  : #1 SMP PREEMPT_DYNAMIC ...
[OS] :  x86_64
[+] Stack Range: 0x... - 0x...
[+] Heap Range: 0x... - 0x...
[+] Page size: 4096 bytes
[+] Hardware capabilities: 0x2
[+] Base address of interpreter: 0x...
[+] UID : 1000, EUID: 1000
[+] GID : 1000, EGID: 1000
...
[+] INFO CPUID :
[+] Vendor String : GenuineIntel
[+] Family: 6
[+] Model: 78
[+] Stepping: 3
[+] Processor Type: 0
[+] Information L2 Cache :
-> Line Size: 64
-> Associativity: 8-Way
-> Capacity: 256 KB
[+] Extended Topology:
-> Level 0: SMT (logical procs: 2)
-> Level 1: Core (logical procs: 4)
[+] Processor Brand String: Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz
[+] AVX Supported
[+] YMM Result: all elements match
[+] XMM Values printed...
[CS] ...
[DS] ...
...
```

---

## License

MIT
