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
  char buffer[20];
  strcpy(buffer, argv[1]);
  return 0;
}
```

This program is vulnerable because the function `strcpy` is memory unsafe: if the argument's length is greater than 20 it will overwrite the contiguous memory addresses. Does it sound familiar already? 😏 Let's move on.

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

## Resources
https://www.youtube.com/watch?v=1S0aBV-Waeo
