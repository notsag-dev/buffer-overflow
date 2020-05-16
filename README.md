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
  char buffer[200];
  strcpy(buffer, argv[1]);
  return 0;
}
```

This program is vulnerable because the function `strcpy` is memory unsafe: if the argument's length is greater than 200 it will overwrite the contiguous memory addresses. Does it sound familiar already? 😏 Let's move on.

First, compile the program:
```bash
gcc -g bufferOverflow.c
```
Note -g is a debug flag that will generate debug info to be used with the GDB debugger, we'll come back to this

## Resources
https://www.youtube.com/watch?v=1S0aBV-Waeo
