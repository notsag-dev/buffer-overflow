# Buffer overflow
From [OWASP](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow):
> A buffer overflow condition exists when a program attempts to put more data in a buffer than it can hold or when a program > attempts to put data in a memory area past a buffer. In this case, a buffer is a sequential section of memory allocated to contain anything from a character string to an array of integers. Writing outside the bounds of a block of allocated memory can corrupt data, crash the program, or cause the execution of malicious code.

## Process memory sections
```
 High memory addresses
 ______________________
|                      |    
| Kernel               |
|______________________|
|                      | Used for function calls, passing parameters, storing local variables. 
| Stack                | Quite limited space.
|______________________|
|                      |
|                      | Allocates bigger chunks of data.
| Heap                 | 
|                      |
|______________________|
|                      |
| Global variables     |
|______________________|
|                      | 
| Code of the program. |
|______________________|

Low memory addresses
```

## Stack
The stack, also known as the call stack, is a data structure located in the RAM memory that allows procedures and function to call each other and also to stores their local variables.

Let's say a function F1 calls the function F2, and the function F2 calls the function F3. Also, each function i defines a local variable VFi. Let's see what the stack would look like for each 

// TODO FINISH EXAMPLE

## Example of 


## Resources
https://www.youtube.com/watch?v=1S0aBV-Waeo
