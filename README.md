# buffer-overflow
From [OWASP](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow):
> A buffer overflow condition exists when a program attempts to put more data in a buffer than it can hold or when a program > attempts to put data in a memory area past a buffer. In this case, a buffer is a sequential section of memory allocated to contain anything from a character string to an array of integers. Writing outside the bounds of a block of allocated memory can corrupt data, crash the program, or cause the execution of malicious code.

## Process memory sections
```
 High memory addresses
 ______________________
|                      |    
| Kernel               |
|______________________|
|                      |
| Stack                |
|______________________|
|                      |
|                      |
| Heap                 | 
|                      |
|______________________|
|                      |
| Code of the program. |
|______________________|
|                      | 
| Code of the program. |
|______________________|

Low memory addresses
```

## Example of 
