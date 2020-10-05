Title: Midnight Sun CTF finals 2020 - autorev writeup 
Date: 2020-10-05 18:48
Modified: 2020-10-05 18:48
Category: blog
Tags: ctf,  infosec
Slug: msunctf_autorev
Authors: Wim van der Schoot
Summary: A writeup for the autorev ctf challenge at Midnight Sun CTF finals 2020.

(i apologise for the horrible markdown code formatting here - working on changing this)

This challenge involved 'auto' reverse engineering 10 programs within a time limit.

Connecting to the challenge via netcat presented the user with the goal:
```
Please reverse 10 programs before I give you the flag
Here is a base64-encoded program for you:
f0VMR..........
You have 10 seconds provide something to pass in to the program as standard input:

Too slow!
Better luck next time
```

After taking the base64-encode program, decoding it and decompiling it with Ghidra, we find the required input is a 64 bit value in the testfunc() program - 
Ghidra simplifies this program, displaying the required parameter.

This is the ghidra decompiled code, showing the main function calling 'testfunc' which checks the input against a 64 bit value.
```c
undefined8 main(void){
  int iVar1;
  undefined8 uVar2;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  uVar2 = get_input();
  iVar1 = testfunc(uVar2);
  if (iVar1 == 1) {
    puts("You did it!");
  }
  else {
    puts("You failed!");
  }
  return 0;
}

...

ulong testfunc(long param_1){
  return (ulong)(param_1 == -0x67b869127d9430b0);
}
```

The assembly reveals the input value is taken, placed in RDI, then XORd and ADDd with a number of 64 bit constants before being compared with a final constant (final_c). Running this challenge a number of times reveals the constants change each time along with the order and amount of XORs and ADDs, and sometimes there is a MOV instruction for RDI to another register before operations are performed on it.

```nasm
undefined testfunc()
  AL:1           <RETURN>
testfunc

ENDBR64
MOV        RAX,0x75af4a9b7ff5a731
ADD        RAX,RDI                 # RDI contains input val
MOV        RDI,-0x21459817860ff2ef
XOR        RAX,RDI
MOV        RDI,-0x7cb8ac47d2e3ea58
ADD        RAX,RDI
MOV        RDI,-0x4a273b94adf2a5a

...

XOR        RAX,RDX
MOV        RDX,0x23a2f8516a4db1c2
ADD        RAX,RDX
MOV        RDX,0x4abcc94853830566
XOR        RAX,RDX
MOV        RDX,0x23292d5bc7a6048b  # final_c
CMP        RAX,RDX
SETZ       AL
MOVZX      EAX,AL
RET
```

This leaves an algorithm along the lines of:
> final_c = (((((((x+a)^b)+c)^d)+e)^f)+....)

We want to find x and are given all the other constants, to reverse we can do:
>x = ((((((final_c .....)^f)-e)^d)-c)^b-a)


To do this we have to decode and parse the base64 encoded elf, finding the constants and operations, our solution is pretty basic but does the job with the help of pwntools. We first jump to the function 'testfunc', then find the constants by checking the opcodes and then jumping from one constant to the next adding to a list, this list we then reverse and invert the operations to find x.
```python
# Solution
from pwn import *
import numpy as np

# algo in program is:
# n = (((((((x+a)^b)+c)^d)+e)^f)+....)
# we're given program that has constants a,b,c,....n, goal is to find x

# alternate between xor and minus to reverse algo
for i in range(len(const_list)):
    c = const_list[i][0]
    op = const_list[i][1]
    if op == 'xor':
        x = x ^ c
    else:
        x = x - c
return x

# find the constants and operations in the elf file
def parseElf(elfPath):
    e = elf.elf.ELF(elfPath)
    baseaddr = e.functions['testfunc'].address # test func contains algo
    addr = baseaddr
    addr += 4
    constantList = []
    inst = e.read(addr,3)
    if ( (inst[0] == 72) and (inst[1] == 49 or inst[1] == 1 or inst[1] == 137) and (inst[2] == 208 or inst[2] == 248)): # check opcodes
        addr += 3 # skip if mov instr

    while True:
        addr += 2
        constantI = int.from_bytes(e.read(addr,8), "little", signed=True)
        addr += 8

        inst = e.read(addr,3)
        if (inst[0] == 72 and inst[1] == 49 and (inst[2] == 208 or inst[2] == 248) ): #xor
            op = 'xor'

        elif (inst[0] == 72 and inst[1] == 1 and (inst[2] == 248 or inst[2] == 208)): #add
            op = 'add'

        elif (inst[0] == 72 and inst[1] == 137 and inst[2] == 248): #mov
            op = 'mov'
        else:
            constantList.append((constantI,'end'))
            break
        addr += 3 # skip ADD/XOR

        constantList.append((constantI, op))
    return constantList

# Connect and solve!
r = remote('<challenge_url>', 10000)
r.recvline() # 'Please reverse 10 programs before I give you the flag...'
while r.connected:
    print(r.recvline()) # 'Here is a base64-encoded..'
    base64prg  = r.recvlineS()
    print(r.recvlineS()) # 'You have 10 seconds to provide something to pass in..'
    prg = util.fiddling.b64d(base64prg)
    f = open('sdf','wb')
    f.write(prg)
    constantList = parseElf('sdf')
    x = x_is(constantList) # find password
    r.sendline(str(x)) # send password
    print("x is: " +str(x))
    for i in range(5):
        print(r.recvline())
```
