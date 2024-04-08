# GhostInjector

proof of concept dll injector which injects without a process handle, and with a thread handle instead. 
with the power of Get/SetThreadContext, and some gadgets, you are able to call functions and write to another process

with the thread context, you can set rax to the value to be written, and rdx to where to write to
and rip to the address of this gadget
```
mov qword ptr [rdx], rax
ret
```
and with the return address/rsp set to this gadget, which is basically a infinite loop
```
jmp 0
```
now 8 bytes of data has been written to the other process

so now you just spam this to write large ammounts of data, and use it to push data to the stack for triggering functions

https://github.com/li4321/GhostInjector/assets/148918162/b72a7d99-3fa8-4d21-8c01-0149425a5865


(!! there is a really weird problem in the program which I do not know how to fix, sometimes it works, sometimes it crashes)
(for some reason, if you place a breakpoint at WriteQword in ghostwrite.cpp, and then remove it and continue once hit, the problem will not occur)
```c++
	// mov qword ptr [rdx], rax
	// ret
	ctx.Rdx = addr;
	ctx.Rax = value;
	ctx.Rip = writeGadgetAddr;		// <-- place breakpoint here
	ctx.Rsp = jmp0StackAddr; // jmp 0 --> infinite loop
```


resources which made this possible:
https://github.com/c0de90e7/GhostWriting/blob/master/gw_ng.c
https://blog.sevagas.com/IMG/pdf/code_injection_series_part5.pdf
