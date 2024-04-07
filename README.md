# GhostInjector

proof of concept dll injector which injects without a process handle, and with a thread handle instead. 
with the power of Get/SetThreadContext, and some gadgets, you are able to call functions and write to another process


https://github.com/li4321/GhostInjector/assets/148918162/3081eb05-40fb-4c04-83c0-fd327c8cedd0


(!! there is a really weird problem in the program which I do not know how to fix, sometimes it works, sometimes it crashes)
(for some reason, if you place a breakpoint at line 176 in ghostwrite.cpp, and then remove it and continue once hit, the problem will not occur)
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
