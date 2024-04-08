#include <iostream>
#include <windows.h>
#include <string>

#pragma once

#include "utils.h"

#pragma comment(lib, "ntdll.lib")


bool InjectDll(std::vector<uint8_t> fileData, uint32_t pid);


class Thread {
public:
	HANDLE handle = 0;
	bool suspended = false;

	void Suspend() {
		if (!suspended)
			if (SuspendThread(handle) == ERROR_SUCCESS)
				suspended = true;
	}

	void Resume() {
		if (suspended)
			if (ResumeThread(handle) == ERROR_SUCCESS)
				suspended = false;
	}

	void SuspendResume(std::function<void()> func) {
		this->Suspend();
		func();
		this->Resume();
	}

	void GetContext(CONTEXT* ctx, uint32_t flags) {
		ctx->ContextFlags = flags;
		GetThreadContext(handle, ctx);
	}

	void SetContext(CONTEXT* ctx) {
		SetThreadContext(handle, ctx);
	}

	uint32_t GetExitCode() {
		DWORD exitCode = 0;
		GetExitCodeThread(handle, &exitCode);
		return exitCode;
	}
};


class GhostWrite {
public:
	CONTEXT savedCtx = {};
	bool Init(uint32_t pid);

	uintptr_t Allocate(uint64_t size);
	bool Protect(uintptr_t addr, uint64_t size, uint32_t protect);
	void LoadLib(std::string name);
	void WriteMemory(uintptr_t addr, std::vector<uint8_t> data);

	uint64_t TriggerFunction(void* func, std::vector<uint64_t> args);

private:
	void WaitForAutoLock(CONTEXT* ctx);
	void WriteQword(uintptr_t addr, uint64_t value);
	uintptr_t ReadQword(uintptr_t addr);

	uintptr_t Push(CONTEXT* ctx, uint64_t value);
	void Pop(CONTEXT* ctx);

	Thread thread = {};
	uintptr_t writeGadgetAddr = 0;
	uintptr_t readGadgetAddr = 0;
	uintptr_t jmp0GadgetAddr = 0;
	uintptr_t jmp0StackAddr = 0;
};
