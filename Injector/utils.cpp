#include "utils.h"
#include <fstream>


std::vector<uint8_t> FileToBytes(std::string path) {
	std::ifstream file(path, std::ios::binary);

	if (!file.is_open())
		return {};

	return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

uint32_t FindPidByName(std::wstring name) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(PROCESSENTRY32);

	uint32_t pid = 0;

	if (Process32First(hSnapshot, &procEntry)) {
		do {
			if (std::wstring(procEntry.szExeFile) == name) {
				pid = procEntry.th32ProcessID;
				CloseHandle(hSnapshot);
				break;
			}
		} while (Process32Next(hSnapshot, &procEntry));
	}

	return pid;
}


std::vector<uint32_t> ListProcessThreads(uint32_t pid) {
	std::vector<uint32_t> tids = {};

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return {};

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == pid) {
				tids.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &threadEntry));
	}

	CloseHandle(hSnapshot);
	return tids;
}


PEB* GetPeb() {
	return reinterpret_cast<PEB*>(__readgsqword(0x60));
}


uint8_t* GetLoadedModule(std::wstring name) {
	PEB* peb = GetPeb();

	LIST_ENTRY* head = peb->Ldr->InMemoryOrderModuleList.Flink;
	LIST_ENTRY* curr = head;

	for (int count = 0;; count++) {
		if (count && curr == head)
			break;

		auto entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(reinterpret_cast<uint8_t*>(curr) - sizeof(LIST_ENTRY));

		if (entry->BaseDllName.Buffer) {
			if (std::wstring(entry->BaseDllName.Buffer) == name)
				return reinterpret_cast<uint8_t*>(entry->DllBase);
		}
		curr = curr->Flink;
	}
	return nullptr;
}



uint32_t PeHeader::RVAToFileOffset(uint32_t rva) {
	for (auto sectHdr : sectHdrs) {
		uint32_t sectSize = sectHdr->Misc.VirtualSize ? sectHdr->Misc.VirtualSize : sectHdr->SizeOfRawData;

		if (rva >= sectHdr->VirtualAddress && rva <= sectHdr->VirtualAddress + sectSize)
			return rva - sectHdr->VirtualAddress + sectHdr->PointerToRawData;
	}
	return 0;
}

void FindSection(uint8_t* image, std::string sectName, uint32_t requiredFlags, uint8_t** out_start, uint8_t** out_end) {
	PeHeader peHeader(image);
	for (auto sectHdr : peHeader.sectHdrs) {
		uint8_t* start = image + sectHdr->VirtualAddress;
		uint8_t* end = start + sectHdr->Misc.VirtualSize;

		if ((requiredFlags == NULL || sectHdr->Characteristics & requiredFlags)
			&& (sectName.empty() || !memcmp(sectHdr->Name, sectName.c_str(), sizeof(sectHdr->Name)))) {
			*out_start = start;
			*out_end = end;
			return;
		}
	}
}


uint8_t* PatternScan(uint8_t* startAddr, uint8_t* endAddr, std::vector<uint8_t> pattern, std::string mask) {
	for (uint8_t* addr = startAddr; addr < (endAddr - mask.size()); addr++) {
		bool found = true;
		for (int i = 0; i < mask.size(); i++) {
			if (mask[i] != '?' && addr[i] != pattern[i]) {
				found = false;
				break;
			}
		}
		if (found) return addr;
	}

	return nullptr;
}

uint8_t* PatternScanSect(uint8_t* image, std::string sectName, std::vector<uint8_t> pattern, std::string mask) {
	uint8_t* start = 0;
	uint8_t* end = 0;

	FindSection(image, sectName, NULL, &start, &end);
	
	if (!start || !end)
		return nullptr;

	return PatternScan(start, end, pattern, mask);
}

