#include <iostream>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <assert.h>
#include <functional>
#include "ntapi.h"

#pragma once

std::vector<uint8_t> FileToBytes(std::string path);

uint32_t FindPidByName(std::wstring name);
std::vector<uint32_t> ListProcessThreads(uint32_t pid);

PEB* GetPeb();
uint8_t* GetLoadedModule(std::wstring name);


struct PeHeader {
	uint8_t* image;

	IMAGE_DOS_HEADER* dosHdr;
	IMAGE_NT_HEADERS* ntHdr;
	std::vector<IMAGE_SECTION_HEADER*> sectHdrs;
	
	IMAGE_DATA_DIRECTORY* dataDir;

	PeHeader(uint8_t* _image) {
		image = _image;
		dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
		ntHdr = reinterpret_cast<IMAGE_NT_HEADERS*>(image + dosHdr->e_lfanew);
		
		IMAGE_SECTION_HEADER* curr = IMAGE_FIRST_SECTION(ntHdr);
		for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
			sectHdrs.push_back(curr);
			curr++;
		}

		dataDir = ntHdr->OptionalHeader.DataDirectory;
	}

	uint32_t RVAToFileOffset(uint32_t rva);

	template<typename T>
	T RVAToPtr(uint32_t rva) {
		return reinterpret_cast<T>(image + RVAToFileOffset(rva));
	}
};

struct BaseRelocEntry {
	uint16_t offset : 12;
	uint16_t type : 4;
};

void FindSection(uint8_t* image, std::string sectName, uint32_t requiredFlags, uint8_t** out_start, uint8_t** out_end);

uint8_t* PatternScan(uint8_t* startAddr, uint8_t* endAddr, std::vector<uint8_t> pattern, std::string mask);
uint8_t* PatternScanSect(uint8_t* image, std::string sectName, std::vector<uint8_t> pattern, std::string mask);
