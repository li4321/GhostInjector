#include "injection.h"

bool InjectDll(std::vector<uint8_t> fileData, uint32_t pid) {
	PeHeader peHdr(fileData.data());

	uint64_t imgSize = peHdr.ntHdr->OptionalHeader.SizeOfImage;
	uint64_t hdrSize = peHdr.ntHdr->OptionalHeader.SizeOfHeaders;

	//
	// allocate remote buffer
	//

	GhostWrite gw;
	gw.Init(pid);
	uintptr_t remoteMem = gw.Allocate(imgSize - hdrSize);


	//
	// fix base reloc
	//
	
	std::printf("resolving base relocs...\n");
	auto baseReloc = peHdr.RVAToPtr<IMAGE_BASE_RELOCATION*>(peHdr.dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	uint64_t delta = (remoteMem - peHdr.ntHdr->OptionalHeader.ImageBase);

	while (baseReloc->SizeOfBlock) {
		if (baseReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
			int count = (baseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(uint16_t));
			BaseRelocEntry* entries = reinterpret_cast<BaseRelocEntry*>(baseReloc + 1);

			for (int i = 0; i < count; i++) {
				auto& entry = entries[i];
				assert(entry.type == IMAGE_REL_BASED_DIR64);

				uint64_t* ptr = peHdr.RVAToPtr<uint64_t*>(baseReloc->VirtualAddress + entry.offset);
				*ptr += delta;
			}
		}
		baseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(baseReloc) + baseReloc->SizeOfBlock);
	}
	std::printf("base relocs resolved\n");

	//
	// fix imports
	//

	std::printf("resolving imports ..\n");

	auto importDesc = peHdr.RVAToPtr<IMAGE_IMPORT_DESCRIPTOR*>(peHdr.dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (importDesc->Characteristics) {
		std::string libName = std::string(peHdr.RVAToPtr<char*>(importDesc->Name));

		HMODULE hModule = LoadLibraryA(libName.c_str());
		if (!hModule) return false;

		gw.LoadLib(libName); // load library in remote process

		auto origFirstThunk = peHdr.RVAToPtr<IMAGE_THUNK_DATA*>(importDesc->OriginalFirstThunk);
		auto firstThunk     = peHdr.RVAToPtr<IMAGE_THUNK_DATA*>(importDesc->FirstThunk);

		while (origFirstThunk->u1.AddressOfData) {
			void* func = 0;
			char* impName = nullptr;

			if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				impName = reinterpret_cast<char*>(origFirstThunk->u1.Ordinal & 0xFFFF);
			else
				impName = (peHdr.RVAToPtr<IMAGE_IMPORT_BY_NAME*>(origFirstThunk->u1.AddressOfData))->Name;

			if (!(func = GetProcAddress(hModule, impName)))
				return false;
			
			firstThunk->u1.Function = reinterpret_cast<uintptr_t>(func);

			origFirstThunk++;
			firstThunk++;
		}
		importDesc++;
	}
	std::printf("imports resolved\n");

	//
	// map into memory
	//
	
	for (auto sectHdr : peHdr.sectHdrs) {
		uintptr_t writeAddr = remoteMem + sectHdr->VirtualAddress - hdrSize;
		uint8_t* sectStart = fileData.data() + sectHdr->PointerToRawData;
	
		std::printf("mapping section, name: %.8s, size: %d, ---> 0x%llx\n", sectHdr->Name, sectHdr->SizeOfRawData, writeAddr);
		gw.WriteMemory(writeAddr, std::vector<uint8_t>(sectStart, sectStart + sectHdr->SizeOfRawData));
	}
	
	uintptr_t remoteEntry = remoteMem + peHdr.ntHdr->OptionalHeader.AddressOfEntryPoint - hdrSize;

	//
	// execute
	//
	
	std::printf("triggering dll entrypoint : 0x%llx\n", remoteEntry);
	gw.TriggerFunction(reinterpret_cast<void*>(remoteEntry), { remoteMem, DLL_PROCESS_ATTACH, 0 });
}