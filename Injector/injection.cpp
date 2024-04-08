#include "injection.h"

bool InjectDll(std::vector<uint8_t> fileData, uint32_t pid) {

	//
	// initialize pe headers
	//

	PeHeader peHdr(fileData.data());

	//
	// allocate remote buffer
	//

	GhostWrite gw;
	gw.Init(pid);
	uintptr_t remoteMem = gw.Allocate(peHdr.ntHdr->OptionalHeader.SizeOfImage);


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
	// map into memory, (exclude pe headers)
	//
	
	for (auto sectHdr : peHdr.sectHdrs) {
		uint8_t*  sectStart = fileData.data() + sectHdr->PointerToRawData;
		uintptr_t remoteSect = remoteMem + sectHdr->VirtualAddress;
	
		std::printf("mapping section, name: %.8s, size: %d, ---> 0x%llx\n", sectHdr->Name, sectHdr->SizeOfRawData, remoteSect);
		gw.WriteMemory(remoteSect, std::vector<uint8_t>(sectStart, sectStart + sectHdr->SizeOfRawData));
	}
	
	//
	// set protections
	//

	for (auto sectHdr : peHdr.sectHdrs) {
		uintptr_t remoteSect = remoteMem + sectHdr->VirtualAddress;

		uint32_t characteristics = sectHdr->Characteristics;
		uint32_t prot = 0;
		std::string protStr = "";

		if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
			prot = PAGE_EXECUTE;
			protStr = "X";
			if (characteristics & IMAGE_SCN_MEM_READ) {
				prot = PAGE_EXECUTE_READ;
				protStr = "RX";
			}
			if (characteristics & IMAGE_SCN_MEM_WRITE) {
				prot = PAGE_EXECUTE_WRITECOPY;
				protStr = "WCX";
			}
			if ((characteristics & IMAGE_SCN_MEM_READ) && (characteristics & IMAGE_SCN_MEM_WRITE)) {
				prot = PAGE_EXECUTE_READWRITE;
				protStr = "RWX";
			}
		}
		else {
			if (characteristics & IMAGE_SCN_MEM_READ) {
				prot = PAGE_READONLY;
				protStr = "RO";
			}
			if (characteristics & IMAGE_SCN_MEM_WRITE) {
				prot = PAGE_WRITECOPY;
				protStr = "WC";
			}
			if ((characteristics & IMAGE_SCN_MEM_READ) && (characteristics & IMAGE_SCN_MEM_WRITE)) {
				prot = PAGE_READWRITE;
				protStr = "RW";
			}
		}

		std::printf("triggering NtProtectVirtualMemory (RW-->%s)\n", protStr.c_str());
		gw.Protect(remoteSect, sectHdr->SizeOfRawData, prot);
	}

	//
	// execute
	//

	uint64_t remoteEntry = remoteMem + peHdr.ntHdr->OptionalHeader.AddressOfEntryPoint;

	std::printf("triggering dll entrypoint : 0x%llx\n", remoteEntry);
	gw.TriggerFunction(reinterpret_cast<void*>(remoteEntry), { remoteMem, DLL_PROCESS_ATTACH, 0 });
}
