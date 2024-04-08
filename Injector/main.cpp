#include <iostream>
#include "injection.h"

int main() {
	uint32_t pid = FindPidByName(L"TestApp.exe");
	std::printf("TestApp.exe process ID: %d\n", pid);
	
	std::printf("enter dll path: ");
	std::string dllPath = "";
	std::cin >> dllPath;

	InjectDll(FileToBytes(dllPath), pid);
	
	system("pause");
}
