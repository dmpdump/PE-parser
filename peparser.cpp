//File format reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

#include <windows.h>
#include <stdio.h>
#include <timezoneapi.h>
#include <ctime>
#include <vector>


DWORD RvaToFileOffset(DWORD rva, PIMAGE_NT_HEADERS pNtHeader) {
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader);
	for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, section++) {
		if (rva >= section->VirtualAddress &&
			rva < (section->VirtualAddress + section->Misc.VirtualSize)) {
			return (rva - section->VirtualAddress) + section->PointerToRawData;
		}
	}
	return 0;
}

int wmain(int argc, PWCHAR argv[])
{
	if (argc != 2)
	{
		puts("[x] Incorrect number of parameters.");
		puts("Please provide the executable to parse as a parameter.");
		puts("E.g.: peparser.exe <filename>");
		return 1;
	}

	LPCWSTR lpFName = argv[1];

	PIMAGE_DOS_HEADER pImageDosH = nullptr;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;
	PIMAGE_SECTION_HEADER pImageSectionH = nullptr;

	//Get a handle to the file with createfileW

	HANDLE FileHandle = INVALID_HANDLE_VALUE;
	FileHandle = CreateFileW(
		lpFName,
		GENERIC_READ | READ_ATTRIBUTES,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == 0x2)
		{
			puts("[x] File not found");
			return 1;
		}
		puts("[x] Could not open file");
		return 1;
	}

	//Map the file to the calling process' memory space: CreateFileMapping + MapViewOfFile

	HANDLE hFileMap = CreateFileMapping(
		FileHandle,
		nullptr,
		PAGE_READONLY,
		0,
		0,
		nullptr
	);

	if (hFileMap != NULL)
	{
		puts("Mapped the file to memory successfully...\n");
	}
	else
	{
		printf("[x] Could not map the file to memory:%d\n", GetLastError());
		return 1;
	}

	LPVOID MappedAddress = nullptr;
	MappedAddress = MapViewOfFile(
		hFileMap,
		FILE_MAP_READ,
		NULL,
		NULL,
		NULL
	);

	//Check if file is an executable

	pImageDosH = (PIMAGE_DOS_HEADER)MappedAddress;
	if (IMAGE_DOS_SIGNATURE == pImageDosH->e_magic)
	{
		puts("[+] First 2 bytes are '4D 5A'. The file looks like an executable.\n");
	}
	else
	{
		puts("[x] File does not look like an executable");
		return 1;
	}

	//Print basic attributes
	BY_HANDLE_FILE_INFORMATION FileInfoStruct = { 0 };

	BOOL bFileInfo = GetFileInformationByHandle(
		FileHandle,
		&FileInfoStruct
	);

	SYSTEMTIME systime = { 0 };

	//Print basic data

	printf("Basic information:\n");
	printf("------------------\n\n");

	printf("[+] File Time stamps:\n");
	if (!FileTimeToSystemTime(&FileInfoStruct.ftCreationTime, &systime))
	{
		printf("Could not convert to creation time to system time. Error:%d", GetLastError());
	}
	printf("File creation time: %02d/%02d/%d %02d:%02d:%02d UTC\n", systime.wMonth, systime.wDay, systime.wYear, systime.wHour, systime.wMinute, systime.wSecond);

	if (!FileTimeToSystemTime(&FileInfoStruct.ftLastAccessTime, &systime))
	{
		printf("Could not convert to System Time. Error:%d", GetLastError());
	}
	printf("Last Access time: %02d/%02d/%d %02d:%02d:%02d UTC\n", systime.wMonth, systime.wDay, systime.wYear, systime.wHour, systime.wMinute, systime.wSecond);

	if (!FileTimeToSystemTime(&FileInfoStruct.ftLastWriteTime, &systime))
	{
		printf("Could not convert to System Time. Error:%d", GetLastError());
	}
	printf("Last Write time: %02d/%02d/%d %02d:%02d:%02d UTC\n", systime.wMonth, systime.wDay, systime.wYear, systime.wHour, systime.wMinute, systime.wSecond);

	printf("\n[+] Size:\n");
	printf("File size in bytes:%llu\n", ((ULONGLONG)FileInfoStruct.nFileSizeHigh << 32) | FileInfoStruct.nFileSizeLow);


	//Depending on bitness - define PIMAGE_NT_HEADERS64 or _IMAGE_NT_HEADERS32

#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pImgNT = (PIMAGE_NT_HEADERS64)((LPBYTE)MappedAddress + pImageDosH->e_lfanew);
#else _WIN32
	PIMAGE_NT_HEADERS32 pImgNT = (PIMAGE_NT_HEADERS32)((LPBYTE)MappedAddress + pImageDosH->e_lfanew);
#endif	

	printf("\n[+] Architecture:\n");

	DWORD machine = pImgNT->FileHeader.Machine;
	switch (machine) {
	case IMAGE_FILE_MACHINE_I386:
		printf("Architecture: x86\n");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		printf("Architecture: x64\n");
		break;
	case IMAGE_FILE_MACHINE_ARM:
		printf("Architecture: ARM\n");
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		printf("Architecture: ARM64\n");
		break;
	default:
		printf("Architecture: Unknown\n");
	}

	printf("\n[+] Characteristics:\n");

	WORD characteristics = pImgNT->FileHeader.Characteristics;
	if (characteristics & IMAGE_FILE_DLL)
	{
		printf("File is a DLL (.dll)\n");
	}
	else
	{
		printf("File is an executable (.exe)\n");
	}
	if (characteristics & IMAGE_FILE_DEBUG_STRIPPED)
	{
		printf("Debug information stripped\n");
	}
	else
	{
		printf("Debug information not stripped\n");
	}

	printf("\n[+] Possible compilation time:\n");
	DWORD TimeDateStamp = pImgNT->FileHeader.TimeDateStamp;
	struct tm timeinfo;
	time_t convTime = (time_t)TimeDateStamp;
	gmtime_s(&timeinfo, &convTime);
	char buffer[80];
	strftime(buffer, sizeof(buffer), "%m/%d/%Y %H:%M:%S UTC", &timeinfo);
	printf("Timestamp: %s \n[!] Timestamps are sometimes modified or inaccurate\n", buffer);

	printf("\n[+] Address of Entry Point:\n");
	DWORD AddressOfEntryPoint = pImgNT->OptionalHeader.AddressOfEntryPoint;
	printf("Address of Entry Point: 0x%08X\n", AddressOfEntryPoint);

	printf("\n[+] Address Space Layout Randomization (ASLR):\n");
	WORD DllCharacteristics = pImgNT->OptionalHeader.DllCharacteristics;
	if (DllCharacteristics & 0x0040)
	{
		printf("Dll can be relocated at load time. Compiled with ASLR\n\n");
	}
	else
	{
		printf("Dll cannot be relocated at load time. Not compiled with ASLR\n\n");
	}

	printf("Press enter to parse imports...\n");
	getchar();

	//Parse imports. Mapping the file to memory manually does not apply relocations. 

	printf("\n[+] Imports:\n");
	IMAGE_DATA_DIRECTORY importDirectory = pImgNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDirectory.VirtualAddress == 0) {
		printf("No imports found.\n");
		return 0;
	}

	DWORD importOffset = RvaToFileOffset(importDirectory.VirtualAddress, pImgNT);
	if (importOffset == 0)
	{
		printf("Failed to convert import directory RVA to file offset.\n");
		return 1;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)MappedAddress + importOffset);

	while (importDesc->Name != 0)
	{
		// Convert the DLL name RVA to file offset
		DWORD nameOffset = RvaToFileOffset(importDesc->Name, pImgNT);
		if (nameOffset == 0) {
			importDesc++;
			continue;
		}

		LPCSTR dllName = (LPCSTR)((LPBYTE)MappedAddress + nameOffset);
		printf("\nDLL: %s\n", dllName);

		// Get the import lookup table
		DWORD iltOffset = RvaToFileOffset(importDesc->OriginalFirstThunk ?
			importDesc->OriginalFirstThunk : importDesc->FirstThunk, pImgNT);

		if (iltOffset != 0) {
			PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((LPBYTE)MappedAddress + iltOffset);

			while (thunk->u1.AddressOfData != 0) {
				if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
					// by name
					DWORD importNameOffset = RvaToFileOffset(
						(DWORD)thunk->u1.AddressOfData, pImgNT);
					if (importNameOffset != 0) {
						PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)(
							(LPBYTE)MappedAddress + importNameOffset);
						printf("    %s\n", importName->Name);
					}
				}
				else {
					// by ordinal
					printf("    Ordinal: %d\n",
						(WORD)(thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
				}
				thunk++;
			}
		}
		importDesc++;
	}

	printf("\nPress enter to parse exports...\n");
	getchar();

	printf("\n[+] Exports:\n");

	IMAGE_DATA_DIRECTORY exportDirectory = pImgNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDirectory.VirtualAddress == 0) {
		printf("No imports found.\n");
		return 0;
	}

	DWORD exportOffset = RvaToFileOffset(exportDirectory.VirtualAddress, pImgNT);
	if (exportOffset == 0) {
		printf("Could not convert export directory RVA to file offset.\n");
		return 1;
	}

	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)MappedAddress + exportOffset);

	printf("Export Directory Information:\n");
	printf("  Characteristics: %u\n", exportDir->Characteristics);
	printf("  TimeDateStamp: %u\n", exportDir->TimeDateStamp);
	printf("  MajorVersion: %u\n", exportDir->MajorVersion);
	printf("  MinorVersion: %u\n", exportDir->MinorVersion);

	DWORD nameOffset = RvaToFileOffset(exportDir->Name, pImgNT);
	if (nameOffset != 0) {
		LPCSTR moduleName = (LPCSTR)((BYTE*)MappedAddress + nameOffset);
		printf("  Module Name: %s\n", moduleName);
	}

	DWORD functionsOffset = RvaToFileOffset(exportDir->AddressOfFunctions, pImgNT);
	DWORD namesOffset = RvaToFileOffset(exportDir->AddressOfNames, pImgNT);
	DWORD nameOrdinalsOffset = RvaToFileOffset(exportDir->AddressOfNameOrdinals, pImgNT);

	if (functionsOffset == 0 || namesOffset == 0 || nameOrdinalsOffset == 0) {
		printf("Could not convert export table RVAs to file offsets.\n");
		return 1;
	}

	DWORD* functionAddresses = (DWORD*)((BYTE*)MappedAddress + functionsOffset);
	DWORD* nameAddresses = (DWORD*)((BYTE*)MappedAddress + namesOffset);
	WORD* nameOrdinals = (WORD*)((BYTE*)MappedAddress + nameOrdinalsOffset);

	std::vector<DWORD> namedFunctions;

	printf("\nExported Functions:\n");
	for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
	{
		DWORD nameRva = nameAddresses[i];
		DWORD nameOffset = RvaToFileOffset(nameRva, pImgNT);

		if (nameOffset == 0) continue;

		const char* functionName = (const char*)((BYTE*)MappedAddress + nameOffset);

		WORD ordinal = nameOrdinals[i];
		DWORD functionRva = functionAddresses[ordinal];

		printf("  Named Function %lu:\n", i + 1);
		printf("    Name: %s\n", functionName);
		printf("    Ordinal: %lu\n", ordinal + exportDir->Base);

		namedFunctions.push_back(functionRva);
	}

	printf("\nUnnamed Functions:\n");
	for (DWORD i = 0; i < exportDir->NumberOfFunctions; ++i) {
		DWORD functionRva = functionAddresses[i];

		if (functionRva >= exportDirectory.VirtualAddress &&
			functionRva < (exportDirectory.VirtualAddress + exportDirectory.Size)) {
			DWORD forwardNameOffset = RvaToFileOffset(functionRva, pImgNT);
			const char* forwardName = (const char*)((BYTE*)MappedAddress + forwardNameOffset);
			printf("  Forwarded Function %lu:\n", i);
			printf("    Forwarded to: %s\n", forwardName);
			continue;
		}

		if (std::find(namedFunctions.begin(), namedFunctions.end(), functionRva) != namedFunctions.end()) {
			continue;
		}

		printf("  Unnamed Function %lu:\n", i);
		printf("    Ordinal: %lu\n", i + exportDir->Base);
		printf("    RVA: 0x%08lX\n", functionRva);

		return 0;
	}
}
