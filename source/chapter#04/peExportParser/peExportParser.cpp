#include <iostream>
#include <windows.h>
#pragma warning(disable : 4996)
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

BOOL ReadBinFile(const char* fileName, char*& buffer, DWORD& size)
{
	// Open file
	FILE* fp = nullptr;
	if (fopen_s(&fp, fileName, "rb"))
	{
		return false;
	}
	else
	{
		// Get the size of the binary file
		fseek(fp, 0, SEEK_END);
		size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		// Get the content of the binary file
		buffer = new char[size];
		if (buffer == nullptr)
		{
			fclose(fp);
			return false;
		}
		fread(buffer, sizeof(char), size, fp);

		// finalization
		fclose(fp);
		return true;
	}
}

size_t RvaToOffset(char* ExeData, size_t RVA)
{
	for (size_t i = 0; i < getNtHdr(ExeData)->FileHeader.NumberOfSections; i++)
	{
		auto CurrSection = getSectionArr(ExeData)[i];
		if (RVA >= CurrSection.VirtualAddress &&
			RVA <= CurrSection.VirtualAddress + CurrSection.Misc.VirtualSize)
			return CurrSection.PointerToRawData + (RVA - CurrSection.VirtualAddress);
	}
	return 0;
}


void ExportParser(char* filename)
{
	char* Buffer;
	DWORD Size;

	if (ReadBinFile(filename, Buffer, Size))
	{
		// Lookup RVA of PIMAGE_EXPORT_DIRECTORY (from DataDirectory)
		IMAGE_OPTIONAL_HEADER optHdr = getNtHdr(Buffer)->OptionalHeader;
		IMAGE_DATA_DIRECTORY dataDir_exportDir = optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		size_t offset_exportDir = RvaToOffset(Buffer, dataDir_exportDir.VirtualAddress);

		// Parse IMAGE_EXPORT_DIRECTORY struct
		PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(Buffer + offset_exportDir);
		printf("[+] Detect module : %s\n", Buffer + RvaToOffset(Buffer, exportTable->Name));

		// Enumerate Exported Functions
		printf("[+] List exported functions (total %i api):\n", exportTable->NumberOfNames);
		uint32_t* arr_rvaOfFunctions = (uint32_t*)(Buffer + RvaToOffset(Buffer, exportTable->AddressOfFunctions));
		uint32_t* arr_rvaOfNames = (uint32_t*)(Buffer + RvaToOffset(Buffer, exportTable->AddressOfNames));
		uint16_t* arr_rvaOfNameOrdinals = (uint16_t*)(Buffer + RvaToOffset(Buffer, exportTable->AddressOfNameOrdinals));
		for (size_t i = 0; i < exportTable->NumberOfNames; i++)
		{
			// list all rvaOfFunctions, rvaOfNames, rvaOfNameOrdinals
			printf("\t#%.2x: %s\n", i, Buffer + RvaToOffset(Buffer, arr_rvaOfNames[i]));
			printf("\t\t- AddressOfNames: %p\n", arr_rvaOfNames[i]);
			printf("\t\t- AddressOfFunctions: %p\n", arr_rvaOfFunctions[i]);
			printf("\t\t- AddressOfNameOrdinals: %p\n", arr_rvaOfNameOrdinals[i]);
		}
	}
	else
		puts("[!] dll file not found.");
}

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		puts("[!] Usage: .\\PEExportParser.exe [path\\to\\dll]\n");
	}
	else
	{
		ExportParser(argv[1]);
	}
	
	return 0;
}