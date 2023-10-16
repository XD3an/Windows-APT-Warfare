#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)
#define file_align 0x200
#define sect_align 0x1000

#define P2ALIGNUP(size, align) ((((size) / align) + 1) * (align))

char shellcode[] =
"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
"\x52\xff\xd0";

int main() {

	// prepare buffer to output PE binary
	size_t peHeaderSize = P2ALIGNUP(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER), file_align);
	size_t sectionDataSize = P2ALIGNUP(sizeof(shellcode), file_align);
	char* peData = (char*)calloc(peHeaderSize + sectionDataSize, 1);

	// DOS Header
	/*
		e_magic: MZ\x00\x00
		e_lfanew: sizeof(IMAGE_DOS_HEADER);
	*/
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)peData;
	dosHdr->e_magic = IMAGE_DOS_SIGNATURE; // MZ
	dosHdr->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	// NT Header
	/*
		Signature: PE\x000\x00

		File Header
			Machine: IMAGE_FILE_MACHINE_I386
			Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE、IMAGE_FILE_32BIT_MACHINE
			SizeOfOptionalHeader: sizeof(IMAGE_OPTIONAL_HEADER)
			NumberOfSections: 1 // for shellcode section
	*/
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(peData + dosHdr->e_lfanew);
	ntHdr->Signature = IMAGE_NT_SIGNATURE; // PE
	ntHdr->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	ntHdr->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
	ntHdr->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	ntHdr->FileHeader.NumberOfSections = 1;

	// Section Header
	/*
		VirtualAddress: 0x1000
		SizeOfRawData: sizeof(shellcode)
		PointerToRawData: PE Header size
		Characteristics:
			IMAGE_SCN_MEM_EXECUTE
			IMAGE_SCN_MEM_READ
			IMAGE_SCN_MEM_WRITE
	*/
	PIMAGE_SECTION_HEADER sectHdr = (PIMAGE_SECTION_HEADER)((char*)ntHdr + sizeof(IMAGE_NT_HEADERS));
	memcpy(&(sectHdr->Name), "TinyLinker", 8);
	sectHdr->VirtualAddress = 0x1000;
	sectHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(shellcode), sect_align);
	sectHdr->SizeOfRawData = sizeof(shellcode);
	sectHdr->PointerToRawData = peHeaderSize;
	memcpy(peData + peHeaderSize, shellcode, sizeof(shellcode));
	sectHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	// Optional Header
	/*
		Magic: IMAGE_NT_OPTIONAL_HDR32_MAGIC (0x10b)
		BaseOfCode = section header->VirtualAddress = 0x1000
		ImageBase = 0x400000
		FileAlignment: file_align (0x200)
		SectionAlignment: sect_align (0x1000)
		Subsystem: IMAGE_SUBSYSTEM_WINDOWS_GUI
		SizeOfImage: sectHdr->VirtualAddress + sectHdr->Misc.VirtualSize
		SizeOfHeaders = PE Header size
		MajorrSubsystemVersion: 5
		MinorSubsystemVersion: 1
		AddressOfEntryPoint: secHdr->VirtualAddress
	*/
	ntHdr->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	ntHdr->OptionalHeader.BaseOfCode = sectHdr->VirtualAddress;   // .text RVA
	//ntHdr->OptionalHeader.BaseOfData = 0x0000;                    // .data RVA
	ntHdr->OptionalHeader.ImageBase = 0x400000;
	ntHdr->OptionalHeader.FileAlignment = file_align;
	ntHdr->OptionalHeader.SectionAlignment = sect_align;
	ntHdr->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	ntHdr->OptionalHeader.SizeOfImage = sectHdr->VirtualAddress + sectHdr->Misc.VirtualSize;
	ntHdr->OptionalHeader.SizeOfHeaders = peHeaderSize;
	ntHdr->OptionalHeader.MajorSubsystemVersion = 5;
	ntHdr->OptionalHeader.MinorSubsystemVersion = 1;
	ntHdr->OptionalHeader.AddressOfEntryPoint = sectHdr->VirtualAddress;

	FILE* fp = fopen("poc.exe", "wb");
	fwrite(peData, peHeaderSize + sectionDataSize, 1, fp);

	return 0;
}