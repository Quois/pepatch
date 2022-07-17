#include "pepatch.h"

pep_pe* pep_load_pe_from_path(const char* path)
{
	FILE* file;
	fopen_s(&file, path, "rb");
	if (!file) {
		return NULL;
	}

	pep_pe* pe = malloc(sizeof(pep_pe));
	if (!pe) {
		return NULL;
	}

	fseek(file, 0, SEEK_END);
	pe->raw_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	pe->base = malloc(pe->raw_size);
	if (!pe->base) {
		free(pe);
		return NULL;
	}

	if (!fread_s(pe->base, pe->raw_size, pe->raw_size, 1, file)) {
		pep_free_pe(pe);
		return NULL;
	}

	fclose(file);

	return pe;
}

pep_pe* pep_load_pe_from_memory(void* mem, size_t pe_size)
{
	// NOT IMPLEMENTED
	return NULL;
}

pep_mapped_pe* pep_map_pe(pep_pe* pe)
{
	if (!pe) return;

	PIMAGE_NT_HEADERS p_nt_headers_raw = NT_HEADERS(pe->base);
	if (p_nt_headers_raw->Signature != IMAGE_NT_SIGNATURE) return NULL;

	pep_mapped_pe* mapped = malloc(sizeof(pep_mapped_pe));
	if (!mapped) return NULL;
	

	// Set basic data

	mapped->raw_size = pe->raw_size;
	mapped->virtual_size = p_nt_headers_raw->OptionalHeader.SizeOfImage;
	mapped->sections = p_nt_headers_raw->FileHeader.NumberOfSections;
	mapped->base = malloc(mapped->virtual_size);
	if (!mapped->base) {
		free(mapped);
		return NULL;
	}

	// Null memory before mapping

	memset(mapped->base, 0, mapped->virtual_size);

	// Copy first page into mapped pe (dos & nt headers)

	memcpy_s(mapped->base, mapped->virtual_size, pe->base, 0x1000);

	PIMAGE_NT_HEADERS p_nt_headers_mapped = NT_HEADERS(mapped->base);

	// Map sections to virtual addresses

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(p_nt_headers_raw);
	for (int i = 0; i < mapped->sections; i++, section++) {
		if (section->PointerToRawData) {
			memcpy(RVA(mapped->base, section->VirtualAddress), RVA(pe->base, section->PointerToRawData), section->SizeOfRawData);
		}
	}

	return mapped;
}

// Returns old size
// If function returns NULL, caller must free old memory block
size_t pep_update_virtual_size(pep_mapped_pe* pe, size_t new_size)
{
	if (!pe) return;
	if (new_size == 0) return;

	size_t old_size = pe->virtual_size;

	void* old_base = pe->base;
	pe->base = realloc(old_base, new_size);
	if (!pe->base) {
		return NULL;
	}

	PIMAGE_NT_HEADERS p_nt_headers = NT_HEADERS(pe->base);
	pe->virtual_size = new_size;
	p_nt_headers->OptionalHeader.SizeOfImage = new_size;

	return old_size;
}

pep_section pep_add_section(pep_mapped_pe* pe, const char* name, size_t size, uint32_t characteristics)
{
	if (!pe) return;

	pep_section section_data;
	section_data.virtual_address = pe->virtual_size;
	section_data.characteristics = characteristics;
	section_data.virtual_size = size;
	section_data.raw_size = size;
	memset(section_data.name, 0, sizeof(section_data.name));
	strcpy_s(section_data.name, sizeof(section_data.name), name);

	pep_update_virtual_size(pe, pe->virtual_size + size);
	
	PIMAGE_NT_HEADERS p_nt_headers = NT_HEADERS(pe->base);

	PIMAGE_SECTION_HEADER new_section = &((PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(p_nt_headers))[pe->sections];
	
	memcpy(new_section->Name, section_data.name, strlen(section_data.name));
	new_section->VirtualAddress = section_data.virtual_address;
	new_section->PointerToRawData = pe->raw_size;
	new_section->SizeOfRawData = section_data.raw_size;
	new_section->Misc.VirtualSize = section_data.virtual_size;
	new_section->Characteristics = section_data.characteristics;

	pe->raw_size += size;
	p_nt_headers->FileHeader.NumberOfSections++;
	pe->sections++;

	// Null new section page

	memset(RVA(pe->base, section_data.virtual_address), 0, section_data.virtual_size);

	return section_data;
}

pep_pe* pep_rebuild_pe_to_memory(pep_mapped_pe* pe)
{
	if (!pe) return;

	PIMAGE_NT_HEADERS p_nt_headers_mapped = NT_HEADERS(pe->base);

	pep_pe* unmapped = malloc(sizeof(pep_pe));
	if (!unmapped) {
		return NULL;
	}

	unmapped->raw_size = pe->raw_size;
	unmapped->base = malloc(pe->raw_size);
	if (!unmapped->base) {
		free(unmapped);
		return NULL;
	}

	// Copy headers

	memcpy_s(unmapped->base, unmapped->raw_size, pe->base, 0x1000);

	PIMAGE_NT_HEADERS p_nt_headers_raw = NT_HEADERS(unmapped->base);

	// Copy sections

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(p_nt_headers_raw);
	for (int i = 0; i < p_nt_headers_raw->FileHeader.NumberOfSections; i++, section++) {
		memcpy(RVA(unmapped->base, section->PointerToRawData), RVA(pe->base, section->VirtualAddress), section->SizeOfRawData);
	}

	return unmapped;
}

size_t pep_pe_to_file(pep_pe* pe, const char* path)
{
	FILE* file;
	fopen_s(&file, path, "wb");
	if (!file) {
		return NULL;
	}

	size_t written = fwrite(pe->base, pe->raw_size, 1, file);

	fclose(file);
	return written;
}

void pep_free_pe(pep_pe* pe)
{
	if (!pe) return;

	free(pe->base);
	free(pe);
}

void pep_free_mapped_pe(pep_mapped_pe* pe)
{
	if (!pe) return;
	
	free(pe->base);
	free(pe);
}
