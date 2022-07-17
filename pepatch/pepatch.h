#ifndef PEPATCH_H
#define PEPATCH_H

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define RVA32(base, rva) ((uint32_t)base + rva)
#define RVA64(base, rva) ((uint64_t)base + rva)
#define RVA(base, rva) ((size_t)base + rva)

#define NT_HEADERS(base) (PIMAGE_NT_HEADERS)RVA(base, ((PIMAGE_DOS_HEADER)base)->e_lfanew);

typedef struct {
	void* base;
	size_t raw_size;
} pep_pe;

typedef struct {
	void* base;
	size_t raw_size;
	size_t virtual_size;
	int sections;
} pep_mapped_pe;

typedef struct {
	//void* base; /* Pointer to region in mapped pe buffer */
	size_t raw_size;
	size_t virtual_size;
	size_t virtual_address; /* Section virtual address, RVA to section in mapped pe memory */
	char name[8];
	uint32_t characteristics;
} pep_section;

pep_pe* pep_load_pe_from_path(const char* path);
pep_pe* pep_load_pe_from_memory(void* mem, size_t pe_size);
pep_mapped_pe* pep_map_pe(pep_pe* pe);

size_t pep_update_virtual_size(pep_mapped_pe* pe, size_t new_size);
pep_section pep_add_section(pep_mapped_pe* pe, const char* name, size_t size, uint32_t characteristics);

pep_pe* pep_rebuild_pe_to_memory(pep_mapped_pe* pe);
size_t pep_pe_to_file(pep_pe* pe, const char* path);

void pep_free_pe(pep_pe* pe);
void pep_free_mapped_pe(pep_mapped_pe* pe);


#endif /* PEPATCH_H */