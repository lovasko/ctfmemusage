#include <libctf/libctf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <libgen.h>

static struct _section*
elf_section_find (Elf* elf, Elf32_Ehdr* elf_header, const char* to_find)
{
	Elf_Scn* section = NULL;  	
	GElf_Shdr section_header;
	
	while ((section = elf_nextscn(elf, section)) != 0)
	{
		gelf_getshdr(section, &section_header);
		char* section_name = elf_strptr(elf, elf_header->e_shstrndx, 
		    section_header.sh_name);

		if (strcmp(section_name, to_find) == 0)
		{
			Elf_Data* data = elf_getdata(section, NULL);

			struct _section* result = malloc(_SECTION_SIZE);
			result->size = data->d_size;
			result->data = malloc(data->d_size);
			memcpy(result->data, data->d_buf, data->d_size);

			return result;
		}
	}

	return NULL;
}

int
main (int argc, char* argv[])
{
	ctf_file file;
	size_t memory_usage = 0;
	size_t ctf_storage_usage = 0;
	size_t dwarf_storage_usage = 0;

	ctf_file_read(argv[1], &file);
	memory_usage = ctf_file_memory_usage(file);	


	int fd;
	if ((fd = open(argv[1], O_RDONLY)) < 0)
		return 1;

	/* read the ELF header */
	Elf32_Ehdr elf_header;
	if (read(fd, &elf_header, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr))
	{
		close(fd);
		return 1;
	}

	/* set the libelf version */
	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		close(fd);
		return 1;
	}

	/* load the ELF file */
	Elf* elf = NULL;
	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
	{
		close(fd);
		return 1;
	}

	/* find the CTF section */
	struct _section* ctf_section = elf_section_find(elf, &elf_header,
	    ".SUNW_ctf");

	/* find the string table section */
	struct _section* strtab_section = elf_section_find(elf, &elf_header,
	    ".strtab");

	/* find the symbol table section */
	struct _section* symtab_section = elf_section_find(elf, &elf_header,
	    ".symtab");

	if (ctf_section != NULL)
		ctf_storage_usage += ctf_section->size;
	
	if (strtab_section != NULL)
		ctf_storage_usage += strtab_section->size;

	if (symtab_section != NULL)
		ctf_storage_usage += symtab_section->size;

	/* find the DWARF core info table */
	struct _section* dwarf_info_section = elf_section_find(elf, &elf_header,
	    ".debug_info");

	/* find the DWARF string table */
	struct _section* dwarf_str_section = elf_section_find(elf, &elf_header,
	    ".debug_str");

	if (dwarf_info_section != NULL)
		dwarf_storage_usage += dwarf_info_section->size;

	if (dwarf_str_section != NULL)
		dwarf_storage_usage += dwarf_str_section->size;

	printf("CTF memory vs. CTF storage\n");	
	printf("--------------------------\n");	
	printf("   Memory usage: %u bytes\n", memory_usage);
	printf("  Storage usage: %u bytes\n", ctf_storage_usage);
	printf("          Ratio: %.3f\n", 
	    (float)memory_usage/(float)ctf_storage_usage);

	printf("\n");

	printf("DWARF storage vs. CTF storage\n");	
	printf("-----------------------------\n");	
	printf("  DWARF: %u bytes\n", dwarf_storage_usage);
	printf("    CTF: %u bytes\n", ctf_storage_usage);
	printf("  Ratio: %.3f\n", 
	    (float)dwarf_storage_usage/(float)ctf_storage_usage);

	return 0;
}

