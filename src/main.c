#include <libctf/libctf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <libgen.h>

/**
 * Locate an ELF section with specific header name.
 *
 * @param[in] elf elf file
 * @param[in] elf_header elf header
 * @param[in] to_find section name
 * @return tuple struct containing offset and size of the section or NULL if
 *         such section does not exist
 */
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

/**
 * Compute CTF disk storage size.
 *
 * The ELF sections that contribute to the result are: .SUNW_ctf, .strtab and
 * .symtab.
 *
 * @param[in] elf elf file
 * @param[in] elf_header elf header
 * @return size in bytes
 */
static size_t
ctf_storage (Elf* elf, Elf32_Ehdr* elf_header)
{
	size_t usage = 0;

	struct _section* ctf = elf_section_find(elf, elf_header, ".SUNW_ctf");
	struct _section* strtab = elf_section_find(elf, elf_header, ".strtab");
	struct _section* symtab = elf_section_find(elf, elf_header, ".symtab");

	if (ctf != NULL)
		usage += ctf->size;
	
	if (strtab != NULL)
		usage += strtab->size;

	if (symtab != NULL)
		usage += symtab->size;

	return usage;
}

/**
 * Compute DWARF disk storage size.
 *
 * The ELF sections that contribute to the result are: .debug_info and
 * .debug_str.
 *
 * @param[in] elf elf file
 * @param[in] elf_header elf header
 * @return size in bytes
 */
static size_t
dwarf_storage (Elf* elf, Elf32_Ehdr* elf_header)
{
	size_t usage = 0;

	struct _section* dwarf_info = elf_section_find(elf, elf_header, 
	    ".debug_info");
	struct _section* dwarf_str = elf_section_find(elf, elf_header,
	    ".debug_str");

	if (dwarf_info != NULL)
		usage += dwarf_info->size;

	if (dwarf_str != NULL)
		usage += dwarf_str->size;

	return usage;
}

/**
 * Print formatted output of the CTF data usage comparison between disk storage
 * and in-memory storage.
 *
 * @param[in] memory_usage size of the CTF in the memory
 * @param[in] ctf_storage_usage size of the CTF on the disk
 * @param[in] r_flag include ratio flag
 * @param[in] s_flag simple ratio output flag
 * @param[in] d_flag include DWARF flag - depending on the presence we add the 
 *                   empty line at the end of the output
 */
static void
print_ctf (size_t memory_usage, size_t ctf_storage_usage, uint8_t r_flag, 
	uint8_t s_flag, uint8_t d_flag)
{
	float ratio = (float)memory_usage/(float)ctf_storage_usage;

	if (r_flag && s_flag)
	{
		printf("%.3f\n", ratio);
		return;
	}

	printf("CTF memory vs. CTF storage\n");	
	printf("--------------------------\n");	
	printf("   Memory usage: %u bytes\n", memory_usage);
	printf("  Storage usage: %u bytes\n", ctf_storage_usage);

	if (r_flag)
		printf("          Ratio: %.3f\n", ratio);

	if (d_flag)
		printf("\n");
}

/**
 * Print formatted output of the CTF and DWARF disk usage comparison.
 *
 * @param[in] ctf_storage_usage size of the CTF on the disk
 * @param[in] dwarf_storage_usage size of the DWARF on the disk
 * @param[in] r_flag include ratio flag
 * @param[in] s_flag simple ratio output flag
 */
static void
print_dwarf (size_t ctf_storage_usage, size_t dwarf_storage_usage, 
    uint8_t r_flag, uint8_t s_flag)
{
	float ratio = (float)dwarf_storage_usage/(float)ctf_storage_usage;

	if (r_flag && s_flag)
	{
		printf("%.3f\n", ratio);
		return;
	}
		
	printf("DWARF storage vs. CTF storage\n");	
	printf("-----------------------------\n");	
	printf("  DWARF: %u bytes\n", dwarf_storage_usage);
	printf("    CTF: %u bytes\n", ctf_storage_usage);

	if (r_flag)
		printf("  Ratio: %.3f\n", ratio);
}

/**
 * Load the ELF file.
 *
 * @param[in] filename ELF filename
 * @param[out] fd file descriptor
 * @param[out] elf elf file
 * @param[out] elf_header elf header
 * @return 0 on success, 1 otherwise
 */
static int 
load_elf (char* filename, int* fd, Elf** elf, Elf32_Ehdr* elf_header)
{
	if ((*fd = open(filename, O_RDONLY)) < 0)
		return 1;

	/* read the ELF header */
	if (read(*fd, elf_header, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr))
	{
		close(*fd);
		return 1;
	}

	/* set the libelf version */
	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		close(*fd);
		return 1;
	}

	/* load the ELF file */
	if ((*elf = elf_begin(*fd, ELF_C_READ, NULL)) == NULL)
	{
		close(*fd);
		return 1;
	}

	return 0;
}

/**
 * Print the usage message.
 */
static void
usage ()
{
	printf("Usage: ctfmemusage [-dhlrs] file\n");
}

/**
 * ctfmemusage - inspect library memory usage and comparison against the DWARF
 * format.
 */
int
main (int argc, char* argv[])
{
	Elf* elf = NULL;
	Elf32_Ehdr elf_header;
	ctf_file file;
	int fd;
	int retval;
	size_t ctf_memory_usage = 0;
	size_t ctf_storage_usage = 0;
	size_t dwarf_storage_usage = 0;
	uint8_t l_flag = 0;
	uint8_t d_flag = 0;
	uint8_t r_flag = 0;
	uint8_t s_flag = 0;
	int option;

	while ((option = getopt(argc, argv, "ldhrs")) != -1)
	{
		switch(option)
		{
			case 'l': 
				l_flag = 1;
			break;

			case 'd': 
				d_flag = 1;
			break;

			case 'r': 
				r_flag = 1;
			break;

			case 's': 
				s_flag = 1;
			break;

			case 'h':
				usage();
				return EXIT_FAILURE;

			case '?':
				fprintf(stderr, "ERROR: invalid option %c\n", optopt);	
				usage();
				return EXIT_FAILURE;

			default: 
				fprintf(stderr, "ERROR: unknown error during option parsing\n");	
				return EXIT_FAILURE;
		}
	}

	if (argc - optind < 1)
	{
		usage();
		return EXIT_FAILURE;
	}

	if ((retval = ctf_file_read(argv[optind], &file)) != CTF_OK)
	{
		fprintf(stderr, "ERROR: %s\n", ctf_get_error_string(retval));
		return EXIT_FAILURE;
	}

	if (load_elf(argv[optind], &fd, &elf, &elf_header) != 0)
	{
		fprintf(stderr, "ERROR: unable to load ELF\n");
		return EXIT_FAILURE;
	}

	ctf_memory_usage = ctf_file_memory_usage(file);
	ctf_storage_usage = ctf_storage(elf, &elf_header);
	dwarf_storage_usage = dwarf_storage(elf, &elf_header);

	if (l_flag)
		print_ctf(ctf_memory_usage, ctf_storage_usage, r_flag, s_flag, d_flag);

	if (d_flag)
		print_dwarf(ctf_storage_usage, dwarf_storage_usage, r_flag, s_flag);

	return EXIT_SUCCESS;
}

