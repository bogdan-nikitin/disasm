#include <iostream>
#include <cstdint>
#include <ios>
#include <fstream>
#include <vector>
#include <cstring>
#include <string>

#define EI_NIDENT 16
#define EI_MAG0 0
#define EI_MAG1 1 
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4

#define SHT_PROGBITS 0x1
#define SHT_SYMTAB 0x2
#define SHT_STRTAB 0x3

#define SHN_UNDEF	0
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_LIVEPATCH	0xff20
#define SHN_ABS		0xfff1
#define SHN_COMMON	0xfff2
#define SHN_HIRESERVE	0xffff

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_TLS     6

#define ELF32_ST_TYPE(i) ((i)&0xf)

#define ELF32_ST_BIND(i)   ((i)>>4)

#define ELF32_ST_VISIBILITY(o) ((o)&0x3)

#define STV_DEFAULT	0
#define STV_INTERNAL	1
#define STV_HIDDEN	2
#define STV_PROTECTED	3

#define STB_LOCAL	0
#define STB_GLOBAL	1
#define STB_WEAK	2
#define STB_LOOS	10
#define STB_HIOS	12
#define STB_LOPROC	13
#define STB_HIPROC	15

typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t Elf32_Sword;
typedef uint32_t Elf32_Word;


typedef struct {
    unsigned char e_ident[EI_NIDENT]; 
    Elf32_Half e_type;
    Elf32_Half e_machine; 
    Elf32_Word e_version; 
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff; 
    Elf32_Word e_flags; 
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;


typedef struct {
  Elf32_Word	sh_name;
  Elf32_Word	sh_type;
  Elf32_Word	sh_flags;
  Elf32_Addr	sh_addr;
  Elf32_Off	sh_offset;
  Elf32_Word	sh_size;
  Elf32_Word	sh_link;
  Elf32_Word	sh_info;
  Elf32_Word	sh_addralign;
  Elf32_Word	sh_entsize;
} Elf32_Shdr;


typedef struct {
    Elf32_Word st_name;
    Elf32_Addr st_value;
    Elf32_Word st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Half st_shndx;
} Elf32_Sym;


std::string get_index(Elf32_Half st_shndx) {
    switch (st_shndx) {
        case 0:
            return "UNDEF";
            /*
        case 0xff00:
            return "LORESERVE";
            */
        case 0xff00:
            return "LOPROC";
        case 0xff1f:
            return "HIPROC";
        case 0xff20:
            return "LIVEPATCH";
        case 	0xfff1:
            return "ABS";
        case 0xfff2:
            return "COMMON";
        case 0xffff:
            return "HIRESERVE";
        default:
            return std::to_string(st_shndx);
    }
}

const char * get_type(unsigned char st_info) {
    switch(ELF32_ST_TYPE(st_info)) {
        case 0:
            return "NOTYPE";
        case 1:
            return "OBJECT";
        case 2:
            return "FUNC";
        case 3:
            return "SECTION";
        case 4:
            return "FILE";
        case 5:
            return "COMMON";
        case 6:
            return "TLS";
        default:
            return nullptr;
    }
}

const char * get_vis(unsigned char st_other) {
    switch(ELF32_ST_VISIBILITY(st_other)) {
        case 0:
            return "DEFAULT";
        case 1:
            return "INTERNAL";
        case 2:
            return "HIDDEN";
        case 3:
            return "PROTECTED";
        default:
            return nullptr;
    }
}

const char * get_bind(unsigned char st_info) {
    switch(ELF32_ST_BIND(st_info)) {
        case 0:
            return "LOCAL";
        case 1:
            return "GLOBAL";
        case 2:
            return "WEAK";
        case 10:
            return "LOOS";
        case 12:
            return "HIOS";
        case 13:
            return "LOPROC";
        case 15:
            return "HIPROC";
        default:
            return nullptr;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Specify input and output files and only" << std::endl;
        return 0;
    }
    std::ifstream elf_file(argv[1], std::ios::binary | std::ios::ate);
    if (!elf_file.is_open()) {
        std::cout << "Couldn't open file" << std::endl;
        return 0;
    }
    int length = elf_file.tellg();
    std::vector<char> elf_file_content(length);
    elf_file.seekg(0, std::ios::beg);
    elf_file.read(&elf_file_content[0], length);
    elf_file.close();
    char *elf_ptr = &elf_file_content[0];
    Elf32_Ehdr *header = (Elf32_Ehdr *) elf_ptr;
    if (header->e_ident[EI_MAG0] != 0x7f ||
            header->e_ident[EI_MAG1] != 0x45 || 
            header->e_ident[EI_MAG2] != 0x4c ||
            header->e_ident[EI_MAG3] != 0x46) {
        std::cout << "Input file is not ELF file" << std::endl;
        return 0;
    }
    if (header->e_ident[EI_CLASS] == 2) {
        std::cout << "64 bit files not supported" << std::endl;
        return 0;
    }
    Elf32_Shdr *text;
    Elf32_Shdr *symtab;
    Elf32_Shdr *strtab;
    Elf32_Shdr *section_names_strtab = (Elf32_Shdr *) (elf_ptr + header->e_shoff + header->e_shstrndx * header->e_shentsize);
    char *section_names_ptr = elf_ptr + section_names_strtab->sh_offset;
    for (int i = 0; i < header->e_shnum; i++) {
        Elf32_Shdr *section = (Elf32_Shdr *) (elf_ptr + header->e_shoff + i * header->e_shentsize);            
        switch (section->sh_type) {
            case SHT_PROGBITS:
                if (strcmp(section_names_ptr + section->sh_name, ".text") == 0) {
                    text = section;
                }
                break;
            case SHT_SYMTAB:
                symtab = section;
                break;
            case SHT_STRTAB:
                if (strcmp(section_names_ptr + section->sh_name, ".strtab") == 0) {
                    strtab = section;
                }
                break;
        }
    }
    printf("Symbol Value          	Size Type 	Bind 	Vis   	Index Name\n");
    for (int i = 0; i < symtab->sh_size / symtab->sh_entsize; i++) {
        Elf32_Sym *sym = (Elf32_Sym *) (elf_ptr + symtab->sh_offset + i * symtab->sh_entsize);
        std::string index = get_index(sym->st_shndx);
        printf("[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s\n", i, sym->st_value, sym->st_size, get_type(sym->st_info), get_bind(sym->st_info), get_vis(sym->st_other), index.c_str(), elf_ptr + strtab->sh_offset + sym->st_name);
    }
}
