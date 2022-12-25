#ifndef ELFUTIL_H
#define ELFUTIL_H

#include <string>

#define EI_MAG0 0
#define EI_MAG1 1 
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4

#define ELFCLASS32 1
#define ELFDATA2LSB 1
#define EV_CURRENT 1
#define EI_DATA 5
#define EI_VERSION 6
#define EM_RISCV 0xf3

#define SHT_PROGBITS 0x1
#define SHT_SYMTAB 0x2
#define SHT_STRTAB 0x3

#define SHN_UNDEF 0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_LIVEPATCH 0xff20
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_COMMON 5
#define STT_TLS 6

#define ELF32_ST_TYPE(i) ((i)&0xf)

#define ELF32_ST_BIND(i) ((i)>>4)

#define ELF32_ST_VISIBILITY(o) ((o)&0x3)

#define STV_DEFAULT 0
#define STV_INTERNAL 1
#define STV_HIDDEN 2
#define STV_PROTECTED 3

#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2
#define STB_LOOS 10
#define STB_HIOS 12
#define STB_LOPROC 13
#define STB_HIPROC 15

typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t Elf32_Sword;
typedef uint32_t Elf32_Word;


#define EI_NIDENT 16


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
    Elf32_Half e_phum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;


typedef struct {
  Elf32_Word sh_name;
  Elf32_Word sh_type;
  Elf32_Word sh_flags;
  Elf32_Addr sh_addr;
  Elf32_Off sh_offset;
  Elf32_Word sh_size;
  Elf32_Word sh_link;
  Elf32_Word sh_info;
  Elf32_Word sh_addralign;
  Elf32_Word sh_entsize;
} Elf32_Shdr;


typedef struct {
    Elf32_Word st_name;
    Elf32_Addr st_value;
    Elf32_Word st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Half st_shndx;
} Elf32_Sym;


std::string get_index(Elf32_Half st_shndx); 

const char * get_type(unsigned char st_info); 

const char * get_vis(unsigned char st_other); 

const char * get_bind(unsigned char st_info); 

#endif
