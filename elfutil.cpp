#include "elfutil.h"


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
