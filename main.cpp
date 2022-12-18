#include <iostream>
#include <cstdint>
#include <ios>
#include <fstream>
#include <vector>
#include <cstring>
#include <string>
#include <sstream>
#include <unordered_map>

#define ILEN_BYTE 4

#define OP_IMM 0b0010011
#define OP 0b0110011
#define LOAD 0b0000011 
#define STORE 0b0100011
#define JALR 0b1100111
#define LUI 0b0110111
#define AUIPC 0b0010111

typedef uint32_t Instruction;
typedef uint8_t Opcode;
typedef uint8_t Register;
typedef uint8_t Funct3;
typedef uint8_t Funct7;
typedef int32_t Immediate;
typedef uint8_t Shamt;
typedef uint8_t ShiftType;

const char * const REG_ABI[] = {
    "zero",
    "ra",
    "sp",
    "gp",
    "tp",
    "t0",
    "t1",
    "t2",
    "s0",
    "s1",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "s8",
    "s9",
    "s10",
    "s11",
    "t3",
    "t4",
    "t5",
    "t6",
};

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


template <class T>
std::string to_hex(T value)
{
    std::ostringstream stream;
    stream << std::hex << value;
    return stream.str();
}

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

const char * get_load_jalr_cmd(Funct3 funct3, Opcode opcode) {
    if (opcode == JALR && funct3 == 0b000) {
        return "JALR";
    } else if (opcode != LOAD) {
        return nullptr;
    }
    switch (funct3) {
        case 0b000:
            return "LB"; 
        case 0b001:
            return "LH"; 
        case 0b010:
            return "LW"; 
        case 0b100:
            return "LBU"; 
        case 0b101:
            return "LHU";
        default:
            return nullptr;
    }

}


void print_unknown(Elf32_Addr addr, Instruction instruction) {
    printf("   %05x:\t%08x\tunknown_instruction\n", addr, instruction);
}

void print_j(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    print_unknown(addr, instruction);
}

void print_b(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    print_unknown(addr, instruction);
}


void print_s(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    print_unknown(addr, instruction);
}


void print_system(Elf32_Addr addr, Instruction instruction) {
    print_unknown(addr, instruction);
}


Register get_rd(Instruction instruction) {
    return (instruction >> 7) & 0b11111;
}

Register get_rs1(Instruction instruction) {
    return (instruction >> 15) & 0b11111;
}

Register get_rs2(Instruction instruction) {
    return (instruction >> 20) & 0b11111;
}

Funct3 get_funct3(Instruction instruction) {
    return (instruction >> 12) & 0b111;
}

Funct7 get_funct7(Instruction instruction) {
    return (instruction >> 25) & 0b1111111;
}

const char * get_reg_name(Register reg) {
    return REG_ABI[reg];
}

const char * get_r_cmd(Funct7 funct7, Funct3 funct3) {
    if (funct7 == 0b0000000 && funct3 == 0b000) {
        return "ADD";
    }
    else if (funct7 == 0b0100000 && funct3 == 0b000) {
        return "SUB";
    }
    else if (funct7 == 0b0000000 && funct3 == 0b001) {
        return "SLL";
    }
    else if (funct7 == 0b0000000 && funct3 == 0b010) {
        return "SLT"; 
    }
    else if (funct7 == 0b0000000 && funct3 == 0b011) {
        return "SLTU"; 
    }
    else if (funct7 == 0b0000000 && funct3 == 0b100) {
        return "XOR"; 
    }
    else if (funct7 == 0b0000000 && funct3 == 0b101) {
        return "SRL";
    }
    else if (funct7 == 0b0100000 && funct3 == 0b101) {
        return "SRA";
    }
    else if (funct7 == 0b0000000 && funct3 == 0b110) {
        return "OR";
    }
    else if (funct7 == 0b0000000 && funct3 == 0b111) {
        return "AND";
    }
    // RV32M
    else if (funct7 == 0b0000001 && funct3 == 0b000) {
        return "MUL";
    }
    else if (funct7 == 0b0000001 && funct3 == 0b001) {
        return "MULH";
    }
    else if (funct7 == 0b0000001 && funct3 == 0b010) {
        return "MULHSU";
    }
    else if (funct7 == 0b0000001 && funct3 == 0b011) {
        return "MULHU";
    } 
    else if (funct7 == 0b0000001 && funct3 == 0b100) {
        return "DIV"; 
    } 
    else if (funct7 == 0b0000001 && funct3 == 0b101) {
        return "DIVU"; 
    }
    else if (funct7 == 0b0000001 && funct3 == 0b110) {
        return "REM"; 
    }
    else if (funct7 == 0b0000001 && funct3 == 0b111) {
        return "REMU";
    }
    return nullptr;
}

void print_r(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    const char * const cmd = get_r_cmd(get_funct7(instruction), get_funct3(instruction));
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        printf("   %05x:\t%08x\t%7s\t%s, %s, %s\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), get_reg_name(get_rs1(instruction)), get_reg_name(get_rs2(instruction)));
    }
}

Immediate get_i_immediate(Instruction instruction) {
    return ((instruction >> 20) & 0b11111111111) | ((instruction >> 31) ? 0b11111111111111111111100000000000 : 0);
}

Immediate get_u_immediate(Instruction instruction) {
    // return instruction & 0b11111111111111111111000000000000;
    return instruction >> 12;
}

const char * get_u_cmd(Opcode opcode) {
    switch (opcode) {
        case LUI:
            return "LUI";
        case AUIPC:
            return "AUIPC";
        default:
            return nullptr;
    }
}

void print_u(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    const char * const cmd = get_u_cmd(opcode);
    std::string immediate = std::to_string(get_u_immediate(instruction));
    printf("   %05x:\t%08x\t%7s\t%s, %s\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), immediate.c_str());
}

const char * get_i_cmd(Funct3 funct3, Opcode opcode) {
    if (funct3 == 0b000 && opcode == OP_IMM) {
        return "ADDI"; 
    }
    else if (funct3 == 0b010 && opcode == OP_IMM) {
        return "SLTI"; 
    }
    else if (funct3 == 0b011 && opcode == OP_IMM) {
        return "SLTIU"; 
    }
    else if (funct3 == 0b100 && opcode == OP_IMM) {
        return "XORI"; 
    }
    else if (funct3 == 0b110 && opcode == OP_IMM) {
        return "ORI"; 
    }
    else if (funct3 == 0b111 && opcode == OP_IMM) {
        return "ANDI";
    }
    return nullptr;
}

bool is_i_shift(Funct3 funct3, Opcode opcode) {
    return opcode == OP_IMM && (funct3 == 0b001 || funct3 == 0b101);
}

ShiftType get_shift_type(Instruction instruction) {
    return instruction >> 25;
}

Shamt get_shamt(Instruction instruction) {
    return (instruction >> 20) & 0b11111;
}

const char * get_shift_cmd(ShiftType shift_type, Funct3 funct3) {
    if (shift_type == 0b0000000 && funct3 == 0b001) {
        return "SLLI";
    }
    else if (shift_type == 0b0000000 && funct3 == 0b101) {
        return "SRLI";
    }
    else if (shift_type == 0b0100000 && funct3 == 0b101) {
        return "SRAI";
    }
    return nullptr;
}


void print_i(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    Funct3 funct3 = get_funct3(instruction);
    const char * cmd;
    std::string arg;
    if (is_i_shift(funct3, opcode)) {
        cmd = get_shift_cmd(get_shift_type(instruction), funct3);
        arg = std::to_string(get_shamt(instruction));
    }
    else {
        cmd = get_i_cmd(funct3, opcode);
        arg = std::to_string(get_i_immediate(instruction));
    }
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    } else {
        printf("   %05x:\t%08x\t%7s\t%s, %s, %s\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), get_reg_name(get_rs1(instruction)), arg.c_str());
    }
}


void print_load_jalr(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    const char * cmd = get_load_jalr_cmd(get_funct3(instruction), opcode);
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        std::string immediate = std::to_string(get_i_immediate(instruction));
        printf("   %05x:\t%08x\t%7s\t%s, %s(%s)\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), immediate.c_str(), get_reg_name(get_rs1(instruction)));
    }
}


void print_instruction(Elf32_Addr addr, Instruction instruction) {
    Opcode opcode = instruction & 0b1111111;
    switch (opcode) {
        case LOAD:
        case JALR:
            print_load_jalr(addr, instruction, opcode);
            break;
        case LUI:
        case AUIPC:
            print_u(addr, instruction, opcode);
            break;
        case 0b1101111:
            print_j(addr, instruction, opcode);
            break;
        case OP_IMM:
            print_i(addr, instruction, opcode);
            break;
        case 0b1100011:
            print_b(addr, instruction, opcode);
            break;
        case 0b0100011:
            print_s(addr, instruction, opcode);
            break;
            /*
        case 0b0001111:
            print_fence(addr, instruction);
            break;
            */
        case OP:
            print_r(addr, instruction, opcode);
            break;
        case 0b1110011:
            print_system(addr, instruction);
            break;
        default:
            print_unknown(addr, instruction);
            break;
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
                /*
            case SHT_STRTAB:
                if (strcmp(section_names_ptr + section->sh_name, ".strtab") == 0) {
                    strtab = section;
                }
                break;
                */
        }
    }
    strtab = (Elf32_Shdr *) (elf_ptr + header->e_shoff + symtab->sh_link * header->e_shentsize);
    printf("Symbol Value          	Size Type 	Bind 	Vis   	Index Name\n");
    std::unordered_map<Elf32_Addr, const char *> labels;
    for (int i = 0; i < symtab->sh_size / symtab->sh_entsize; i++) {
        Elf32_Sym *sym = (Elf32_Sym *) (elf_ptr + symtab->sh_offset + i * symtab->sh_entsize);
        std::string index = get_index(sym->st_shndx);
        const char * name = elf_ptr + strtab->sh_offset + sym->st_name;
        printf("[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s\n", i, sym->st_value, sym->st_size, get_type(sym->st_info), get_bind(sym->st_info), get_vis(sym->st_other), index.c_str(), name);
        labels[sym->st_value] = name;
    }
    for (int i = 0; i < text->sh_size; i += ILEN_BYTE) {
        Elf32_Addr addr = header->e_entry + i;
        if (labels.find(addr) != labels.end()) {
            printf("\n");
            printf("%08x   <%s>:\n", addr, labels[addr]);
        }
        // printf("%x %x\n", header->e_entry + i, *((uint32_t *) (elf_ptr + text->sh_offset + i)));
        print_instruction(header->e_entry + i, *((Instruction *) (elf_ptr + text->sh_offset + i)));
    }
}
