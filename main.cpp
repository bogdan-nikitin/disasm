#include <iostream>
#include <cstdint>
#include <ios>
#include <fstream>
#include <vector>
#include <cstring>
#include <string>
#include <sstream>
#include <unordered_map>

#include "elfutil.h"
#include "riscvutil.h"





std::unordered_map<Elf32_Addr, const char *> labels;  // TODO: Make local
std::unordered_map<Elf32_Addr, Elf32_Addr> l_labels;  // TODO: Make local

template <class T>
std::string to_hex(T value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}



bool has_label(Elf32_Addr addr) {
    return labels.find(addr) != labels.end();
}

bool has_l_label(Elf32_Addr addr) {
    return l_labels.find(addr) != l_labels.end();
}

void print_unknown(Elf32_Addr addr, Instruction instruction) {
    printf("   %05x:\t%08x\tunknown_instruction\n", addr, instruction);
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


void print_s(Elf32_Addr addr, Instruction instruction) {
    const char * cmd = get_s_cmd(get_funct3(instruction));
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        std::string immediate = std::to_string(get_s_immediate(instruction));
        printf("   %05x:\t%08x\t%7s\t%s, %s(%s)\n", addr, instruction, cmd, get_reg_name(get_rs2(instruction)), immediate.c_str(), get_reg_name(get_rs1(instruction)));
    }
}


void print_u(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    const char * const cmd = get_u_cmd(opcode);
    std::string immediate = std::to_string(get_u_immediate(instruction));
    printf("   %05x:\t%08x\t%7s\t%s, %s\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), immediate.c_str());
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

std::string format_target(Elf32_Addr addr, Immediate immediate) {
    Elf32_Addr target = addr + immediate;
    std::string label;
    if (has_label(target)) {
        label = labels[target];
    }
    else {
        if (!has_l_label(target)) {
            l_labels[target] = l_labels.size();
        }
        label = "L" + std::to_string(l_labels[target]);
    }
    return to_hex(target) + " <" + label + ">";
}

void print_j(Elf32_Addr addr, Instruction instruction) {
    std::string target = format_target(addr, get_j_immediate(instruction));
    printf("   %05x:\t%08x\t%7s\t%s, %s\n", addr, instruction, "jal", get_reg_name(get_rd(instruction)), target.c_str());
}


void print_b(Elf32_Addr addr, Instruction instruction) {
    const char * cmd = get_b_cmd(get_funct3(instruction));
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        std::string target = format_target(addr, get_b_immediate(instruction));
        printf("   %05x:\t%08x\t%7s\t%s, %s, %s\n", addr, instruction, cmd, get_reg_name(get_rs1(instruction)), get_reg_name(get_rs2(instruction)), target.c_str());
    }
}


const char * get_system_cmd(Instruction instruction) {
    if (get_funct3(instruction) == PRIV && get_rd(instruction) == 0 && get_rs1(instruction) == 0) {
        switch (get_funct12(instruction)) {
            case ECALL:
                return "ecall";
            case EBREAK:
                return "ebreak";
            default:
                return nullptr;
        }
    }
    return nullptr;
}

void print_system(Elf32_Addr addr, Instruction instruction) {
    const char * cmd = get_system_cmd(instruction);
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        printf("   %05x:\t%08x\t%7s\n", addr, instruction, cmd);
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
        case JAL:
            print_j(addr, instruction);
            break;
        case OP_IMM:
            print_i(addr, instruction, opcode);
            break;
        case BRANCH:
            print_b(addr, instruction);
            break;
        case STORE:
            print_s(addr, instruction);
            break;
            /*
        case 0b0001111:
            print_fence(addr, instruction);
            break;
            */
        case OP:
            print_r(addr, instruction, opcode);
            break;
        case SYSTEM:
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
    if (header->e_ident[EI_CLASS] != ELFCLASS32) {
        std::cout << "Only 32 bits files supported" << std::endl;
        return 0;
    }
    if (header->e_ident[EI_DATA] != ELFDATA2LSB) {
        std::cout << "Only little-endian files supported" << std::endl;
        return 0;
    }
    if (header->e_ident[EI_VERSION] != EV_CURRENT) {
        std::cout << "Incorrect ELF version" << std::endl;
        return 0;
    }
    if (header->e_machine != EM_RISCV) {
        std::cout << "Not RISC-V file" << std::endl;
        return 0;
    }
    if (header->e_version != EV_CURRENT) {
        std::cout << "Incorrect format version" << std::endl;
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
        }
    }
    strtab = (Elf32_Shdr *) (elf_ptr + header->e_shoff + symtab->sh_link * header->e_shentsize);
    printf("Symbol Value          	Size Type 	Bind 	Vis   	Index Name\n");
    for (int i = 0; i < symtab->sh_size / symtab->sh_entsize; i++) {
        Elf32_Sym *sym = (Elf32_Sym *) (elf_ptr + symtab->sh_offset + i * symtab->sh_entsize);
        std::string index = get_index(sym->st_shndx);
        const char * name = elf_ptr + strtab->sh_offset + sym->st_name;
        printf("[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s\n", i, sym->st_value, sym->st_size, get_type(sym->st_info), get_bind(sym->st_info), get_vis(sym->st_other), index.c_str(), name);
        labels[sym->st_value] = name;
    }
    for (int i = 0; i < text->sh_size; i += ILEN_BYTE) {
        Elf32_Addr addr = header->e_entry + i;
        if (has_label(addr)) {
            printf("\n");
            printf("%08x   <%s>:\n", addr, labels[addr]);
        }
        print_instruction(header->e_entry + i, *((Instruction *) (elf_ptr + text->sh_offset + i)));
    }
}
