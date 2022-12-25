#include <string>
#include <ios>
#include <vector>
#include <cstring>
#include <string>
#include <sstream>
#include <unordered_map>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cerrno>

#include "disasm.h"
#include "riscvutil.h"
#include "elfutil.h"


template <class T>
static std::string to_hex(T value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}


bool Disasm::has_symtab_label(Elf32_Addr addr) {
    return symtab_labels.find(addr) != symtab_labels.end();
}


bool Disasm::has_l_label(Elf32_Addr addr) {
    return l_labels.find(addr) != l_labels.end();
}


bool Disasm::has_label(Elf32_Addr addr) {
    return has_symtab_label(addr) || has_l_label(addr);
}


void Disasm::print_unknown(Elf32_Addr addr, Instruction instruction) {
    print("   %05x:\t%08x\tunknown_instruction\n", addr, instruction);
}


void Disasm::print_r(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    const char * const cmd = get_r_cmd(get_funct7(instruction), get_funct3(instruction));
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        print("   %05x:\t%08x\t%7s\t%s, %s, %s\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), get_reg_name(get_rs1(instruction)), get_reg_name(get_rs2(instruction)));
    }
}


void Disasm::Disasm::print_s(Elf32_Addr addr, Instruction instruction) {
    const char * cmd = get_s_cmd(get_funct3(instruction));
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        std::string immediate = std::to_string(get_s_immediate(instruction));
        print("   %05x:\t%08x\t%7s\t%s, %s(%s)\n", addr, instruction, cmd, get_reg_name(get_rs2(instruction)), immediate.c_str(), get_reg_name(get_rs1(instruction)));
    }
}


void Disasm::print_u(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    const char * const cmd = get_u_cmd(opcode);
    std::string immediate = std::to_string(get_u_immediate(instruction));
    print("   %05x:\t%08x\t%7s\t%s, %s\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), immediate.c_str());
}


void Disasm::print_i(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
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
        print("   %05x:\t%08x\t%7s\t%s, %s, %s\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), get_reg_name(get_rs1(instruction)), arg.c_str());
    }
}


void Disasm::print_load_jalr(Elf32_Addr addr, Instruction instruction, Opcode opcode) {
    const char * cmd = get_load_jalr_cmd(get_funct3(instruction), opcode);
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        std::string immediate = std::to_string(get_i_immediate(instruction));
        print("   %05x:\t%08x\t%7s\t%s, %s(%s)\n", addr, instruction, cmd, get_reg_name(get_rd(instruction)), immediate.c_str(), get_reg_name(get_rs1(instruction)));
    }
}


std::string Disasm::get_label(Elf32_Addr addr) {
    std::string label;
    if (has_symtab_label(addr)) {
        label = symtab_labels[addr];
    }
    else {
        label = "L" + std::to_string(l_labels[addr]);
    }
    return label;
}


std::string Disasm::format_target(Elf32_Addr addr, Immediate immediate) {
    Elf32_Addr target = addr + immediate;
    return to_hex(target) + " <" + get_label(target) + ">";
}


void Disasm::print_j(Elf32_Addr addr, Instruction instruction) {
    std::string target = format_target(addr, get_j_immediate(instruction));
    print("   %05x:\t%08x\t%7s\t%s, %s\n", addr, instruction, "jal", get_reg_name(get_rd(instruction)), target.c_str());
}


void Disasm::print_b(Elf32_Addr addr, Instruction instruction) {
    const char * cmd = get_b_cmd(get_funct3(instruction));
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        std::string target = format_target(addr, get_b_immediate(instruction));
        print("   %05x:\t%08x\t%7s\t%s, %s, %s\n", addr, instruction, cmd, get_reg_name(get_rs1(instruction)), get_reg_name(get_rs2(instruction)), target.c_str());
    }
}


const char * Disasm::get_system_cmd(Instruction instruction) {
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


void Disasm::print_system(Elf32_Addr addr, Instruction instruction) {
    const char * cmd = get_system_cmd(instruction);
    if (cmd == nullptr) {
        print_unknown(addr, instruction);
    }
    else {
        print("   %05x:\t%08x\t%7s\n", addr, instruction, cmd);
    }
}


void Disasm::extract_l_label(Elf32_Addr addr, Instruction instruction) {
    Opcode opcode = instruction & 0b1111111;
    Immediate immediate;
    if (opcode == JAL) {
        immediate = get_j_immediate(instruction);
    }
    else if (opcode == BRANCH && is_valid_b_instruction(get_funct3(instruction))) {
        immediate = get_b_immediate(instruction);
    } else {
        return;
    }
    Elf32_Addr target = addr + immediate;
    if (!has_label(target) && !has_l_label(target)) {
        l_labels[target] = l_labels.size();
    }
}


void Disasm::print_instruction(Elf32_Addr addr, Instruction instruction) {
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


void Disasm::print(const char *format, ...) {
    va_list ptr;
    va_start(ptr, format);
    vprintf(format, ptr);
    va_end(ptr);
}


bool Disasm::read_input_file(std::vector<char> &dest, const char *input_file_name) {
    FILE *elf_file = fopen(input_file_name, "rb");
    if (elf_file == NULL) {
        perror("Couldn't open input file");
        return false;
    }
    fseek(elf_file, 0, SEEK_END);
    long length = ftell(elf_file);
    dest.resize(length);
    fseek(elf_file, 0, SEEK_SET);
    fread(&dest[0], length, 1, elf_file);
    fclose(elf_file);
    return true;
}


void Disasm::collect_l_labels() {
    for (int i = 0; i < text->sh_size; i += ILEN_BYTE) {
        Elf32_Addr addr = header->e_entry + i;
        extract_l_label(header->e_entry + i, *((Instruction *) (elf_ptr + text->sh_offset + i)));
    }
}


void Disasm::process(const char *input_file_name, const char *output_file_name) {
    std::vector<char> elf_file_content;
    if (!read_input_file(elf_file_content, input_file_name)) {
        return;
    }
    elf_ptr = &elf_file_content[0];
    header = (Elf32_Ehdr *) elf_ptr;
    if (header->e_ident[EI_MAG0] != 0x7f ||
            header->e_ident[EI_MAG1] != 0x45 || 
            header->e_ident[EI_MAG2] != 0x4c ||
            header->e_ident[EI_MAG3] != 0x46) {
        printf("Input file is not ELF file\n");
        return;
    }
    if (header->e_ident[EI_CLASS] != ELFCLASS32) {
        printf("Only 32 bits files supported\n");
        return;
    }
    if (header->e_ident[EI_DATA] != ELFDATA2LSB) {
        printf("Only little-endian files supported\n");
        return;
    }
    if (header->e_ident[EI_VERSION] != EV_CURRENT) {
        printf("Incorrect ELF version\n");
        return;
    }
    if (header->e_machine != EM_RISCV) {
        printf("Not RISC-V file\n");
        return;
    }
    if (header->e_version != EV_CURRENT) {
        printf("Incorrect format version\n");
        return;
    }
    if (header->e_entry == 0) {
        printf("No entry point\n");
        return;
    }
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
    if (text == nullptr) {
        printf(".text not found\n");
        return;
    }
    else if (symtab == nullptr) {
        printf(".symtab not found\n");
        return;
    }
    Elf32_Shdr *strtab = (Elf32_Shdr *) (elf_ptr + header->e_shoff + symtab->sh_link * header->e_shentsize);
    print("Symbol Value          	Size Type 	Bind 	Vis   	Index Name\n");
    for (int i = 0; i < symtab->sh_size / symtab->sh_entsize; i++) {
        Elf32_Sym *sym = (Elf32_Sym *) (elf_ptr + symtab->sh_offset + i * symtab->sh_entsize);
        std::string index = get_index(sym->st_shndx);
        const char * name = elf_ptr + strtab->sh_offset + sym->st_name;
        print("[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s\n", i, sym->st_value, sym->st_size, get_type(sym->st_info), get_bind(sym->st_info), get_vis(sym->st_other), index.c_str(), name);
        symtab_labels[sym->st_value] = name;
    }
    collect_l_labels();
    for (int i = 0; i < text->sh_size; i += ILEN_BYTE) {
        Elf32_Addr addr = header->e_entry + i;
        if (has_label(addr)) {
            std::string label = get_label(addr);
            print("%08x   <%s>:\n", addr, label.c_str());
        }
        print_instruction(header->e_entry + i, *((Instruction *) (elf_ptr + text->sh_offset + i)));
    }
}
