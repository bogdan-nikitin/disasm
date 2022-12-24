#ifndef DISASM_H
#define DISASM_H

#include <unordered_map>

#include "riscvutil.h"
#include "elfutil.h"


class Disasm {
public:
    void process(const char *input_file_name, const char *output_file_name);
private:
    bool has_label(Elf32_Addr addr); 
    bool has_l_label(Elf32_Addr addr); 

    void print_unknown(Elf32_Addr addr, Instruction instruction); 
    void print_r(Elf32_Addr addr, Instruction instruction, Opcode opcode); 
    void print_s(Elf32_Addr addr, Instruction instruction); 
    void print_u(Elf32_Addr addr, Instruction instruction, Opcode opcode); 
    void print_i(Elf32_Addr addr, Instruction instruction, Opcode opcode); 
    void print_load_jalr(Elf32_Addr addr, Instruction instruction, Opcode opcode); 
    std::string format_target(Elf32_Addr addr, Immediate immediate); 
    void print_j(Elf32_Addr addr, Instruction instruction); 
    void print_b(Elf32_Addr addr, Instruction instruction); 
    const char * get_system_cmd(Instruction instruction); 
    void print_system(Elf32_Addr addr, Instruction instruction); 
    void print_instruction(Elf32_Addr addr, Instruction instruction); 

    std::unordered_map<Elf32_Addr, const char *> labels;
    std::unordered_map<Elf32_Addr, Elf32_Addr> l_labels;
};

#endif
