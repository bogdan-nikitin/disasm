#ifndef DISASM_H
#define DISASM_H

#include <unordered_map>
#include <vector>

#include "riscvutil.h"
#include "elfutil.h"


class Disasm {
public:
    void process(const char *input_file_name, const char *output_file_name);
private:
    long get_file_offset(const char *ptr);
    bool in_file(const char *ptr, long size);
    bool has_symtab_label(Elf32_Addr addr); 
    bool has_l_label(Elf32_Addr addr); 
    bool has_label(Elf32_Addr addr); 
    void print_unknown(Elf32_Addr addr, Instruction instruction); 
    void print_r(Elf32_Addr addr, Instruction instruction); 
    void print_s(Elf32_Addr addr, Instruction instruction); 
    void print_u(Elf32_Addr addr, Instruction instruction, Opcode opcode); 
    void print_i(Elf32_Addr addr, Instruction instruction, Opcode opcode); 
    void print_load_jalr(Elf32_Addr addr, Instruction instruction, Opcode opcode); 
    std::string get_label(Elf32_Addr addr);
    std::string format_target(Elf32_Addr addr, Immediate immediate); 
    void print_j(Elf32_Addr addr, Instruction instruction); 
    void print_b(Elf32_Addr addr, Instruction instruction); 
    const char * get_system_cmd(Instruction instruction); 
    void print_system(Elf32_Addr addr, Instruction instruction); 
    void extract_l_label(Elf32_Addr addr, Instruction instruction);
    void print_instruction(Elf32_Addr addr, Instruction instruction); 
    void print(const char *format, ...);
    void report_error(const char *format, ...);
    bool read_input_file(std::vector<char> &dest, const char *input_file_name);
    void collect_l_labels();
    bool process_section_header_table();
    bool process_symtab();
    void print_text();
    void print_symtab();
    bool process_header();
    bool check_text();
    bool open_write_file(const char *output_file_name);

    std::vector<char> elf_file_content;
    std::unordered_map<Elf32_Addr, const char *> symtab_labels;
    std::unordered_map<Elf32_Addr, Elf32_Addr> l_labels;
    Elf32_Shdr *text = nullptr;
    Elf32_Shdr *symtab = nullptr;
    Elf32_Shdr *strtab;
    char *elf_ptr;
    Elf32_Ehdr *header;
    FILE *output_file;
    int write_error = 0;
};

#endif
