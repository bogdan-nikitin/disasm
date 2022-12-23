#ifndef RISCVUTIL_H
#define RISCVUTIL_H

#include <cstdint>

#define ILEN_BYTE 4

#define OP_IMM 0b0010011
#define OP 0b0110011
#define LOAD 0b0000011 
#define STORE 0b0100011
#define JALR 0b1100111
#define LUI 0b0110111
#define AUIPC 0b0010111
#define JAL 0b1101111
#define BRANCH 0b1100011
#define SYSTEM 0b1110011
#define PRIV 0b000
#define ECALL 0b000000000000
#define EBREAK 0b000000000001

typedef uint32_t Instruction;
typedef uint8_t Opcode;
typedef uint8_t Register;
typedef uint8_t Funct3;
typedef uint8_t Funct7;
typedef uint16_t Funct12;
typedef int32_t Immediate;
typedef uint8_t Shamt;
typedef uint8_t ShiftType;

const char * get_load_jalr_cmd(Funct3 funct3, Opcode opcode);

Register get_rd(Instruction instruction);

Register get_rs1(Instruction instruction);

Register get_rs2(Instruction instruction);

Funct3 get_funct3(Instruction instruction);

Funct7 get_funct7(Instruction instruction);

const char * get_reg_name(Register reg);

Funct12 get_funct12(Instruction instruction);

const char * get_r_cmd(Funct7 funct7, Funct3 funct3);

Immediate get_i_immediate(Instruction instruction);

Immediate get_u_immediate(Instruction instruction); 

Immediate get_s_immediate(Instruction instruction);

Immediate get_j_immediate(Instruction instruction); 


const char * get_u_cmd(Opcode opcode); 

const char * get_s_cmd(Funct3 funct3); 

const char * get_i_cmd(Funct3 funct3, Opcode opcode); 

bool is_i_shift(Funct3 funct3, Opcode opcode); 

ShiftType get_shift_type(Instruction instruction); 

Shamt get_shamt(Instruction instruction); 

const char * get_shift_cmd(ShiftType shift_type, Funct3 funct3); 

Immediate get_b_immediate(Instruction instruction); 

const char * get_b_cmd(Funct3 funct3); 


#endif
