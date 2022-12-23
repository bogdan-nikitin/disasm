#include "riscvutil.h"


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


const char * get_load_jalr_cmd(Funct3 funct3, Opcode opcode) {
    if (opcode == JALR && funct3 == 0b000) {
        return "jalr";
    } else if (opcode != LOAD) {
        return nullptr;
    }
    switch (funct3) {
        case 0b000:
            return "lb"; 
        case 0b001:
            return "lh"; 
        case 0b010:
            return "lw"; 
        case 0b100:
            return "lbu"; 
        case 0b101:
            return "lhu";
        default:
            return nullptr;
    }
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

Funct12 get_funct12(Instruction instruction) {
    return instruction >> 20;
}

const char * get_r_cmd(Funct7 funct7, Funct3 funct3) {
    if (funct7 == 0b0000000 && funct3 == 0b000) {
        return "add";
    }
    else if (funct7 == 0b0100000 && funct3 == 0b000) {
        return "sub";
    }
    else if (funct7 == 0b0000000 && funct3 == 0b001) {
        return "sll";
    }
    else if (funct7 == 0b0000000 && funct3 == 0b010) {
        return "slt"; 
    }
    else if (funct7 == 0b0000000 && funct3 == 0b011) {
        return "sltu"; 
    }
    else if (funct7 == 0b0000000 && funct3 == 0b100) {
        return "xor"; 
    }
    else if (funct7 == 0b0000000 && funct3 == 0b101) {
        return "srl";
    }
    else if (funct7 == 0b0100000 && funct3 == 0b101) {
        return "sra";
    }
    else if (funct7 == 0b0000000 && funct3 == 0b110) {
        return "or";
    }
    else if (funct7 == 0b0000000 && funct3 == 0b111) {
        return "and";
    }
    // RV32M
    else if (funct7 == 0b0000001 && funct3 == 0b000) {
        return "mul";
    }
    else if (funct7 == 0b0000001 && funct3 == 0b001) {
        return "mulh";
    }
    else if (funct7 == 0b0000001 && funct3 == 0b010) {
        return "mulhsu";
    }
    else if (funct7 == 0b0000001 && funct3 == 0b011) {
        return "mulhu";
    } 
    else if (funct7 == 0b0000001 && funct3 == 0b100) {
        return "div"; 
    } 
    else if (funct7 == 0b0000001 && funct3 == 0b101) {
        return "divu"; 
    }
    else if (funct7 == 0b0000001 && funct3 == 0b110) {
        return "rem"; 
    }
    else if (funct7 == 0b0000001 && funct3 == 0b111) {
        return "remu";
    }
    return nullptr;
}

Immediate get_i_immediate(Instruction instruction) {
    return ((instruction >> 20) & 0b11111111111) | ((instruction >> 31) ? 0b11111111111111111111100000000000 : 0);
}

Immediate get_u_immediate(Instruction instruction) {
    return instruction >> 12;
}

Immediate get_s_immediate(Instruction instruction) {
    return (instruction >> 7 & 0b11111 | (((instruction >> 25) & 0b111111) << 5)) | ((instruction >> 31) ? 0b11111111111111111111100000000000 : 0);
}

Immediate get_j_immediate(Instruction instruction) {
    return (((instruction >> 21) & 0b1111111111) << 1) | (((instruction >> 20) & 1) << 11) | (instruction & 0b11111111000000000000) | ((instruction >> 31) ? 0b11111111111100000000000000000000 : 0);
}


const char * get_u_cmd(Opcode opcode) {
    switch (opcode) {
        case LUI:
            return "lui";
        case AUIPC:
            return "auipc";
        default:
            return nullptr;
    }
}

const char * get_s_cmd(Funct3 funct3) {
    switch (funct3) {
        case 0b000:
            return "sb";
        case 0b001:
            return "sh";
        case 0b010:
            return "sw";
        default:
            return nullptr;
    }
}

const char * get_i_cmd(Funct3 funct3, Opcode opcode) {
    if (funct3 == 0b000 && opcode == OP_IMM) {
        return "addi"; 
    }
    else if (funct3 == 0b010 && opcode == OP_IMM) {
        return "slti"; 
    }
    else if (funct3 == 0b011 && opcode == OP_IMM) {
        return "sltiu"; 
    }
    else if (funct3 == 0b100 && opcode == OP_IMM) {
        return "xori"; 
    }
    else if (funct3 == 0b110 && opcode == OP_IMM) {
        return "ori"; 
    }
    else if (funct3 == 0b111 && opcode == OP_IMM) {
        return "andi";
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
        return "slli";
    }
    else if (shift_type == 0b0000000 && funct3 == 0b101) {
        return "srli";
    }
    else if (shift_type == 0b0100000 && funct3 == 0b101) {
        return "srai";
    }
    return nullptr;
}


Immediate get_b_immediate(Instruction instruction) {
    return (((instruction >> 8) & 0b1111) << 1) | (((instruction >> 25) & 0b111111) << 5) | (((instruction >> 7) & 1) << 11) | ((instruction >> 31) ? 0b11111111111111111111000000000000 : 0);
}

const char * get_b_cmd(Funct3 funct3) {
    switch (funct3) {
        case 0b000:
            return "beq"; 
        case 0b001:
            return "bne"; 
        case 0b100:
            return "blt"; 
        case 0b101:
            return "bge"; 
        case 0b110:
            return "bltu"; 
        case 0b111:
            return "bgeu";
        default:
            return nullptr;
    }
}
