#include <iostream>

#include "disasm.h"
#include "elfutil.h"
#include "riscvutil.h"


int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Specify input and output files and only" << std::endl;
        return 0;
    }
    Disasm disasm{};
    disasm.process(argv[1], argv[2]);
}
