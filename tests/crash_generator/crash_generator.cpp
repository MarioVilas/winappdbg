#include <iostream>
#include <string>
#include <windows.h>
#include <vector>
#include <cstdlib> // for exit()

// Function to cause a null pointer dereference
void nullPointerDereference() {
    int* ptr = nullptr;
    *ptr = 42; // This will crash
}

// Function to cause an access violation
void accessViolation() {
    int* ptr = reinterpret_cast<int*>(0x12345678);
    *ptr = 42; // This will crash
}

// Function to cause a stack overflow
void stackOverflow() {
    std::vector<char> buffer(1024 * 1024); // Allocate a large buffer on the stack
    stackOverflow(); // Recursive call will overflow the stack
}

// Function to cause a divide by zero
void divideByZero() {
    volatile int zero = 0;
    int result = 1 / zero; // This will crash
}

// Function to execute an illegal instruction
void illegalInstruction() {
    // UD2 instruction (guaranteed to be invalid)
    unsigned char* code = new unsigned char[2];
    code[0] = 0x0F;
    code[1] = 0x0B;

    DWORD oldProtect;
    // Make the memory executable
    if (VirtualProtect(code, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Cast to function pointer and call
        void (*func)() = reinterpret_cast<void(*)()>(code);
        func();
    }

    // Note: This delete[] will never be reached due to the crash
    delete[] code;
}

// Function to corrupt the heap
void heapCorruption() {
    char* buffer = new char[10];
    // Write beyond the allocated memory
    for (int i = 0; i < 100; i++) {
        buffer[i] = 'X';
    }
    delete[] buffer; // This will likely crash
}

void printUsage() {
    std::cout << "Usage: crash_generator.exe <crash_type>\n";
    std::cout << "Available crash types:\n";
    std::cout << "  null    - Null pointer dereference\n";
    std::cout << "  access  - Access violation\n";
    std::cout << "  stack   - Stack overflow\n";
    std::cout << "  divide  - Divide by zero\n";
    std::cout << "  illegal - Illegal instruction\n";
    std::cout << "  heap    - Heap corruption\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printUsage();
        return 1;
    }

    std::string crashType = argv[1];
    std::cout << "Generating crash: " << crashType << std::endl;

    try {
        if (crashType == "null") {
            nullPointerDereference();
        }
        else if (crashType == "access") {
            accessViolation();
        }
        else if (crashType == "stack") {
            stackOverflow();
        }
        else if (crashType == "divide") {
            divideByZero();
        }
        else if (crashType == "illegal") {
            illegalInstruction();
        }
        else if (crashType == "heap") {
            heapCorruption();
        }
        else {
            std::cout << "Unknown crash type: " << crashType << std::endl;
            printUsage();
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cout << "Exception caught: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "If you see this message the program has survived the crash." << std::endl;
    return 0;
}