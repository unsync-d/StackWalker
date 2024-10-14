#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>
#include <winternl.h>
#include <vector>
#include <string> 
#include <sstream> 
#include <algorithm>  
#include <tuple>
#include <thread> 

// Load NtQueryInformationThread dynamically
typedef NTSTATUS(WINAPI* _NtQueryInformationThread)(
    HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

// Struct to hold thread information
struct ThreadInfo {
    DWORD tid;
    void* startAddress;
};


// Helper function to check if an address is a readable string
bool IsReadableString(HANDLE hProcess, void* addr) {
    char buffer[256];  // Assume string won't exceed 256 characters
    SIZE_T bytesRead;
    if (ReadProcessMemory(hProcess, addr, buffer, sizeof(buffer) - 1, &bytesRead)) {
        buffer[bytesRead] = '\0';  // Null terminate the string
        // Check if the buffer contains printable characters
        for (size_t i = 0; i < bytesRead; i++) {
            if (!isprint(buffer[i]) && buffer[i] != '\0') {
                return false;
            }
        }
        return true;
    }
    return false;
}


void PrintFunctionParameters(const CONTEXT& context, HANDLE hProcess, STACKFRAME64& stackFrame) {
#ifdef _M_X64
    std::cout << "    Function Parameters:\n";

    // Heuristic check for common parameter types
    auto printParam = [&hProcess](const char* regName, DWORD64 value) {  // Capture hProcess by reference
        // Try interpreting as different types (int, string, pointer)
        std::cout << "      " << regName << ": 0x" << std::hex << value << std::dec;

        // Check if it's a valid pointer
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (void*)value, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                // Try reading the memory as a string (ASCII/UTF-16)
                char buffer[256];
                if (ReadProcessMemory(hProcess, (void*)value, buffer, sizeof(buffer) - 1, nullptr)) {
                    buffer[255] = '\0'; // Null-terminate
                    std::cout << " (string: \"" << buffer << "\")";
                }
            }
        }
        else if (value <= INT_MAX) {
            std::cout << " (int: " << (int)value << ")";
        }

        std::cout << "\n";
        };

    printParam("RCX", context.Rcx);
    printParam("RDX", context.Rdx);
    printParam("R8", context.R8);
    printParam("R9", context.R9);

#endif
}



// Function to get the start address of a thread
void* GetThreadStartAddress(HANDLE hThread) {
    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    if (!hNtDll) {
        std::cerr << "Failed to load ntdll.dll\n";
        return nullptr;
    }

    _NtQueryInformationThread NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(hNtDll, "NtQueryInformationThread");
    if (!NtQueryInformationThread) {
        std::cerr << "Failed to get NtQueryInformationThread function\n";
        return nullptr;
    }

    void* startAddress = nullptr;
    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)9 /*ThreadQuerySetWin32StartAddress*/, &startAddress, sizeof(startAddress), nullptr);
    if (status != 0) {
        std::cerr << "NtQueryInformationThread failed with status: " << status << std::endl;
        return nullptr;
    }

    return startAddress;
}

// Function to get module name by address, optionally return the full path if verbose is true
std::string GetModuleNameFromAddress(void* addr, HANDLE hProcess, bool verbose) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    // Get the list of all modules in the process
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(MODULEINFO));

            // Check if the address is within this module's range
            if (addr >= modInfo.lpBaseOfDll && addr < (void*)((char*)modInfo.lpBaseOfDll + modInfo.SizeOfImage)) {
                char modulePath[MAX_PATH];
                GetModuleFileNameExA(hProcess, hMods[i], modulePath, sizeof(modulePath) / sizeof(char));

                if (verbose) {
                    // Return the full module path
                    return std::string(modulePath);
                }
                else {
                    // Return only the module name (strip the path)
                    std::string moduleName = modulePath;
                    size_t lastSlash = moduleName.find_last_of("\\/");
                    if (lastSlash != std::string::npos) {
                        moduleName = moduleName.substr(lastSlash + 1);
                    }
                    return moduleName;
                }
            }
        }
    }
    return "Unknown Module";
}

// Function to resolve address to function name and module using dbghelp
std::string ResolveAddressToFunction(void* addr, HANDLE hProcess, bool verbose) {
    char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement = 0;
    // Try to resolve the symbol name from the address
    if (SymFromAddr(hProcess, (DWORD64)addr, &displacement, pSymbol)) {
        // Get the module name or full path for the address
        std::string moduleName = GetModuleNameFromAddress(addr, hProcess, verbose);

        // Format displacement as hex
        std::stringstream ss;
        ss << std::hex << "0x" << displacement;

        return moduleName + "!" + pSymbol->Name + "+" + ss.str();
    }
    else {
        // If SymFromAddr fails, fallback to showing the module name + offset
        std::string moduleName = GetModuleNameFromAddress(addr, hProcess, verbose);
        if (moduleName != "Unknown Module") {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, GetModuleHandleA(moduleName.c_str()), &modInfo, sizeof(MODULEINFO))) {
                // Calculate offset from the base of the module
                DWORD64 offset = (DWORD64)addr - (DWORD64)modInfo.lpBaseOfDll;

                // Format offset as hex
                std::stringstream ss;
                ss << std::hex << "0x" << offset;

                return moduleName + "+0x" + ss.str();
            }
        }
        return "Unknown";
    }
}


void PrintStackTrace(HANDLE hProcess, HANDLE hThread, int maxFrames, bool showParams) {
    
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;

    if (SuspendThread(hThread) == (DWORD)-1) {
        std::cerr << "Failed to suspend thread.\n";
        return;
    }

    if (!GetThreadContext(hThread, &context)) {
        std::cerr << "Failed to get thread context.\n";
        ResumeThread(hThread);
        return;
    }
    
    STACKFRAME64 stackFrame = {};
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    
#ifdef _M_X64
    stackFrame.AddrPC.Offset = context.Rip;  // Instruction Pointer
    stackFrame.AddrFrame.Offset = context.Rbp;  // Frame Pointer
    stackFrame.AddrStack.Offset = context.Rsp;  // Stack Pointer
#else
    // Add x86 support here if needed
#endif
    
    DWORD imageType;
#ifdef _M_X64
    imageType = IMAGE_FILE_MACHINE_AMD64;
#else
    imageType = IMAGE_FILE_MACHINE_I386;
#endif
    //here
    int frameNumber = 1;

    for (int frameNum = 0; frameNum < maxFrames; ++frameNum) {
        
        if (!StackWalk64(
            imageType, hProcess, hThread, &stackFrame, &context,
            NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }
        
        // Resolve the function name
        DWORD64 displacement = 0;
        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        std::cout << "----------------------------------------------------\n";
        std::cout << "Frame #" << frameNum << ":\n";

        // Print the return address (instruction pointer at the time of the call)
        std::cout << "Return Address: 0x" << std::hex << stackFrame.AddrPC.Offset << std::dec;
        
        if (SymFromAddr(hProcess, stackFrame.AddrPC.Offset, &displacement, pSymbol)) {
            std::cout << " (" << pSymbol->Name << "+0x" << std::hex << displacement << std::dec << ")";
        }
        std::cout << "\n";

        // Print parameters and stack variables, by reading them from the memory
        if (showParams) {
            PrintFunctionParameters(context, hProcess, stackFrame);
        }

        // Program Counter (PC) or Instruction Pointer
        std::cout << "    Instruction Pointer (PC/RIP): 0x" << std::hex << stackFrame.AddrPC.Offset << std::dec << "\n";

        // Frame Pointer (FP)
        std::cout << "    Frame Pointer (FP/RBP): 0x" << std::hex << stackFrame.AddrFrame.Offset << std::dec << "\n";

        // Stack Pointer (SP)
        std::cout << "    Stack Pointer (SP/RSP): 0x" << std::hex << stackFrame.AddrStack.Offset << std::dec << "\n";

        // Local variables are typically below the frame pointer (RBP)
        // Assuming `rbp` is correctly set to the base pointer (saved RBP)
        DWORD64 localVariableSpace = 0;
        if (stackFrame.AddrFrame.Offset > context.Rsp) {
            localVariableSpace = stackFrame.AddrFrame.Offset - context.Rsp;
            std::cout << "    Local Variables:\n";
            std::cout << "      Stack space for local variables: " << localVariableSpace << " bytes\n";
        }
        else {
            std::cout << "    Local Variables:\n";
            std::cout << "      Unable to determine local variable space (RSP > RBP).\n";
        }
        
    }
    ResumeThread(hThread);;
}

// Function to refresh the stack trace periodically
void RefreshStackTrace(HANDLE hProcess, HANDLE hThread, int interval, bool verbose) {
    while (true) {
        system("cls"); // Clear the screen
        PrintStackTrace(hProcess, hThread, 5, true); // PARAMETERS !!
        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }
}

// Function to list threads of a process
std::vector<DWORD> ListThreads(DWORD pid) {
    std::vector<DWORD> threadIds;
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed.\n";
        return threadIds;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        std::cerr << "Thread32First failed.\n";
        CloseHandle(hThreadSnap);
        return threadIds;
    }

    do {
        if (te32.th32OwnerProcessID == pid) {
            threadIds.push_back(te32.th32ThreadID);
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return threadIds;
}


// Function to list and print threads for a given PID
void PrintThreads(HANDLE hProcess, DWORD pid, bool verbose) {
    std::cout << "Threads for PID " << pid << ":\n";
    std::vector<DWORD> threadIds = ListThreads(pid);

    for (DWORD tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!hThread) {
            std::cerr << "Failed to open thread with TID " << tid << "\n";
            continue;
        }

        void* startAddr = GetThreadStartAddress(hThread);
        if (startAddr) {
            std::string functionName = ResolveAddressToFunction(startAddr, hProcess, verbose);
            std::cout << "TID: " << tid << ", Start Address: " << startAddr << " (" << functionName << ")\n";
        }
        else {
            std::cout << "TID: " << tid << ", Start Address: Unknown\n";
        }

        CloseHandle(hThread);
    }
}


// Function to refresh the thread list periodically
void RefreshThreadList(HANDLE hProcess, DWORD pid, int interval, bool verbose) {
    while (true) {
        system("cls"); // Clear the screen
        PrintThreads(hProcess, pid, verbose);
        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }
}


int main(int argc, char* argv[]) {
    bool verbose = false;
    bool sortByAddress = false;
    bool sortByTid = false;
    DWORD tid = 0;
    DWORD pid = 0;
    int interval = 0;


    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-p" && i + 1 < argc) {
            pid = std::stoi(argv[i + 1]);
        }
        if (std::string(argv[i]) == "-t" && i + 1 < argc) {
            tid = std::stoi(argv[i + 1]);
        }
        if (std::string(argv[i]) == "-m" && i + 1 < argc) {
            interval = std::stoi(argv[i + 1]);
        }
        if (std::string(argv[i]) == "-V") {
            verbose = true;
        }
        if (std::string(argv[i]) == "-oA") {
            sortByAddress = true;
        }
        if (std::string(argv[i]) == "-oI") {
            sortByTid = true;
        }
    }

    if (pid == 0) {
        std::cerr << "Usage: " << argv[0] << " -p <PID> [-t <TID>] [-m <n secs>] [-oA] [-oI] [-V]\n";
        exit(1);
    }


    // Initialize symbols for resolving addresses
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process with PID " << pid << "\n";
        return 1;
    }

    if (!SymInitialize(hProcess, "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols", TRUE)) {
        std::cerr << "Failed to initialize symbol handler.\n";
        CloseHandle(hProcess);
        return 1;
    }

    // If a specific thread is provided with -t
    if (tid != 0) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
        if (!hThread) {
            std::cerr << "Failed to open thread with TID " << tid << "\n";
            CloseHandle(hProcess);
            return 1;
        }

        // Reresh stack every -m seconds
        if (interval > 0) {
            std::cout << "Refreshing stack trace for TID: " << tid << " every " << interval << " seconds...\n";
            RefreshStackTrace(hProcess, hThread, interval, verbose);
        }
        else {
            std::cout << "Showing stack trace for TID: " << tid << "\n";
            PrintStackTrace(hProcess, hThread, 5, true);
        }

        CloseHandle(hThread);
        SymCleanup(hProcess);
        CloseHandle(hProcess);
        return 0; // Exit after showing stack trace for a specific thread
    }


    // List threads for the given PID
    std::vector<DWORD> threadIds = ListThreads(pid);
    if (threadIds.empty()) {
        std::cerr << "No threads found for PID " << pid << "\n";
        CloseHandle(hProcess);
        return 1;
    }

    std::vector<ThreadInfo> threads;

    for (DWORD tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!hThread) {
            //std::cerr << "Failed to open thread with TID " << tid << "\n";
            DWORD errorCode = GetLastError();
            std::cerr << "Failed to open thread with TID " << tid << ". Error Code: " << errorCode << "\n";
            continue;
        }

        void* startAddr = GetThreadStartAddress(hThread);
        threads.push_back({ tid, startAddr });

        CloseHandle(hThread);
    }

    // Sort threads based on user options
    if (sortByAddress) {
        std::sort(threads.begin(), threads.end(), [](const ThreadInfo& a, const ThreadInfo& b) {
            return a.startAddress < b.startAddress;
            });
    }
    else if (sortByTid) {
        std::sort(threads.begin(), threads.end(), [](const ThreadInfo& a, const ThreadInfo& b) {
            return a.tid < b.tid;
            });
    }


    // List threads for the given PID
    if (interval > 0) {
        std::cout << "Refreshing thread list for PID: " << pid << " every " << interval << " seconds...\n";
        RefreshThreadList(hProcess, pid, interval, verbose);
    }
    else {
        PrintThreads(hProcess, pid, verbose);

    }

    SymCleanup(hProcess);
    CloseHandle(hProcess);

    return 0;
}
