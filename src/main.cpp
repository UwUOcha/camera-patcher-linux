#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <vector>
#include <iomanip>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
    std::string perms;
    std::string path;
};

class ProcessMemory {
private:
    pid_t pid;
    int memFd;

public:
    ProcessMemory() : pid(-1), memFd(-1) {}

    ~ProcessMemory() {
        if (memFd >= 0) {
            close(memFd);
        }
    }

    bool attach(pid_t target_pid) {
        pid = target_pid;

        // Открываем /proc/PID/mem напрямую
        std::string memPath = "/proc/" + std::to_string(pid) + "/mem";
        memFd = open(memPath.c_str(), O_RDWR);

        if (memFd < 0) {
            std::cerr << "Failed to open " << memPath << ": " << strerror(errno) << std::endl;

            if (errno == EACCES) {
                std::cerr << "\n=== TROUBLESHOOTING ===\n";
                std::cerr << "Permission denied.\n\n";
                std::cerr << "This can happen if:\n";
                std::cerr << "1. Game runs in a container\n";
                std::cerr << "2. SELinux/AppArmor is blocking access\n";
                std::cerr << "3. Process is in different namespace\n\n";
                std::cerr << "========================\n";
            }

            return false;
        }

        std::cout << "✅ Successfully opened /proc/" << pid << "/mem\n";
        return true;
    }

    template<typename T>
    bool read(uintptr_t address, T& value) {
        if (pread(memFd, &value, sizeof(T), address) != sizeof(T)) {
            return false;
        }
        return true;
    }

    template<typename T>
    bool write(uintptr_t address, const T& value) {
        if (pwrite(memFd, &value, sizeof(T), address) != sizeof(T)) {
            return false;
        }
        return true;
    }

    bool readBytes(uintptr_t address, size_t size, std::vector<uint8_t>& buffer) {
        buffer.resize(size);
        ssize_t nread = pread(memFd, buffer.data(), size, address);
        return nread == static_cast<ssize_t>(size);
    }

    std::vector<MemoryRegion> getMemoryRegions() {
        std::vector<MemoryRegion> regions;
        std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream mapsFile(mapsPath);

        if (!mapsFile.is_open()) return regions;

        std::string line;
        while (std::getline(mapsFile, line)) {
            MemoryRegion region;
            size_t dashPos = line.find('-');
            size_t spacePos = line.find(' ');

            if (dashPos == std::string::npos || spacePos == std::string::npos) continue;

            region.start = std::stoull(line.substr(0, dashPos), nullptr, 16);
            region.end = std::stoull(line.substr(dashPos + 1, spacePos - dashPos - 1), nullptr, 16);
            region.perms = line.substr(spacePos + 1, 4);

            size_t pathPos = line.find('/');
            if (pathPos != std::string::npos) {
                region.path = line.substr(pathPos);
            }

            regions.push_back(region);
        }

        return regions;
    }
};

std::vector<pid_t> findProcessesByName(const std::string& processName) {
    std::vector<pid_t> pids;
    DIR* dir = opendir("/proc");
    if (!dir) return pids;

    pid_t myPid = getpid();
    pid_t parentPid = getppid();

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;

        pid_t pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        // Пропускаем себя и родительский процесс (sudo)
        if (pid == myPid || pid == parentPid) continue;

        std::string cmdlinePath = "/proc/" + std::string(entry->d_name) + "/cmdline";
        std::ifstream cmdlineFile(cmdlinePath);
        if (!cmdlineFile.is_open()) continue;

        std::string cmdline;
        std::getline(cmdlineFile, cmdline);

        // Пропускаем если это сам patcher
        if (cmdline.find("camera_patcher") != std::string::npos) continue;

        // Ищем только реальные процессы dota2
        if (cmdline.find(processName) != std::string::npos) {
            pids.push_back(pid);
        }
    }

    closedir(dir);
    return pids;
}

uintptr_t scanForCameraAddress(ProcessMemory& mem, const MemoryRegion& region, float targetDistance) {
    const size_t CHUNK_SIZE = 0x10000;
    std::vector<uint8_t> buffer;

    for (uintptr_t addr = region.start; addr < region.end - sizeof(float); addr += CHUNK_SIZE) {
        size_t readSize = std::min(CHUNK_SIZE, static_cast<size_t>(region.end - addr));

        if (!mem.readBytes(addr, readSize, buffer)) continue;

        for (size_t i = 0; i <= readSize - sizeof(float); i += 4) {
            float value;
            memcpy(&value, &buffer[i], sizeof(float));

            if (value >= targetDistance - 100 && value <= targetDistance + 100) {
                uintptr_t foundAddr = addr + i;

                float directValue;
                if (mem.read(foundAddr, directValue)) {
                    if (std::abs(directValue - targetDistance) < 100) {
                        std::cout << "  Found at: 0x" << std::hex << foundAddr
                                  << " (value: " << std::dec << directValue << ")" << std::endl;
                        return foundAddr;
                    }
                }
            }
        }
    }

    return 0;
}

void printMenu() {
    std::cout << "\n=== Camera Patcher (Direct Memory Access) ===\n";
    std::cout << "[1] Scan for camera address\n";
    std::cout << "[2] Write to specific address\n";
    std::cout << "[3] Read from specific address\n";
    std::cout << "[4] Set distance by offset\n";
    std::cout << "[5] Show memory regions\n";
    std::cout << "[0] Exit\n";
    std::cout << "\n=> ";
}

void showMemoryRegions(const std::vector<MemoryRegion>& regions) {
    std::cout << "\n=== Memory Regions ===\n";
    for (const auto& region : regions) {
        if (region.path.find("client.so") != std::string::npos ||
            region.path.find("libclient") != std::string::npos ||
            region.path.find("server.so") != std::string::npos) {
            std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << region.start
                      << " - 0x" << std::setw(16) << region.end << std::dec
                      << " [" << region.perms << "] " << region.path << std::endl;
        }
    }
}

int main() {
    std::cout << "Camera Patcher (Direct /proc/mem access)\n";
    std::cout << "================================================\n\n";

    if (geteuid() != 0) {
        std::cerr << "⚠️  WARNING: Not running as root!\n";
        std::cerr << "This program requires root privileges.\n";
        std::cerr << "Please run: sudo ./camera_patcher\n\n";
        return 1;
    }

    std::cout << "Searching for game processes...\n";

    auto pids = findProcessesByName("dota2");
    if (pids.empty()) {
        std::cerr << "ERROR: No game process found!\n";
        std::cerr << "Make sure Dota 2 is running.\n";
        return 1;
    }

    std::cout << "Found " << pids.size() << " game process(es):\n";
    for (size_t i = 0; i < pids.size(); i++) {
        std::cout << "  [" << i << "] PID: " << pids[i];

        // Показываем размер памяти для определения основного процесса
        std::string statusPath = "/proc/" + std::to_string(pids[i]) + "/status";
        std::ifstream statusFile(statusPath);
        if (statusFile.is_open()) {
            std::string line;
            while (std::getline(statusFile, line)) {
                if (line.find("VmRSS:") == 0) {
                    std::cout << " - Memory: " << line.substr(7);
                    break;
                }
            }
        }

        // Показываем командную строку
        std::ifstream cmdline("/proc/" + std::to_string(pids[i]) + "/cmdline");
        if (cmdline.is_open()) {
            std::string cmd;
            std::getline(cmdline, cmd);
            // Заменяем нулевые байты на пробелы
            for (char& c : cmd) {
                if (c == '\0') c = ' ';
            }
            if (cmd.length() > 80) cmd = cmd.substr(0, 77) + "...";
            std::cout << "\n      " << cmd;
        }
        std::cout << std::endl;
    }

    pid_t dotaPid;
    if (pids.size() == 1) {
        dotaPid = pids[0];
        std::cout << "\nAuto-selected PID: " << dotaPid << std::endl;
    } else if (pids.size() == 0) {
        std::cerr << "No valid game process found!\n";
        std::cerr << "Make sure you're in a game (not just the menu)\n";
        return 1;
    } else {
        std::cout << "\n💡 Tip: Choose the process with the LARGEST memory usage\n";
        std::cout << "Select process [0-" << pids.size()-1 << "]: ";
        int choice;
        std::cin >> choice;
        if (choice < 0 || choice >= static_cast<int>(pids.size())) {
            std::cerr << "Invalid choice\n";
            return 1;
        }
        dotaPid = pids[choice];
    }

    ProcessMemory mem;
    if (!mem.attach(dotaPid)) {
        std::cerr << "ERROR: Failed to attach.\n";
        return 1;
    }

    std::cout << "Analyzing memory regions...\n";

    auto regions = mem.getMemoryRegions();
    std::vector<MemoryRegion> clientRegions;

    std::cout << "Looking for game modules...\n";

    // Ищем различные варианты модулей
    for (const auto& region : regions) {
        bool isGameModule = false;

        // Проверяем различные варианты имен
        if (region.path.find("client") != std::string::npos ||
            region.path.find("dota2") != std::string::npos ||
            region.path.find("game/bin") != std::string::npos ||
            region.path.find("libclient") != std::string::npos) {

            // Показываем все найденные модули
            if (region.perms.find('w') != std::string::npos) {
                std::cout << "  Found: " << region.path << " [" << region.perms << "]\n";
                clientRegions.push_back(region);
                isGameModule = true;
            }
        }
    }

    if (clientRegions.empty()) {
        std::cerr << "\nERROR: No writable game modules found!\n";
        std::cerr << "\nShowing all mapped files:\n";

        // Показываем все регионы для отладки
        for (const auto& region : regions) {
            if (!region.path.empty() && region.path[0] == '/') {
                std::cout << "  " << region.path << " [" << region.perms << "]\n";
            }
        }

        std::cerr << "\nMake sure you are IN A GAME (not in menu)!\n";
        return 1;
    }

    std::cout << "\n✅ Found " << clientRegions.size() << " writable game region(s)\n";

    int choice;
    bool running = true;
    uintptr_t lastFoundAddress = 0;

    while (running) {
        printMenu();
        std::cin >> choice;

        switch (choice) {
            case 1: {
                float currentDistance;
                std::cout << "Enter CURRENT camera distance (1134-1500): ";
                std::cin >> currentDistance;

                std::cout << "\nScanning...\n";
                for (const auto& region : clientRegions) {
                    uintptr_t found = scanForCameraAddress(mem, region, currentDistance);
                    if (found != 0) {
                        lastFoundAddress = found;
                        std::cout << "\n*** FOUND: 0x" << std::hex << found << std::dec << " ***\n";
                        break;
                    }
                }
                break;
            }

            case 2: {
                uintptr_t address;
                float value;

                if (lastFoundAddress != 0) {
                    std::cout << "Use 0x" << std::hex << lastFoundAddress << std::dec << "? (y/n): ";
                    char ans;
                    std::cin >> ans;
                    address = (ans == 'y' || ans == 'Y') ? lastFoundAddress : 0;
                }

                if (address == 0) {
                    std::cout << "Address (hex): 0x";
                    std::cin >> std::hex >> address >> std::dec;
                }

                std::cout << "Value: ";
                std::cin >> value;

                if (mem.write(address, value)) {
                    std::cout << "✅ Written " << value << " to 0x" << std::hex << address << std::dec << std::endl;
                } else {
                    std::cerr << "❌ Failed\n";
                }
                break;
            }

            case 3: {
                uintptr_t address;
                std::cout << "Address (hex): 0x";
                std::cin >> std::hex >> address >> std::dec;

                float value;
                if (mem.read(address, value)) {
                    std::cout << "Value: " << value << std::endl;
                } else {
                    std::cerr << "❌ Failed\n";
                }
                break;
            }

            case 4: {
                uintptr_t baseAddr;
                uint32_t offset;
                float value;

                std::cout << "Base (hex): 0x";
                std::cin >> std::hex >> baseAddr >> std::dec;
                std::cout << "Offset (hex): 0x";
                std::cin >> std::hex >> offset >> std::dec;
                std::cout << "Value: ";
                std::cin >> value;

                if (mem.write(baseAddr + offset, value)) {
                    std::cout << "✅ Done\n";
                } else {
                    std::cerr << "❌ Failed\n";
                }
                break;
            }

            case 5:
                showMemoryRegions(regions);
                break;

            case 0:
                running = false;
                break;
        }
    }

    return 0;
}
