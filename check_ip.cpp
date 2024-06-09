#include <iostream>
#include "./spf-lib.cpp"

bool isIpInRange(const std::string& ip, const std::string& baseIp, int mask) {
    struct in_addr addr, baseAddr;

    // Convert input IP and base IP to integer format
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return false;
    }
    if (inet_pton(AF_INET, baseIp.c_str(), &baseAddr) != 1) {
        return false;
    }

    uint32_t ipInt = ntohl(addr.s_addr);
    uint32_t baseIpInt = ntohl(baseAddr.s_addr);

    // Calculate the subnet mask
    uint32_t subnetMask = 0xFFFFFFFF << (32 - mask);

    // Calculate the network address for the base IP and the input IP
    uint32_t baseNetwork = baseIpInt & subnetMask;
    uint32_t ipNetwork = ipInt & subnetMask;

    // Check if the network addresses match
    return baseNetwork == ipNetwork;
}

bool isIpv6InRange(const std::string& ip, const std::string& baseIp, int mask) {
    struct in6_addr addr, baseAddr;

    // Convert input IP and base IP to integer format
    if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1) {
        return false;
    }
    if (inet_pton(AF_INET6, baseIp.c_str(), &baseAddr) != 1) {
        return false;
    }

    // Convert addresses to arrays of bytes
    uint8_t* ipBytes = addr.s6_addr;
    uint8_t* baseIpBytes = baseAddr.s6_addr;

    // Calculate the number of full bytes and remaining bits in the subnet mask
    int fullBytes = mask / 8;
    int remainingBits = mask % 8;

    // Check full bytes
    for (int i = 0; i < fullBytes; ++i) {
        if (ipBytes[i] != baseIpBytes[i]) {
            return false;
        }
    }

    // Check remaining bits
    if (remainingBits > 0) {
        uint8_t maskByte = (0xFF << (8 - remainingBits)) & 0xFF;
        if ((ipBytes[fullBytes] & maskByte) != (baseIpBytes[fullBytes] & maskByte)) {
            return false;
        }
    }

    return true;
}

int main(int argc, char* argv[]) {
    char* domain = argv[1];
    std::string ip_to_check = argv[2];
    std::vector<std::string> ips = get_ips(domain);

    std::vector<std::string>::iterator it = std::find(ips.begin(), ips.end(), ip_to_check);
    bool a = false;
    if (it != ips.end()) {
        a = true;
    } else {
        for (int i = 0; i < ips.size(); i++) {
            std::string ip = split(ips[i], '/')[0];
            int mask = std::stoi(split(ips[i], '/')[1]);
            if (isIpv6InRange(ip_to_check, ip, mask)) {

            }
            if (isIpInRange(ip_to_check, ip, mask)) {
                a = true;
                break;
            } else {
                a = false;
                continue;
            }
        }
    }

    if (a) {
        std::cout << "IP was found" << "\n";
    } else {
        std::cout << "IP wasn't found" << "\n";
    }
    return 0;
    
}