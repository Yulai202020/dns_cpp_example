#include <iostream>
#include "./spf-lib.cpp"

int main(int argc, char* argv[]) {
    char* domain = argv[1];
    std::vector<std::string> ips = get_ips(domain);

    for (int i = 0; i < ips.size(); i++) {
        std::cout << ips[i] << std::endl;
    }
    return 0;
}