#include <iostream>
#include <netdb.h>

#include <ares.h>
#include <ares_dns.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <vector>
#include <boost/algorithm/string.hpp>

std::vector<std::string> ips = {};
std::vector<std::string> rederect = {};


std::vector<std::string> split(const std::string &str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    
    for (char ch : str) {
        if (ch == delimiter) {
            if (!token.empty()) {
                tokens.push_back(token);
                token.clear();
            }
        } else {
            token += ch;
        }
    }
    
    if (!token.empty()) {
        tokens.push_back(token);
    }
    
    return tokens;
}

// Callback function to handle the DNS response
void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen) {
    if (status != ARES_SUCCESS) {
        std::cerr << "Failed to look up SPF record: " << ares_strerror(status) << std::endl;
        return;
    }

    struct ares_txt_reply* txt_out = nullptr;
    status = ares_parse_txt_reply(abuf, alen, &txt_out);
    if (status != ARES_SUCCESS) {
        std::cerr << "Failed to parse TXT record: " << ares_strerror(status) << std::endl;
        return;
    }

    struct ares_txt_reply* txt_curr = txt_out;
    std::vector<std::vector<std::string>> end;
    std::vector<std::string> result;
    while (txt_curr) {
        std::string txt_record((char*)txt_curr->txt, txt_curr->length);
        if (txt_record.find("v=spf1") != std::string::npos) {
            std::vector<std::string> tmp = split(txt_record, ' ');
            result.insert(result.end(), tmp.begin(), tmp.end());
        }
        txt_curr = txt_curr->next;
    }

    for (int i = 0; i < result.size(); i++) {
        std::vector<std::string> tmp = split(result[i], '=');
        int ag = result[i].find(':');
        std::string data, start;

        if (ag != std::string::npos) {
            data = result[i].substr(ag+1, result[i].length()-1);
            start = result[i].substr(0, ag);
        } else {
            data = "";
            start = "";
        }
        if (tmp[0] == "ip4" || tmp[0] == "ip6"){
            ips.push_back(tmp[1]);
            continue;
        }
        if (start == "ip4" || start == "ip6"){
            ips.push_back(data);
            continue;
        }
        if (start == "include") {
            rederect.push_back(data);
        }
        if (tmp[0] == "redirect") {
            rederect.push_back(tmp[1]);
        }
    }

    for (int i = 0; i < end.size(); i++) {
        if (end[i][0] == "redirect" || end[i][0] == "include") {
            rederect.push_back(end[i][1]);
        } else if (end[i][0] == "ipv4") {
        }
    }

    ares_free_data(txt_out);
}

std::vector<std::string> get_ips(char* domain) {
    ares_channel channel;
    int status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        std::cerr << "Failed to initialize c-ares library: " << ares_strerror(status) << std::endl;
        ips = {};
        return ips;
    }

    status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        std::cerr << "Failed to initialize c-ares channel: " << ares_strerror(status) << std::endl;
        ares_library_cleanup();
        ips = {};
        return ips;
    }

    // Perform the DNS query for TXT records
    ares_query(channel, domain, ns_c_in, ns_t_txt, callback, nullptr);

    // Wait for the query to complete
    // first request
    for (;;) {
        fd_set read_fds, write_fds;
        int nfds;
        struct timeval* tvp, tv;

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0) {
            break;
        }

        tvp = ares_timeout(channel, nullptr, &tv);
        select(nfds, &read_fds, &write_fds, nullptr, tvp);
        ares_process(channel, &read_fds, &write_fds);
    }

    while (rederect.size() > 0) {
        const char* tmp = rederect[0].c_str();
        ares_query(channel, tmp, ns_c_in, ns_t_txt, callback, nullptr);
        for (;;) {
            fd_set read_fds, write_fds;
            int nfds;
            struct timeval* tvp, tv;

            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            nfds = ares_fds(channel, &read_fds, &write_fds);
            if (nfds == 0) {
                break;
            }

            tvp = ares_timeout(channel, nullptr, &tv);
            select(nfds, &read_fds, &write_fds, nullptr, tvp);
            ares_process(channel, &read_fds, &write_fds);
        }
        rederect.erase(rederect.begin());
    }

    ares_destroy(channel);
    ares_library_cleanup();
    return ips;
}