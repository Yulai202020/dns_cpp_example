#include <iostream>
#include <vector>
#include <cstring>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>

void query_mx_records(const std::string& domain) {
    unsigned char query_buffer[NS_PACKETSZ]; // Buffer for the DNS query
    unsigned char answer_buffer[NS_PACKETSZ]; // Buffer for the DNS answer

    // Initialize resolver
    res_init();

    // Modify the resolver to use the specified DNS server (8.8.8.8)
    _res.nscount = 1; // Use only one nameserver
    _res.nsaddr_list[0].sin_addr.s_addr = inet_addr("8.8.8.8");
    _res.nsaddr_list[0].sin_family = AF_INET;
    _res.nsaddr_list[0].sin_port = htons(53);

    int query_length = res_query(domain.c_str(), C_IN, ns_t_mx, query_buffer, sizeof(query_buffer));

    if (query_length < 0) {
        std::cerr << "DNS query failed" << std::endl;
        return;
    }

    ns_msg handle;
    if (ns_initparse(query_buffer, query_length, &handle) < 0) {
        std::cerr << "Failed to parse DNS response" << std::endl;
        return;
    }

    int answer_count = ns_msg_count(handle, ns_s_an);

    std::cout << "MX records for " << domain << ":" << std::endl;

    for (int i = 0; i < answer_count; ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
            if (ns_rr_type(rr) == ns_t_mx) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                uint16_t preference = ntohs(*(uint16_t*)rdata);
                char exchange[NS_MAXDNAME];

                if (dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata + sizeof(uint16_t), exchange, sizeof(exchange)) >= 0) {
                    std::cout << "Preference: " << preference << ", Exchange: " << exchange << std::endl;
                }
            }
        } else {
            std::cerr << "Failed to parse record " << i << std::endl;
        }
    }
}

void query_ip_address(const std::string& domain, bool use_custom_dns = false, const std::string& custom_dns = "8.8.8.8", std::string type = "a") {
    unsigned char query_buffer[NS_PACKETSZ]; // Buffer for the DNS query
    unsigned char answer_buffer[NS_PACKETSZ]; // Buffer for the DNS answer

    // Initialize resolver
    res_init();

    // Optionally modify the resolver to use the specified DNS server
    if (use_custom_dns) {
        _res.nscount = 1; // Use only one nameserver
        _res.nsaddr_list[0].sin_addr.s_addr = inet_addr(custom_dns.c_str());
        _res.nsaddr_list[0].sin_family = AF_INET;
        _res.nsaddr_list[0].sin_port = htons(53);
    }
    
    int query_length;
    
    if (type == "mx")
        query_length = res_query(domain.c_str(), C_IN, ns_t_mx, query_buffer, sizeof(query_buffer));
    else if (type == "a")
        query_length = res_query(domain.c_str(), C_IN, ns_t_a, query_buffer, sizeof(query_buffer));
    else if (type == "any")
        query_length = res_query(domain.c_str(), C_IN, ns_t_any, query_buffer, sizeof(query_buffer));
    else if (type == "aaaa")
        query_length = res_query(domain.c_str(), C_IN, ns_t_aaaa, query_buffer, sizeof(query_buffer));
    else if (type == "cname")
        query_length = res_query(domain.c_str(), C_IN, ns_t_cname, query_buffer, sizeof(query_buffer));
    else if (type == "caa")
        query_length = res_query(domain.c_str(), C_IN, ns_t_caa, query_buffer, sizeof(query_buffer));
    else if (type == "ns")
        query_length = res_query(domain.c_str(), C_IN, ns_t_ns, query_buffer, sizeof(query_buffer));
    else if (type == "srv")
        query_length = res_query(domain.c_str(), C_IN, ns_t_srv, query_buffer, sizeof(query_buffer));
    else if (type == "txt")
        query_length = res_query(domain.c_str(), C_IN, ns_t_txt, query_buffer, sizeof(query_buffer));

    if (query_length < 0) {
        std::cerr << "DNS query failed" << std::endl;
        return;
    }

    ns_msg handle;
    if (ns_initparse(query_buffer, query_length, &handle) < 0) {
        std::cerr << "Failed to parse DNS response" << std::endl;
        return;
    }

    int answer_count = ns_msg_count(handle, ns_s_an);

    std::cout << "DNS answer for " << domain << ":" << std::endl;

    for (int i = 0; i < answer_count; ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
            if (ns_rr_type(rr) == ns_t_a) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                char ip_address[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, rdata, ip_address, sizeof(ip_address));
                std::cout << "  A (IPv4): " << ip_address << std::endl;
            } else if (ns_rr_type(rr) == ns_t_mx) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                uint16_t preference = ntohs(*(uint16_t*)rdata);
                char exchange[NS_MAXDNAME];
                dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata + sizeof(uint16_t), exchange, sizeof(exchange));
                std::cout << "  MX: " << exchange << " (Preference: " << preference << ")" << std::endl;
            } else if (ns_rr_type(rr) == ns_t_cname) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                char cname[NS_MAXDNAME];
                dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata, cname, sizeof(cname));
                std::cout << "  CNAME: " << cname << std::endl;
            } else if (ns_rr_type(rr) == ns_t_any) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                char name[NS_MAXDNAME];
                dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata, name, sizeof(name));
                std::cout << "  Type: " << ns_rr_type(rr) << ", Data: " << name << std::endl;
            } else if (ns_rr_type(rr) == ns_t_aaaa) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                std::cout << "  AAAA (IPv6): ";
                for (int j = 0; j < ns_rr_rdlen(rr); ++j) {
                    std::cout << std::hex << static_cast<int>(rdata[j]);
                    if (j < ns_rr_rdlen(rr) - 1) {
                        std::cout << ":";
                    }
                }
                std::cout << std::dec << std::endl;
            } else if (ns_rr_type(rr) == ns_t_cname) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                char cname[NS_MAXDNAME];
                dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata, cname, sizeof(cname));
                std::cout << "  CNAME: " << cname << std::endl;
            } else if (ns_rr_type(rr) == ns_t_caa) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                std::cout << "  Flags: " << static_cast<int>(rdata[0]) << ", ";
                unsigned char tag_len = rdata[1];
                std::cout << "Tag: ";
                for (int j = 2; j < 2 + tag_len; ++j) {
                    std::cout << rdata[j];
                }
                std::cout << ", Value: ";
                for (int j = 2 + tag_len; j < ns_rr_rdlen(rr); ++j) {
                    std::cout << rdata[j];
                }
                std::cout << std::endl;
            } else if (ns_rr_type(rr) == ns_t_ns) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                char nsname[NS_MAXDNAME];
                if (dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata, nsname, sizeof(nsname)) >= 0) {
                    std::cout << "  NS: " << nsname << std::endl;
                } else {
                    std::cerr << "Failed to expand domain name" << std::endl;
                }
            } else if (ns_rr_type(rr) == ns_t_txt) {
                const unsigned char* rdata = ns_rr_rdata(rr);
                int txt_len = rdata[0];
                std::string txt_record(reinterpret_cast<const char*>(rdata + 1), txt_len);
                std::cout << "  TXT: " << txt_record << std::endl;
            } else {
                std::cout << "  Unknown record type" << std::endl;
            }
        } else {
            std::cerr << "Failed to parse record " << i << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc == 4) {
        query_ip_address(argv[1], true, argv[2], argv[3]);
    }
    else {
        query_ip_address(argv[1], false, "", argv[2]);
    }

    return 0;
}
