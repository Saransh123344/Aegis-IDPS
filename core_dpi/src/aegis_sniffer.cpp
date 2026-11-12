#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string>
#include <algorithm>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
        
        int header_size = sizeof(struct ether_header) + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
        int payload_length = header->caplen - header_size;
        
        if (payload_length > 0) {
            const u_char *payload = packet + header_size;
            std::string payload_str(reinterpret_cast<const char*>(payload), payload_length);
            
            // Explicitly hunt for plaintext SQLi, HTTP traffic, OR URL-encoded apostrophes (%27)
            if (payload_str.find("HTTP") != std::string::npos || 
                payload_str.find("'1'='1") != std::string::npos || 
                payload_str.find("%27") != std::string::npos) {
                
                // Expand capture window to 600 characters to prevent chopping off the Docker API JSON
                size_t capture_size = std::min((size_t)600, payload_str.length());
                std::string clean_payload = payload_str.substr(0, capture_size);
                
                // Clean up the payload string to prevent terminal formatting breaks
                clean_payload.erase(std::remove(clean_payload.begin(), clean_payload.end(), '\n'), clean_payload.end());
                clean_payload.erase(std::remove(clean_payload.begin(), clean_payload.end(), '\r'), clean_payload.end());

                // Print exactly what the Bash script and Python AI are looking for
                std::cout << "SRC: " << inet_ntoa(ip_header->ip_src) 
                          << " | DST: " << inet_ntoa(ip_header->ip_dst) 
                          << " | PROTOCOL: TCP | L7_PAYLOAD: " << clean_payload << std::endl;
                
                // Force the memory buffer to push to the bash script immediately
                std::cout.flush();
            }
        }
    }
}

int main() {
    // Disable OS-level block buffering entirely
    setvbuf(stdout, NULL, _IONBF, 0);
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    std::string target_device = "any";
    std::cout << "[AegisNet] Binding DPI Engine to interface: " << target_device << std::endl;

    pcap_t *handle = pcap_open_live(target_device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << target_device << ": " << errbuf << std::endl;
        return 1;
    }

    std::cout << "[AegisNet] DPI Engine Active. Sniffing L3-L7 traffic..." << std::endl;
    
    pcap_loop(handle, 0, process_packet, nullptr);
    
    pcap_close(handle);
    pcap_freealldevs(interfaces);
    return 0;
}