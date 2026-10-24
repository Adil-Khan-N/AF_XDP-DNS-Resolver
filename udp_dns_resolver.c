#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdint.h>

#define BUF_SIZE 512
#define PORT 5353
#define UPSTREAM_IP "8.8.8.8"
#define UPSTREAM_PORT 53
#define MAX_EVENTS 10
#define MAX_CONCURRENT_QUERIES 65536

// ---------------------------------------------------------
// 1. PROTOCOL & STATE STRUCTURES
// ---------------------------------------------------------
struct dns_header {
    uint16_t id;
    uint8_t rd : 1; uint8_t tc : 1; uint8_t aa : 1; uint8_t opcode : 4; uint8_t qr : 1;
    uint8_t rcode : 4; uint8_t cd : 1; uint8_t ad : 1; uint8_t z : 1; uint8_t ra : 1;
    uint16_t q_count; uint16_t ans_count; uint16_t auth_count; uint16_t add_count;
};

// The O(1) State Table
struct query_state {
    uint8_t active;
    uint16_t original_txid;
    struct sockaddr_in client_addr;
    socklen_t client_len;
};

struct query_state state_table[MAX_CONCURRENT_QUERIES] = {0};
uint16_t current_txid = 0; // Simple counter for upstream transaction IDs

//Updating skip_qname:  Unbounded Pointer Arithmetic (Memory Safety) The skip_qname function blindly trusts the data in the packet.
unsigned char* skip_qname(unsigned char* reader, const unsigned char* buffer_end) {
    while (reader < buffer_end && *reader != 0) { 
        unsigned char* next_position = reader + (*reader) + 1;

        if(next_position >= buffer_end) return NULL;    

        reader = next_position;
    }

    if (reader >= buffer_end) {
        return NULL;
    }
    return reader + 1;
}

int main() {
    int client_fd, upstream_fd, epoll_fd;
    struct sockaddr_in server_addr, upstream_addr, client_addr;
    unsigned char buffer[BUF_SIZE];

    // ---------------------------------------------------------
    // 2. SOCKET & EPOLL SETUP
    // ---------------------------------------------------------
    client_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (client_fd < 0) {
        perror("Failed to create client socket");
        exit(EXIT_FAILURE);
    }

    upstream_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (upstream_fd < 0) {
        perror("Failed to create upstream socket");
        exit(EXIT_FAILURE);
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    if (bind(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("FATAL: Failed to bind client socket (is port 5353 already in use?)");
        exit(EXIT_FAILURE);
    }

    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(UPSTREAM_PORT);

    // Safely convert the IP string to binary format
    int pton_result = inet_pton(AF_INET, UPSTREAM_IP, &upstream_addr.sin_addr);
    if (pton_result == 0) {
        fprintf(stderr, "FATAL: Upstream IP '%s' is not a valid IPv4 address\n", UPSTREAM_IP);
        exit(EXIT_FAILURE);
    } else if (pton_result < 0) {
        perror("FATAL: inet_pton failed (system error)");
        exit(EXIT_FAILURE);
    }

    // Initialize epoll
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("FATAL: Failed to create epoll file descriptor");
        exit(EXIT_FAILURE);
    }
    struct epoll_event ev, events[MAX_EVENTS];
    
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        perror("FATAL: Failed to add client socket to epoll");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN;
    ev.data.fd = upstream_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstream_fd, &ev) < 0) {
        perror("FATAL: Failed to add upstream socket to epoll");
        exit(EXIT_FAILURE);
    }

    printf("Epoll Resolver listening on port %d, forwarding to %s...\n", PORT, UPSTREAM_IP);

    // ---------------------------------------------------------
    // 3. MAIN EVENT LOOP
    // ---------------------------------------------------------
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        
        for (int i = 0; i < nfds; i++) {
            int active_fd = events[i].data.fd;

            // ====================================================
            // PATH A: NEW QUERY FROM CLIENT
            // ====================================================
            if (active_fd == client_fd) {
                socklen_t client_len = sizeof(client_addr);
                int bytes_read = recvfrom(client_fd, buffer, BUF_SIZE, 0, 
                                         (struct sockaddr *)&client_addr, &client_len);
                if(bytes_read < 0) continue;
                if ((size_t)bytes_read < sizeof(struct dns_header)) continue;

                struct dns_header *dns = (struct dns_header *)buffer;
                if (dns->qr != 0 || dns->opcode != 0) continue; 

                unsigned char* buffer_end = buffer + bytes_read;
                unsigned char *qtype_ptr = skip_qname(&buffer[sizeof(struct dns_header)], buffer_end);

                // If skip_qname failed, or if there isn't enough room left for QTYPE (2 bytes) 
                // and QCLASS (2 bytes), drop the packet to prevent buffer over-reads.
                if(qtype_ptr == NULL || (qtype_ptr + 4) > buffer_end){
                    continue;
                }

                // Safely read QTYPE byte-by-byte to prevent SIGBUS crashes on unaligned memory
                uint16_t qtype = (qtype_ptr[0] << 8) | qtype_ptr[1];

                // FAST-PATH REJECTION
                if (qtype != 1 && qtype != 28) {
                    dns->qr = 1; dns->rcode = 4; dns->ra = 1;
                    sendto(client_fd, buffer, bytes_read, 0, (struct sockaddr *)&client_addr, client_len);
                    continue;
                }

                // STATE ALLOCATION & FORWARDING
                uint16_t new_txid;
                int max_attempts = 100; // Prevent infinite loop if the table is completely saturated
                int found_slot = 0;

                // Probe forward to find an empty slot
                for (int attempt = 0; attempt < max_attempts; attempt++) {
                    new_txid = current_txid++;

                    if (state_table[new_txid].active == 0) {
                        found_slot = 1;
                        break;
                    }
                }

                // If we couldn't find a free slot after 100 attempts, the resolver is overloaded.
                // Drop this query to protect the system.
                if (!found_slot) {
                    continue; 
                }
                
                // Save client state in O(1) table
                state_table[new_txid].active = 1;
                state_table[new_txid].original_txid = ntohs(dns->id);
                state_table[new_txid].client_addr = client_addr;
                state_table[new_txid].client_len = client_len;

                // Overwrite ID and send to 8.8.8.8
                dns->id = htons(new_txid); 
                sendto(upstream_fd, buffer, bytes_read, 0, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));
            }

            // ====================================================
            // PATH B: RESPONSE FROM UPSTREAM (8.8.8.8)
            // ====================================================
            else if (active_fd == upstream_fd) {
                struct sockaddr_in sender_addr;
                socklen_t sender_len = sizeof(sender_addr);

                int bytes_read = recvfrom(upstream_fd, buffer, BUF_SIZE, 0, (struct sockaddr *)&sender_addr, &sender_len);
                if((size_t)bytes_read < 0) continue;

                // SECURITY VALIDATION: The "Anti-Spoofing" Check
                // If the IP or the Port does not perfectly match our configured upstream (8.8.8.8:53),
                // it is either a spoofed attack or background internet noise. Drop it immediately.
                if (sender_addr.sin_addr.s_addr != upstream_addr.sin_addr.s_addr || 
                    sender_addr.sin_port != upstream_addr.sin_port) {
                    // fprintf(stderr, "dropped spoofed packet from %s:%d\n",
                    // inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port));
                    continue;
                }

                if ((size_t)bytes_read < sizeof(struct dns_header)) continue;

                struct dns_header *dns = (struct dns_header *)buffer;

                if (dns->qr != 1) {
                    continue; 
                }

                uint16_t resp_txid = ntohs(dns->id);

                // Check O(1) state table
                if (state_table[resp_txid].active) {
                    // Restore original client's ID
                    dns->id = htons(state_table[resp_txid].original_txid);
                    
                    // Route back to original client
                    sendto(client_fd, buffer, bytes_read, 0, 
                           (struct sockaddr *)&state_table[resp_txid].client_addr, 
                           state_table[resp_txid].client_len);
                    
                    // Clear state slot
                    state_table[resp_txid].active = 0;
                }
            }
        }
    }
    return 0;
}
