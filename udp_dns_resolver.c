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

unsigned char* skip_qname(unsigned char* reader) {
    while (*reader != 0) { reader += (*reader) + 1; }
    return reader + 1;
}

int main() {
    int client_fd, upstream_fd, epoll_fd;
    struct sockaddr_in server_addr, upstream_addr, client_addr;
    unsigned char buffer[BUF_SIZE];

    // ---------------------------------------------------------
    // 2. SOCKET & EPOLL SETUP
    // ---------------------------------------------------------
    client_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    upstream_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    bind(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_addr.s_addr = inet_addr(UPSTREAM_IP);
    upstream_addr.sin_port = htons(UPSTREAM_PORT);

    // Initialize epoll
    epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];
    
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

    ev.events = EPOLLIN;
    ev.data.fd = upstream_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstream_fd, &ev);

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
                if (bytes_read < sizeof(struct dns_header)) continue;

                struct dns_header *dns = (struct dns_header *)buffer;
                if (dns->qr != 0 || dns->opcode != 0) continue; 

                unsigned char *qtype_ptr = skip_qname(&buffer[sizeof(struct dns_header)]);
                uint16_t qtype = ntohs(*(uint16_t *)qtype_ptr);

                // FAST-PATH REJECTION
                if (qtype != 1 && qtype != 28) {
                    dns->qr = 1; dns->rcode = 4; dns->ra = 1;
                    sendto(client_fd, buffer, bytes_read, 0, (struct sockaddr *)&client_addr, client_len);
                    continue;
                }

                // STATE ALLOCATION & FORWARDING
                uint16_t new_txid = current_txid++; 
                
                // Save client state in O(1) table
                state_table[new_txid].active = 1;
                state_table[new_txid].original_txid = dns->id;
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
                int bytes_read = recvfrom(upstream_fd, buffer, BUF_SIZE, 0, NULL, NULL);
                if (bytes_read < sizeof(struct dns_header)) continue;

                struct dns_header *dns = (struct dns_header *)buffer;
                uint16_t resp_txid = ntohs(dns->id);

                // Check O(1) state table
                if (state_table[resp_txid].active) {
                    // Restore original client's ID
                    dns->id = state_table[resp_txid].original_txid;
                    
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
