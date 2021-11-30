#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
    u_int16_t sport_;       /* source port */
    u_int16_t dport_;       /* destination port */
    u_int32_t seq_;          /* sequence number */
    u_int32_t ack_;          /* acknowledgement number */
    u_int8_t  off_;        /* data offset */    
    u_int8_t  flags_;       /* control flags */
    u_int16_t win_;         /* window */
    u_int16_t sum_;         /* checksum */
    u_int16_t urp_;         /* urgent pointer */

	u_int16_t sport() { return ntohs(sport_); }
	u_int16_t dport() { return ntohs(dport_); }
    u_int32_t seq() { return ntohl(seq_); }
    u_int32_t ack() { return ntohl(ack_); }
    u_int32_t flags() { return flags_; }
    u_int32_t hl() { return (off_>>4) << 2; }

    // Flags(flags_)
	enum: uint8_t {
        urg_f = 0x20,
        ack_f = 0x10,
        psh_f = 0x08,
        rst_f = 0x04,
        syn_f = 0x02,
        fin_f = 0x01
	};

};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)




