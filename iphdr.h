#pragma once

#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	u_int8_t  v_hl_;       /* version, header length */
    u_int8_t  tos_;       /* type of service */
    u_int16_t len_;         /* total length */
    u_int16_t id_;          /* identification */
    u_int16_t off_;
    u_int8_t  ttl_;          /* time to live */
    u_int8_t  protocol_;            /* protocol */
    u_int16_t sum_;         /* checksum */
    Ip src_;
    Ip dst_;

	Ip src() { return ntohl(src_); }
	Ip dst() { return ntohl(dst_); }
    u_int8_t hl() { return (v_hl_ & 0x0F) <<2; }
    u_int16_t len() { return ntohs(len_); }
    u_int8_t protocol() { return protocol_; }
    u_int16_t id() { return ntohs(id_); }

	// Type(type_)
	enum: uint8_t {
        tcp = 0x06
	};
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
