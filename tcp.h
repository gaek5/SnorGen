/**************************************************************************** 
**
** File: tcp.h
**
** Author: Mike Borella
**
** Comments: Generic TCP header structure - an attempt at OS independence
**
*****************************************************************************/

/*
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

#define TCPOPT_EOL      0
#define TCPOPT_NOP      1
#define TCPOPT_MAXSEG   2
*/

/*
 * TCP header
 */


typedef struct _TCPHdr
{
        u_int16_t src_port;               // source port
        u_int16_t dst_port;               // destination port 
        u_int32_t seq_num;                // sequence number
        u_int32_t ack_num;                // acknowledgement number
#ifdef WORDS_BIGENDIAN
        u_int8_t  d_offset:4,               // data offset 
                  th_x2:4;                // (unused) 
#else
        u_int8_t  th_x2:4,                // (unused) 
                  d_offset:4;               // data offset 
#endif
        u_int8_t  flags;
        u_int16_t window;                 // window 
        u_int16_t chk_sum;                 // checksum 
        u_int16_t urg_point;                 // urgent pointer 
} TCPHdr;

