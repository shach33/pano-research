#!/usr/bin/env python3

import dnslib
import sys
from struct import unpack
from bcc import BPF
from socket import if_indextoname

def print_dns(cpu, data, size):
    import ctypes as ct
    class SkbEvent(ct.Structure):
        _fields_ = [
            ("pid", ct.c_uint32),
            ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))
        ]
    # We get our 'port_val' structure and also the packet itself in the 'raw' field:
    sk = ct.cast(data, ct.POINTER(SkbEvent)).contents

    # Protocols:
    NET_PROTO = {6: "TCP", 17: "UDP"}

    #Get process name
    with open(f'/proc/{sk.pid}/comm', 'r') as proc_comm:
        proc_name = proc_comm.read().rstrip()

    # Ethernet frame header length- 14 bytes:
    ip_packet = bytes(sk.raw[14:])
    
    
    (length, _, _, _, _, proto, _, saddr, daddr) = unpack('!BBHLBBHLL', ip_packet[:20])
    # The direct length is written in the second half of the first byte (0b00001111 = 15):
    len_iph = length & 15
    # Length is written in 32-bit words, convert it to bytes:
    len_iph = len_iph * 4
    
    saddr = ".".join(map(str, [saddr >> 24 & 0xff, saddr >> 16 & 0xff, saddr >> 8 & 0xff, saddr & 0xff]))
    daddr = ".".join(map(str, [daddr >> 24 & 0xff, daddr >> 16 & 0xff, daddr >> 8 & 0xff, daddr & 0xff]))

    if proto == 17: #UDP
        udp_packet = ip_packet[len_iph:]
        (sport, dport) = unpack('!HH', udp_packet[:4])
        # UDP datagram header length is 8 bytes:
        dns_packet = udp_packet[8:]
    else:
        return

    # DNS data decoding:
    dns_data = dnslib.DNSRecord.parse(dns_packet)

    DNS_QTYPE = {1: "A", 28: "AAAA"}

    # Query:
    if dns_data.header.qr == 0:
        for q in dns_data.questions:
            if q.qtype == 1 or q.qtype == 28:
                print(f'[Query] Process={proc_name} src={saddr} dst={daddr} S_port={sport} D_port={dport} Name={q.qname} Query_type={DNS_QTYPE[q.qtype]}')
    # Response:
    elif dns_data.header.qr == 1:
        for rr in dns_data.rr:
            if rr.rtype == 1 or rr.rtype == 28:
                print(f'[Response] Process={proc_name} src={saddr} dst={daddr} S_port={sport} D_port={dport} Name={rr.rname} Query_type={DNS_QTYPE[rr.rtype]} Query_data={rr.rdata}')
    else:
        print('Invalid DNS packet.')
    
    print(f'{sk.raw}')
    print('\n=========================')
    sys.stdout.buffer.write(bytes(sk.raw))
    #print(hex(int(bytes(sk.raw),base=16)))
    print('\n=========================')

BPF_KPROBE = """
#include <net/sock.h>
//the structure that will be used as a key for eBPF table 'proc_ports':
struct port_key {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
// the structure which will be stored in the eBPF table 'proc_ports',
// contains information about the process:
struct port_val {
    u32 pid;
};
// Public (accessible from other eBPF programs) eBPF table
// information about the process is written to.
// It is read when a packet appears on the socket:
BPF_TABLE_PUBLIC("hash", struct port_key, struct port_val, proc_ports, 20480);
int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    if (sport == ntohs(53) || dport == ntohs(53)) {
        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = 17};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);
        //Forming a structure with socket properties:
        struct port_val val = {}; 
        val.pid = pid_tgid >> 32;
        //Write the value into the eBPF table:
        proc_ports.update(&key, &val);
    }
    return 0;
}
"""


BPF_SOCK = r'''
#include <net/sock.h>
#include <bcc/proto.h>
//the structure that will be used as a key for
// eBPF table 'proc_ports':
struct port_key {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
// the structure which will be stored in the eBPF table 'proc_ports',
// contains information about the process:
struct port_val {
    u32 pid;
};
// eBPF table from which information about the process is extracted.
// Filled when calling kernel functions udp_sendmsg()/tcp_sendmsg():
BPF_TABLE("extern", struct port_key, struct port_val, proc_ports, 20480);
// table for transmitting data to the user space:
BPF_PERF_OUTPUT(dns_events);
// Among the data passing through the socket, look for DNS packets
// and check for information about the process:
int dns_matching(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (ethernet->type == ETH_P_IP) {
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        u8 proto;
        u16 sport;
        u16 dport;
        if (ip->nextp == IPPROTO_UDP) {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
            proto = 17;
            //receive port data:
            sport = udp->sport;
            dport = udp->dport;
        } else {
            return 0;
        }
        if (dport == 53 || sport == 53) { //DNS request
            struct port_key key = {};
            key.proto = proto;
            if (skb->ingress_ifindex == 0) {
                key.saddr = ip->src;
                key.daddr = ip->dst;
                key.sport = sport;
                key.dport = dport;
            } else {
                key.saddr = ip->dst;
                key.daddr = ip->src;
                key.sport = dport;
                key.dport = sport;
            }
            // By the key we are looking for a value in the eBPF table:
            struct port_val *p_val;
            p_val = proc_ports.lookup(&key);
            if (!p_val) {
                return 0;
            }
            // pass the structure with the process information along with
            // skb->len bytes sent to the socket:
            dns_events.perf_submit_skb(skb, skb->len, p_val,
                                       sizeof(struct port_val));
            return 0;
        } //dport == 53 || sport == 53
    } //ethernet->type == ETH_P_IP
    return 0;
}
'''

def main():

    # Init  BPF 
    bpf_kprobe = BPF(text=BPF_KPROBE)
    bpf_sock = BPF(text=BPF_SOCK)

    # UDP sending:
    bpf_kprobe.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")

    # Socket:
    function_dns_matching = bpf_sock.load_func("dns_matching", BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(function_dns_matching, '')

    bpf_sock["dns_events"].open_perf_buffer(print_dns)

    while 1:
        bpf_sock.perf_buffer_poll()

if __name__ == "__main__":
    main()

