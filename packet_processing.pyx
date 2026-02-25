# distutils: language = c
# cython: boundscheck=False, wraparound=False, cdivision=True

import dpkt
import socket

# Define a cpdef function so it can be called from Python
cpdef bool process_packet_data(double ts, bytes buf, bint has_eth, dict pair_map):
    """Cython implementation of packet parsing.
    Returns True if packet was processed and pair_map updated.
    """
    cdef object src_ip_bytes
    cdef object dst_ip_bytes
    cdef str src_ip
    cdef str dst_ip
    cdef tuple key
    cdef list entry
    cdef double first_ts, last_ts
    cdef int pkt_cnt
    cdef unsigned int version

    if has_eth:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            return False
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            return False
        ip = eth.data
    else:
        version = (buf[0] >> 4) & 0xF
        if version != 4:
            return False
        try:
            ip = dpkt.ip.IP(buf)
        except Exception:
            return False

    src_ip_bytes = getattr(ip, 'src', None)
    dst_ip_bytes = getattr(ip, 'dst', None)
    if src_ip_bytes is None or dst_ip_bytes is None:
        return False
    src_ip = socket.inet_ntoa(<bytes>src_ip_bytes)
    dst_ip = socket.inet_ntoa(<bytes>dst_ip_bytes)
    key = (src_ip, dst_ip)
    if key not in pair_map:
        pair_map[key] = [ts, ts, 1]
    else:
        entry = pair_map[key]
        first_ts = entry[0]
        last_ts = entry[1]
        pkt_cnt = entry[2]
        if ts < first_ts:
            first_ts = ts
        if ts > last_ts:
            last_ts = ts
        pair_map[key] = [first_ts, last_ts, pkt_cnt + 1]
    return True
