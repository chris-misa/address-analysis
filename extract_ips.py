import dpkt
import socket
import sys

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    filename = sys.argv[1]
    with open(filename, 'rb') as f:
        reader = dpkt.pcap.Reader(f)
        for ts, buf in reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            print(f"{ts}, {src_ip}, {dst_ip}")

if __name__ == "__main__":
    main()

