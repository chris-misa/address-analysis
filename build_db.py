import dpkt
import dpkt.ip
import socket
import sys
import sqlite3
import os


def flush_db(conn, pair_map):
    """Persist accumulated pair data to the database using an UPSERT."""
    if not pair_map:
        return
    cur = conn.cursor()
    sql = (
        "INSERT INTO ip_pairs (src_ip, dst_ip, first_timestamp, last_timestamp, packet_count) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(src_ip, dst_ip) DO UPDATE SET "
        "first_timestamp = CASE WHEN excluded.first_timestamp < ip_pairs.first_timestamp "
        "THEN excluded.first_timestamp ELSE ip_pairs.first_timestamp END, "
        "last_timestamp = CASE WHEN excluded.last_timestamp > ip_pairs.last_timestamp "
        "THEN excluded.last_timestamp ELSE ip_pairs.last_timestamp END, "
        "packet_count = ip_pairs.packet_count + excluded.packet_count"
    )
    values = []
    for (src_ip, dst_ip), (first_ts, last_ts, pkt_cnt) in pair_map.items():
        values.append((src_ip, dst_ip, first_ts, last_ts, pkt_cnt))
    cur.executemany(sql, values)
    conn.commit()


def process_file(filename, conn):
    """Process a single pcap file and update the database using a dict accumulator."""
    pair_map = {}
    batch_size = 100000
    count = 0

    with open(filename, 'rb') as f:
        reader = dpkt.pcap.Reader(f)
        dlt = reader.datalink()
        if dlt == dpkt.pcap.DLT_EN10MB:
            has_eth = True
        elif dlt == dpkt.pcap.DLT_RAW or dlt == 101:
            has_eth = False
        else:
            print(f"Unknown link-layer type {dlt} in {filename}...skipping!")
            return

        for ts, buf in reader:
            if len(buf) < 40:
                continue

            if has_eth:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue
                ip = eth.data
            else:
                version = (buf[0] >> 4) & 0xF
                if version != 4:
                    continue
                try:
                    ip = dpkt.ip.IP(buf)
                except Exception:
                    continue

            # At this point ip should be an instance of dpkt.ip.IP
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            key = (src_ip, dst_ip)
            if key not in pair_map:
                pair_map[key] = [ts, ts, 1]
            else:
                first_ts, last_ts, pkt_cnt = pair_map[key]
                if ts < first_ts:
                    first_ts = ts
                if ts > last_ts:
                    last_ts = ts
                pair_map[key] = [first_ts, last_ts, pkt_cnt + 1]
            count += 1
            if count % batch_size == 0:
                flush_db(conn, pair_map)
                pair_map.clear()

        if pair_map:
            flush_db(conn, pair_map)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <pcap_file_or_directory> <sqlite3 database file (created if it doesn't exist)>")
        sys.exit(1)

    path = sys.argv[1]
    db_filename = sys.argv[2]

    conn = sqlite3.connect(db_filename)
    cur = conn.cursor()

    cur.execute("PRAGMA synchronous = OFF")
    cur.execute("PRAGMA journal_mode = MEMORY")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_pairs (
            src_ip TEXT,
            dst_ip TEXT,
            first_timestamp REAL,
            last_timestamp REAL,
            packet_count INTEGER DEFAULT 1,
            PRIMARY KEY (src_ip, dst_ip)
        )
        """
    )
    conn.commit()

    if os.path.isdir(path):
        files = [f for f in os.listdir(path) if f.endswith('.pcap') or f.endswith('.cap') or f.endswith('.dump')]
        for filename in files:
            print(f"Processing {filename}...")
            process_file(os.path.join(path, filename), conn)
    else:
        process_file(path, conn)

    conn.close()
    print("Done.")


if __name__ == "__main__":
    main()
