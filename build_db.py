import dpkt
import sys
import sqlite3
import os

# Attempt to import the cython compiled version of process_packet_data
try:
    from packet_processing import process_packet_data
except Exception:
    # Fallback: install pyximport if available and retry
    try:
        import pyximport
        pyximport.install()
        from packet_processing import process_packet_data
    except Exception as e:
        # If still not available, raise a clear error for the user
        raise ImportError("Failed to import compiled process_packet_data. Ensure pyximport is installed and packet_processing.pyx is present.")


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
            processed = process_packet_data(ts, buf, has_eth, pair_map)
            if processed:
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


