import dpkt
import socket
import sys
import sqlite3
import os

def process_file(filename):
  """Process a single pcap file and update the database"""
  db_filename = 'ip_pairs.db'

  # Connect to SQLite database
  conn = sqlite3.connect(db_filename)
  cur = conn.cursor()

  # Optimize SQLite for speed (note: synchronous=OFF and journal_mode=MEMORY are risky)
  cur.execute("PRAGMA synchronous = OFF")  # Faster writes, risk of data loss on crash
  cur.execute("PRAGMA journal_mode = MEMORY")  # Reduce disk I/O, no crash recovery

  # Check if table exists and add packet_count column if needed
  cur.execute("PRAGMA table_info(ip_pairs)")
  columns = cur.fetchall()
  packet_count_exists = any(col[1] == 'packet_count' for col in columns)

  if not packet_count_exists:
      # If table doesn't exist, create it with packet_count column
      cur.execute("""CREATE TABLE IF NOT EXISTS ip_pairs
                  (src_ip TEXT, dst_ip TEXT, first_timestamp REAL, last_timestamp REAL,
                   packet_count INTEGER DEFAULT 1,
                   PRIMARY KEY (src_ip, dst_ip))""")
  else:
      # If table exists but lacks packet_count column, add it
      cur.execute("ALTER TABLE ip_pairs ADD COLUMN packet_count INTEGER DEFAULT 1")

  # Create index if not exists (redundant with PRIMARY KEY but explicitly shown)
  cur.execute("CREATE INDEX IF NOT EXISTS idx_src_dst ON ip_pairs (src_ip, dst_ip)")
  conn.commit()

  # Begin transaction
  cur.execute("BEGIN")

  batch_size = 1000  # Adjust this based on available memory
  count = 0

  with open(filename, 'rb') as f:
      reader = dpkt.pcap.Reader(f)
      for ts, buf in reader:
          eth = dpkt.ethernet.Ethernet(buf)
          if eth.type != dpkt.ethernet.ETH_TYPE_IP:
              continue
          ip = eth.data
          src_ip = socket.inet_ntoa(ip.src)
          dst_ip = socket.inet_ntoa(ip.dst)

          # Check if the IP pair exists
          cur.execute("SELECT * FROM ip_pairs WHERE src_ip = ? AND dst_ip = ?", (src_ip, dst_ip))
          existing = cur.fetchone()

          if existing:
              # Update last_timestamp and increment packet_count
              cur.execute("""
                  UPDATE ip_pairs
                  SET last_timestamp = ?, packet_count = packet_count + 1
                  WHERE src_ip = ? AND dst_ip = ?
                  """,
                  (ts, src_ip, dst_ip))
          else:
              # Insert new row with packet_count initialized to 1
              cur.execute("""
                  INSERT INTO ip_pairs
                  (src_ip, dst_ip, first_timestamp, last_timestamp, packet_count)
                  VALUES (?, ?, ?, ?, 1)""",
                  (src_ip, dst_ip, ts, ts))
          count += 1

          # Commit in batches
          if count % batch_size == 0:
              conn.commit()
              cur.execute("BEGIN")  # Restart transaction

      # Commit remaining operations
      conn.commit()

  # Close connection
  conn.close()

def main():
  if len(sys.argv) != 2:
      print(f"Usage: {sys.argv[0]} <pcap_file_or_directory>")
      sys.exit(1)

  path = sys.argv[1]

  # Check if path is a directory
  if os.path.isdir(path):
      # Process all pcap files in the directory
      files = [f for f in os.listdir(path) if f.endswith('.pcap') or f.endswith('.cap')]
      for filename in files:
          process_file(os.path.join(path, filename))
  else:
      # Process single file
      process_file(path)

if __name__ == "__main__":
  main()

