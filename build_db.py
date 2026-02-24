import dpkt
import socket
import sys
import sqlite3
import os

def process_file(filename, conn):
  """Process a single pcap file and update the database"""

  cur = conn.cursor()

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


def main():
  if len(sys.argv) != 3:
      print(f"Usage: {sys.argv[0]} <pcap_file_or_directory> <sqlite3 database file (created if it doesn't exist)>")
      sys.exit(1)

  path = sys.argv[1]
  db_filename = sys.argv[2]

  # Connect to SQLite database
  conn = sqlite3.connect(db_filename)
  cur = conn.cursor()

  # Optimize SQLite for speed (note: synchronous=OFF and journal_mode=MEMORY are risky)
  cur.execute("PRAGMA synchronous = OFF")  # Faster writes, risk of data loss on crash
  cur.execute("PRAGMA journal_mode = MEMORY")  # Reduce disk I/O, no crash recovery

  # Create table if needed
  cur.execute("""CREATE TABLE IF NOT EXISTS ip_pairs
              (src_ip TEXT, dst_ip TEXT, first_timestamp REAL, last_timestamp REAL,
               packet_count INTEGER DEFAULT 1,
               PRIMARY KEY (src_ip, dst_ip))""")

  conn.commit()

  # Check if path is a directory
  if os.path.isdir(path):
      # Process all pcap files in the directory
      files = [f for f in os.listdir(path) if f.endswith('.pcap') or f.endswith('.cap') or f.endswith('.dump')]
      for filename in files:
          print(f"Processing {filename}...")
          process_file(os.path.join(path, filename), conn)
  else:
      # Process single file
      process_file(path, conn)

  # Close connection
  conn.close()
 
  print("Done.")

if __name__ == "__main__":
  main()

