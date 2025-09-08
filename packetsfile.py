import sqlite3
import pandas as pd
import os
from tabulate import tabulate

if not os.path.exists('packets.db'):
    print("Database file packets.db not found!")
    print("Run sniffing5.py first to create the database and capture packets.")
    exit()

conn = sqlite3.connect('packets.db')
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

if not tables:
    print("No tables found in database!")
    print("Run sniffing5.py and let it capture some packets first.")
    conn.close()
    exit()

print("Recent Alerts:")
try:
    cursor.execute("SELECT COUNT(*) FROM alerts")
    alert_count = cursor.fetchone()[0]
    if alert_count > 0:
        alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20", conn)
        print(tabulate(alerts, headers='keys', tablefmt='grid', showindex=False))
    else:
        print("No alerts found in database yet.")
except Exception as e:
    print(f"Error reading alerts: {e}")

print("\n\nRecent Packets:")
try:
    cursor.execute("SELECT COUNT(*) FROM packets")
    packet_count = cursor.fetchone()[0]
    if packet_count > 0:
        packets = pd.read_sql_query("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 20", conn)
        print(tabulate(packets, headers='keys', tablefmt='grid', showindex=False))
    else:
        print("No packets found in database yet.")
except Exception as e:
    print(f"Error reading packets: {e}")

conn.close()