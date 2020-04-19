#!usr/bin/env python3
import concurrent.futures
import os
import socket
import argparse
from concurrent.futures.thread import ThreadPoolExecutor
import csv

# hostname of the computer
HOST_NAME = str(socket.gethostname())   # socket.getfqdn()
# csv containing the result of the scan
SCAN_RESULT = "port_scanner_result.csv"
# number of workers/threads
MAX_THREADS = 8
# max port number
MAX_PORT = 65536
# time-out: 5 seconds
TIMEOUT = 5
# where the csv will be save
SOURCE_PATH = os.path.dirname(os.path.abspath(__file__))
# path to the result
RESULT_FILE = os.path.join(SOURCE_PATH, SCAN_RESULT)

def tcp_connection(ip_or_host, port):
    is_connected = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((ip_or_host, port))
        is_connected = True
        s.close()
        return is_connected
    except:
        is_connected = False
        return is_connected

if __name__  == "__main__":
    print(HOST_NAME)
    parser = argparse.ArgumentParser(description="Usage of port_scanner.py")
    parser.add_argument('--host', metavar="", type=str, default=HOST_NAME, help='hostname of the computer')
    parser.add_argument('--output', metavar="", type=str, default=SCAN_RESULT, help='output csv file')
    args = parser.parse_args()

    future_to_result_dict = {}

    with open(RESULT_FILE, 'w', newline='') as csv_file:
        result_writer = csv.writer(csv_file, delimiter=',',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
        result_writer.writerow(['Host', 'Port', 'Connected'])
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_result_dict = {executor.submit(tcp_connection, HOST_NAME, port): port for port in range(MAX_PORT)}
            for future in concurrent.futures.as_completed(future_to_result_dict):
                port = future_to_result_dict[future]
                try:
                    is_connected = future.result()
                    result_writer.writerow([HOST_NAME, port, is_connected])
                    print(f"connected to: {port}")
                except:
                    print("Error while processing concurrent futures")



