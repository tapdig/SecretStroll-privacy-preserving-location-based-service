"""
Data generation script to ease traffic sniffing
"""

import argparse
import subprocess
import sys
import threading
import time
import os
from scapy.all import sniff, wrpcap

def _sniff(e, round_id, cell_id):
    """Capture traffic and save to file based on round and cell_id values"""
    iface = "eth0"
    packets = sniff(iface=iface, stop_filter=lambda p: e.is_set())
    filename = f"tor_pcap/generate_data_{round_id}_requests_cell_{cell_id}.pcap"
    wrpcap(filename, packets)
    print(f"[✓] Captured {len(packets)} packets for cell {cell_id}, round {round_id}")

def main(args):
    """Generate and capture grid requests through Tor"""
    parser = argparse.ArgumentParser(description="Data generation for Part 3 of SecretStroll project")

    parser.add_argument("-n", "--numtries", type=int, help="Number of requests per cell_id.")
    parser.add_argument("-i", "--start-index", type=int, default=0, help="Start index for file naming.")

    namespace = parser.parse_args(args)

    if not namespace.numtries:
        parser.print_help()
        return

    os.makedirs("tor_pcap", exist_ok=True)

    for cell_id in range(1, 101):  # cell_id ∈ [1, 100]
        for round_id in range(namespace.start_index, namespace.start_index + namespace.numtries):
            print(f"→ Capturing for cell {cell_id}, round {round_id}")

            # Start sniffing in a thread
            stop_event = threading.Event()
            sniffer = threading.Thread(target=_sniff, args=(stop_event, round_id, cell_id))
            sniffer.start()

            # Make the request
            subprocess.run(
                ["python3", "client.py", "grid", str(cell_id), "-T", "restaurant", "-t"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Stop sniffing
            stop_event.set()

            # Wait for the thread to finish
            while sniffer.is_alive():
                sniffer.join(timeout=2)

            time.sleep(1)  # sleep between requests

if __name__ == "__main__":
    main(sys.argv[1:])
