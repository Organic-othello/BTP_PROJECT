import os
import pyshark
import time
import numpy as np
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

# Function to calculate statistics

output_dir = "data"
os.makedirs(output_dir, exist_ok=True)

def calculate_statistics(data):
    if not data:
        return {"avg": None, "std_dev": None, "median": None, "25th": None, "75th": None, "10th": None, "90th": None}
    return {
        "avg": np.mean(data),
        "std_dev": np.std(data),
        "median": np.median(data),
        "25th": np.percentile(data, 25),
        "75th": np.percentile(data, 75),
        "10th": np.percentile(data, 10),
        "90th": np.percentile(data, 90),
    }

# Load URLs from file
urls = ['http://example.com']
# try:
#     with open("top_20_websites_india.txt", "r") as f:
#         urls = [line.split(": ")[1].strip() for line in f.readlines()]
# except FileNotFoundError:
#     print("Error: The file 'top_20_websites_india.txt' was not found.")
#     exit(1)
# except IndexError:
#     print("Error: Ensure the file has URLs in the format '1: http://example.com'.")
#     exit(1)

# Selenium setup for headless Chrome
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=chrome_options)

# Dictionary to store metrics for each URL
metrics_data = {}

# Loop through each URL and measure network conditions
for url in urls:
    i = 0 
    while i < 1 :
        rtts = []
        dns_latencies = []
        tcp_connection_times = []
        retransmissions = 0
        total_data = 0

        try:
            # Generate a pcap file for the current URL
            pcap_file = os.path.join(output_dir, f"{url.replace('http://', '').replace('https://', '').replace('/', '_')}.pcap")
            tcpdump_cmd = ["sudo", "tcpdump", "-w", pcap_file, "-i", "eth0", "-c", "100"]
            tcpdump_proc = subprocess.Popen(tcpdump_cmd)

            # Measure page load time with Selenium
            start_time = time.time()
            driver.get(url)
            load_time = time.time() - start_time

            # Terminate tcpdump and wait
            tcpdump_proc.terminate()
            tcpdump_proc.wait()

            # Analyze captured packets
            cap = pyshark.FileCapture(pcap_file)
            dns_start_time = {}
            tcp_syn_times = {}

            for packet in cap:
                try:
                    # DNS latency
                    if "DNS" in packet:
                        if packet.dns.flags_response == "0":  # DNS Query
                            dns_start_time[packet.dns.id] = float(packet.sniff_timestamp)
                        elif packet.dns.flags_response == "1":  # DNS Response
                            if packet.dns.id in dns_start_time:
                                dns_latency = float(packet.sniff_timestamp) - dns_start_time[packet.dns.id]
                                dns_latencies.append(dns_latency)

                    # TCP analysis
                    if "TCP" in packet:
                        total_data += int(packet.length)  # For throughput

                        if hasattr(packet.tcp, "analysis_ack_rtt"):
                            rtts.append(float(packet.tcp.analysis_ack_rtt))
                        if packet.tcp.flags_syn == "1" and packet.tcp.flags_ack == "0":  # SYN packet
                            tcp_syn_times[packet.tcp.stream] = float(packet.sniff_timestamp)
                        elif packet.tcp.flags_syn == "1" and packet.tcp.flags_ack == "1":  # SYN-ACK response
                            if packet.tcp.stream in tcp_syn_times:
                                tcp_connection_time = float(packet.sniff_timestamp) - tcp_syn_times[packet.tcp.stream]
                                tcp_connection_times.append(tcp_connection_time)

                        # Retransmissions
                        if hasattr(packet.tcp, "analysis_retransmission"):
                            retransmissions += 1

                except AttributeError:
                    continue

            cap.close()

            # Calculate throughput
            tcp_throughput = total_data / load_time if load_time > 0 else 0

            # Calculate statistics
            dns_latency_stats = calculate_statistics(dns_latencies)
            rtt_stats = calculate_statistics(rtts)
            tcp_connection_stats = calculate_statistics(tcp_connection_times)

            # Save metrics to dictionary
            metrics_data[url] = {
                "load_time": load_time,
                "tcp_throughput": tcp_throughput,
                "dns_latency_stats": dns_latency_stats,
                "tcp_connection_stats": tcp_connection_stats,
                "rtt_stats": rtt_stats,
                "retransmissions": retransmissions,
            }

            # Print metrics for the URL
            print(f"\nMetrics for {url}:")
            print(f"Load Time: {load_time:.2f} seconds")
            print(f"TCP Throughput: {tcp_throughput:.2f} bytes/second")
            print("DNS Latency Statistics:", dns_latency_stats)
            print("TCP Connection Statistics:", tcp_connection_stats)
            print("RTT Statistics:", rtt_stats)
            print(f"Retransmissions: {retransmissions}")

        except Exception as e:
            print(f"Error processing {url}: {e}")
        i += 1

# Quit the browser
driver.quit()
