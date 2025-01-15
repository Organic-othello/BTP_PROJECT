import os
import time
import signal
import numpy as np
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from influxdb import InfluxDBClient  # For InfluxDB 1.x
import csv
import sys

print("Python executable:", sys.executable)

# Selenium setup for headless Chrome
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
chrome_options.add_experimental_option("useAutomationExtension", False)
chrome_options.binary_location = "/usr/bin/chromium"
chrome_driver_path = "/usr/bin/chromedriver"
print("Chrome-driver works")

# Helper Functions
def terminate(proc, timeout):
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait()

def calculate_statistics(data):
    if not data:
        return {"avg": 0, "std_dev": 0, "median": 0, "25th": 0, "75th": 0}
    return {
        "avg": float(np.mean(data)),
        "std_dev": float(np.std(data)),
        "median": float(np.median(data)),
        "25th": float(np.percentile(data, 25)),
        "75th": float(np.percentile(data, 75)),
    }

def save_to_csv(data, filename="metrics_data.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "Load Time", "TCP Throughput", "Retransmissions", 
                         "DNS Avg Latency", "TCP Connection Avg", "RTT Avg"])
        for url, metrics in data.items():
            writer.writerow([
                url,
                metrics["load_time"],
                metrics["tcp_throughput"],
                metrics["retransmissions"],
                metrics["dns_latency_stats"]["avg"],
                metrics["tcp_connection_stats"]["avg"],
                metrics["rtt_stats"]["avg"],
            ])

# Main Code
urls = [
    "https://www.google.com",
    "https://www.facebook.com",
    "https://www.amazon.in",
    "https://www.youtube.com",
    "https://www.wikipedia.org",
]
metrics_data = {}

# Initialize InfluxDB client for InfluxDB 1.x
client = InfluxDBClient(host="localhost", port=8086)
client.switch_database("wifi_metrics")

for url in urls:
    rtts = []
    dns_latencies = []
    dns_queries = []
    dns_start_times = {}
    syn_times = {}
    tcp_connection_times = []
    retransmissions = 0
    total_data = 0

    try:
        service = Service(chrome_driver_path)
        driver = webdriver.Chrome(service=service, options=chrome_options)

        # TShark Command
        tshark_cmd = [
            "sudo", "tshark",
            "-i", "wlan0",
            "-l",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.analysis.ack_rtt",
            "-e", "dns.qry.name",
            "-e", "dns.flags.rcode",
            "-e", "dns.id",
            "-e", "tcp.stream",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-e", "tcp.analysis.retransmission",
            "-e", "frame.len",
            "-E", "separator=,",
        ]

        tshark_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"Capturing packets for {url} in real-time...")

        # Page Load Metrics
        driver.get(url)
        navigation_start = driver.execute_script("return window.performance.timing.navigationStart")
        load_event_end = driver.execute_script("return window.performance.timing.loadEventEnd")
        load_time = (load_event_end - navigation_start) / 1000
        print(f"Page load time: {load_time:.2f} seconds")
        time.sleep(max(load_time + 5, 6))  # Allow tshark to capture packets

        # Terminate TShark
        terminate(tshark_proc, timeout=5)
        print('TShark terminated')

        syn_times = {}
        for line in tshark_proc.stdout:
            fields = line.strip().split(",")
            fields = [field if field != '' else None for field in fields]
            print(fields)
            if len(fields) >= 12:
                timestamp, src_ip, dst_ip, ack_rtt, dns_name, rcode, dns_id, stream, syn, ack, retrans, frame_len = fields
                
                try: 
                    if ack_rtt:
                        rtts.append(float(ack_rtt))
                    if dns_name:
                        dns_queries.append({"dns_id":dns_id,"timestamp":float(timestamp)})
                    if rcode :
                        if int(rcode) == 0:
                            for query in dns_queries:
                                if query["dns_id"] == dns_id:
                                    dns_latency = float(timestamp) - query ["timestamp"]
                                    dns_latencies.append(dns_latency)
                                    dns_queries.remove(query)
                                    break
                    # else:
                    #     print(f'this rcode failed coz rcode was : {int(rcode)}')
                    if stream != None and syn != None and ack != None :
                        timestamp = float(timestamp)
                        stream = int(stream)
                        syn = syn.lower() == 'true'
                        ack = ack.lower() == 'true'
                        if retrans != None :
                            retrans = retrans.lower() == 'true'
                            if retrans:
                                retransmissions = +1
                        print(f"stream : {stream} , syn : {syn} , ack : {ack} , retrans : {retrans} ")
                        if syn and not ack:
                            syn_times[stream] = timestamp
                        if syn and ack:
                            if stream in syn_times:
                                connection_time = timestamp - syn_times.pop(stream)
                                tcp_connection_times.append(connection_time)
                       
                    # if bool(syn) and not bool(ack):
                    #     syn_times[stream] = float(timestamp)
                    # if bool(syn) and bool(ack):
                    #     if int(stream) in syn_times:
                    #         connection_time = timestamp - syn_times.pop(stream)
                    #         tcp_connection_times.append(connection_time)
                    # if bool(retrans) :
                    #     retransmissions += 1


                    if frame_len:
                        total_data += int(frame_len)  # Calculate throughput based on packet size
                except ValueError:
                    continue

        tcp_throughput = total_data / load_time if load_time > 0 else 0
        
        metrics_data[url] = {
            "load_time": load_time,
            "tcp_throughput": tcp_throughput,
            "dns_latency_stats": {k: (float(v) if v is not None else None) for k, v in calculate_statistics(dns_latencies).items()},
            "tcp_connection_stats":{k: (float(v) if v is not None else None) for k, v in calculate_statistics(tcp_connection_times).items()},
            "rtt_stats": {k: (float(v) if v is not None else None) for k, v in calculate_statistics(rtts).items()},
            "retransmissions": retransmissions,
        }

        print(f"Metrics for {url}:", metrics_data[url])

        # Write to InfluxDB
        json_body = [
    {
        "measurement": "wifi_metrics",
        "tags": {
            "url": url,
        },
        "fields": {
            "load_time": float(metrics_data[url]["load_time"]),
            "tcp_throughput": float(metrics_data[url]["tcp_throughput"]),
            "retransmissions": int(metrics_data[url]["retransmissions"]),
            "dns_latency_avg": float(metrics_data[url]["dns_latency_stats"]["avg"]),
            "rtt_avg": float(metrics_data[url]["rtt_stats"]["avg"]),
            "tcp_connection_avg": float(metrics_data[url]["tcp_connection_stats"]["avg"]),
        }
    }
]

        client.write_points(json_body)

    except Exception as e:
        print(f"Error processing {url}: {e}")
    finally:
        driver.quit()

# Save Metrics to CSV
save_to_csv(metrics_data)
print("Metrics saved to CSV successfully.")
