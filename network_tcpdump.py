import os
import pyshark
import time
import signal
import psutil
import csv
import numpy as np
import subprocess
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import sys


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
csv_file = "/home/networksbtp2/BTP_PROJECT/data_analysis.csv"

# Define CSV headers
csv_headers = [
    "Iteration", "URL", "Time of First Packet", "Load Time",
    "TCP Throughput", "DNS Avg Latency", "DNS Std Dev", "DNS 25th", "DNS Median", "DNS 75th",
    "TCP Conn Avg Time", "TCP Conn Std Dev", "TCP Conn 25th", "TCP Conn Median", "TCP Conn 75th",
    "RTT Avg", "RTT Std Dev", "RTT 25th", "RTT Median", "RTT 75th",
    "Retransmissions", "PCAP File"
]

def init_csv():
    if not os.path.exists(csv_file):
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(csv_headers)  # Write headers

def append_to_csv(data):
    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(data) 


def terminate_tcpdump():
    try:
        # Get all tcpdump processes with their PIDs and PPIDs
        result = subprocess.run(["sudo", "ps", "-eo", "pid,ppid,cmd"], capture_output=True, text=True)
        lines = result.stdout.split("\n")

        for line in lines:
            if "tcpdump" in line:
                parts = line.split()
                if len(parts) >= 2:
                    pid = parts[0]
                    ppid = parts[1]

                    # Check if PPID matches the terminal process ID 
                    terminal_pid = str(os.getppid())

                    if ppid == terminal_pid:
                        print(f"Skipping process {pid} (linked to terminal)")
                        continue  # Don't kill terminal-attached process

                    # Kill the process
                    subprocess.run(["sudo", "kill", "-9", pid])
                    print(f"Terminated tcpdump process {pid}")

    except Exception as e:
        print(f"Error terminating tcpdump: {e}")
 

def calculate_statistics(data):
    if not data:
        return {"avg": None, "std_dev": None, "median": None, "25th": None, "75th": None}
    return {
        "avg": np.mean(data),
        "std_dev": np.std(data),
        "median": np.median(data),
        "25th": np.percentile(data, 25),
        "75th": np.percentile(data, 75),
    }
iteration_file = "/home/networksbtp2/BTP_PROJECT/iteration_counter.txt"
def get_iteration():
    if os.path.exists(iteration_file):
        with open(iteration_file, "r") as f:
            try:
                iteration = f.readline().strip()
                # print(iteration)
                if iteration.isdigit():
                    return int(iteration)
                
            except Exception as e:
                print(f"error reading the file : {e}")

    sys.exit(1)
def update_iteration(iteration):
    with open(iteration_file, "w") as f:
        f.write(str(iteration)+ "\n")



def get_folder_name(url):
    if url == "https://www.google.com":
        return "Google"
    elif url == "https://openai.com":
        return "OpenAI"
    elif url == 'https://www.youtube.com':
        return "Youtube"
    elif url == "https://www.wikipedia.org":
        return "Wikipedia"
    elif url == "https://www.amazon.in":
        return "Amazon"

urls = ["https://www.google.com","https://openai.com",'https://www.youtube.com',"https://www.wikipedia.org","https://www.amazon.in"]
data_folder = "/home/networksbtp2/BTP_PROJECT/DATA"
init_csv()
# metrics_data = {}
iteration = get_iteration()
while True:

    for url in urls:
        folder_name = get_folder_name(url)
        website_folder = os.path.join(data_folder,folder_name)
        os.makedirs(website_folder, exist_ok = True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(f"starting for {url}")
        pcap_file = os.path.join(website_folder, f"{iteration}_{folder_name}_{timestamp}.pcap")
        tcpdump_cmd = [ "sudo","tcpdump","-i","wlan0","-s","96","-w",pcap_file,"tcp or udp"]
        tcpdump_proc = subprocess.Popen(tcpdump_cmd, stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
        try:
            service = Service(chrome_driver_path)
            driver = webdriver.Chrome(service=service,options=chrome_options)
            driver.get(url)
            navigation_start = driver.execute_script("return window.performance.timing.navigationStart")
            load_event_end = driver.execute_script("return window.performance.timing.loadEventEnd")
            load_time = (load_event_end - navigation_start)/1000
            response_start = driver.execute_script("return window.performance.timing.responseStart")
            request_start = driver.execute_script("return window.performance.timing.requestStart")
            if response_start and request_start and response_start > request_start :
                    ttfb = (response_start-request_start)/1000
            print(f"Page load time: {load_time:.2f} seconds")
            time.sleep(5)
        except Exception as e:
            print(f"error with selenium for {url}:{e}")
        finally :
            subprocess.run(["sudo","pkill","-2","tcpdump"],check=True)
            # terminate_tcpdump()
            driver.quit()
            
            print("terminated")

        try:
            cap = pyshark.FileCapture(pcap_file,display_filter="tcp or dns")
            first_packet_time = ttfb
            rtts = []
            dns_latencies = []
            dns_start_times = {}
            tcp_connection_times =[]
            retransmissions = 0
            total_data = 0
            syn_times = {}
            retran = {}
            for packet in cap:
                try:
                    if "DNS" in packet:
                        dns_id = int(packet.dns.id,16)
                        if "flags_response" in packet.dns.field_names and str(packet.dns.flags_response) == "True" :

                                # If this response corresponds to a query, calculate latency
                                if dns_id in dns_start_times:
                                    dns_latency = float(packet.sniff_timestamp) - dns_start_times[dns_id]
                                    dns_latencies.append(dns_latency)
                                    del dns_start_times[dns_id]  # Remove it since we got a response
                        else:  
                                dns_start_times[dns_id] = float(packet.sniff_timestamp)
                    if "TCP" in packet:
                        if hasattr(packet.tcp,"analysis_ack_rtt"):
                            rtts.append(float(packet.tcp.analysis_ack_rtt))
                        if hasattr(packet.tcp, "stream") and hasattr(packet.tcp, "flags_syn") and hasattr(packet.tcp, "flags_ack"):
                            stream_id = int(packet.tcp.stream)
                            if str(packet.tcp.flags_syn) == "True":
                                syn_flag = True
                            else:
                                syn_flag = False
                            if str(packet.tcp.flags_ack) == "True":
                                ack_flag = True
                            else:
                                ack_flag = False
                            if syn_flag and not ack_flag:
                                syn_times[stream_id] = float(packet.sniff_timestamp)
                            elif syn_flag and ack_flag and stream_id in syn_times:
                                conn_time = float(packet.sniff_timestamp) - syn_times[stream_id]
                                tcp_connection_times.append(conn_time)
                                del syn_times[stream_id]
                        if hasattr(packet.tcp, "seq") and hasattr(packet.tcp, "ack"):
                            seq_num = int(packet.tcp.seq)
                            ack_num = int(packet.tcp.ack)
                            if (seq_num,ack_num) in retran :
                                retransmissions +=1
                            else:
                                retran[(seq_num,ack_num)] = float(packet.sniff_timestamp)

                    if hasattr(packet, "frame_info") and hasattr(packet.frame_info,"frame.len"):
                        total_data += int(packet.frame_info._all_fields["frame.len"].show)
                except AttributeError:
                    continue
            dns_stats = calculate_statistics(dns_latencies)
            tcp_stats = calculate_statistics(tcp_connection_times)
            rtt_stats = calculate_statistics(rtts)
            tcp_throughput = total_data / load_time if load_time > 0 else 0

    
            append_to_csv([
                iteration, url, first_packet_time, load_time, tcp_throughput,
                dns_stats["avg"], dns_stats["std_dev"], dns_stats["25th"], dns_stats["median"], dns_stats["75th"],
                tcp_stats["avg"], tcp_stats["std_dev"], tcp_stats["25th"], tcp_stats["median"], tcp_stats["75th"],
                rtt_stats["avg"], rtt_stats["std_dev"], rtt_stats["25th"], rtt_stats["median"], rtt_stats["75th"],
                retransmissions, pcap_file
            ])
            # tcp_throughput = total_data/ load_time if load_time > 0 else 0
            # metrics_data[url] = {
            #     "load_time": load_time,
            #     "tcp_throughput": tcp_throughput,
            #     "dns_latency_stats": {k: (float(v) if v is not None else None) for k, v in calculate_statistics(dns_latencies).items()},
            #     "tcp_connection_stats":{k: (float(v) if v is not None else None) for k, v in calculate_statistics(tcp_connection_times).items()},
            #     "rtt_stats": {k: (float(v) if v is not None else None) for k, v in calculate_statistics(rtts).items()},
            #     "retransmissions": retransmissions,
            # }

            # print(f"Metrics for {url}:", metrics_data[url])
        except Exception as e:
            print("error")
        finally:
            cap.close()
    iteration += 1
    update_iteration(iteration)
