import os
import pyshark
import time
import signal
import numpy as np
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options


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

def terminate(proc,timeout):
    try :
        proc.terminate
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.kill(proc.pid,signal.SIGKILL)
        proc.wait()

# Dictionary to store metrics for each URL
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

urls = ["https://www.google.com"]
metrics_data = {}

for url in urls:
    rtts = []
    dns_queries = []
    dns_latencies = []
    dns_start_times = {}
    tcp_connection_times = []
    retransmissions = 0
    total_data = 0

    try:
        service = Service(chrome_driver_path)
        driver = webdriver.Chrome(service=service, options=chrome_options)
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

        driver.get(url)
        navigation_start = driver.execute_script("return window.performance.timing.navigationStart")
        load_event_end = driver.execute_script("return window.performance.timing.loadEventEnd")
        load_time = (load_event_end - navigation_start)/1000
        print(f"Page load time: {load_time:.2f} seconds")
        wait_time =load_time + 5
        print(wait_time)
        time.sleep(wait_time)  # Allow tshark to capture packets during load
        print('start terminating')
        terminate(tshark_proc,timeout=5)
        print('terminated')
        stderr_output = tshark_proc.stderr.read()
        print("tshark stderr:",stderr_output)

        syn_times = {}
        print(" I am here")

        for line in tshark_proc.stdout:
            fields = line.strip().split(",")
            print(fields)
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

    except Exception as e:
        print(f"Error processing {url}: {e}")
    finally:
        driver.quit()