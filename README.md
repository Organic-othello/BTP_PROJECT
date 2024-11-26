# BTP_PROJECT
# Project Scope

## Motivation  
We found from our regular use of campus Wi-Fi that multiple times throughout the day, the IITD Wi-Fi was not maintaining the expected speed. There was a considerable delay in loading websites at random intervals. However, when performing speed tests during these intervals, the results showed high speeds, indicating that Wi-Fi speed itself was not the issue. This suggested the possibility of firewalls or other reasons affecting the internet performance on personal devices. To investigate this issue, we decided to undertake the following project.

## Project Idea  
The basic idea was to continuously monitor the IITD Wi-Fi at various locations across the campus and identify problems using various network metrics. The data collected from this exercise would help us pinpoint the root causes as we analyze these metrics.

## Project Work  

To monitor the IITD Wi-Fi continuously, we decided to run our code on a Raspberry Pi, enabling uninterrupted data collection. For the initial phase, we focused on websites. We aimed to compare the page load times of websites with metrics such as Average RTT, DNS Latency, and TCP Throughput. The steps were as follows:  

1. **Data Collection**:  
   - Calibrate the packets received during website loading.  
   - Record the page load time and compare it with the metrics for each run.  
   - Collect data throughout the day for the top 20 websites in India and monitor the associated network metrics.

2. **Metrics Calibration**:  
   The code would generate a PCAP file for each website. Using this PCAP file, we calibrated the following metrics:  
   - **TCP Throughput**  
   - **DNS Latency Stats**  
   - **TCP Connection Stats**  
   - **RTT Stats**  
   - **Retransmissions**  

3. **Correlation Analysis**:  
   These metrics would be correlated with page load times to identify relationships. The data collected over several days would be stored in a database for proper visualization. We plan to use **InfluxDB** on top of **PostgreSQL** for this purpose. Key visualizations include time series plots and scatter plots between metrics.

4. **Second Phase**:  
   - Conduct an in-depth analysis of the network using **TSLB Probes**.  
   - Use **Ping Probes** to measure Round Trip Time (RTT).  
   - Leverage Ping Probes to quickly detect basic connectivity issues in the network.

## Result  
Using the calibrated metrics, we aim to identify the problems affecting network performance. A conclusive report will be prepared to assist the CSC team in addressing these issues, with the hope of improving the IITD Wi-Fi network.  
