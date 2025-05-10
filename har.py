import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import json
import time

resp = requests.post("http://localhost:9090/proxy")
port = resp.json()['port']
proxy_url = f"http://localhost:9090/proxy/{port}"

requests.put(f"{proxy_url}/har", json={"captureContent": "true"})

chrome_options = Options()
chrome_options.add_argument("--disable-cache")
chrome_options.add_argument("--headless=new")
chrome_options.add_argument(f"--proxy-server=localhost:{port}")
chrome_options.add_argument("--ignore-certificate-errors")
chrome_options.binary_location = "/usr/bin/chromium"
chrome_driver_path = "/usr/bin/chromedriver"
service = Service(chrome_driver_path)
driver = webdriver.Chrome(service=service,options=chrome_options)

driver.get("https://google.com")

time.sleep(5)


har_resp = requests.get(f"{proxy_url}/har")
try:
    har=har_resp.json()
    with open("output.har", "w") as f:
        json.dump(har, f)
except Exception as e:
    print("failed to parse HAR JSON:", e)
    har = None

driver.quit()
requests.delete(f"http://localhost:9090/proxy/{port}")
