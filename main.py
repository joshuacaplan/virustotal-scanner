import sys
import hashlib
import os
import requests
import io
from pathlib import Path
import json
import time

def is_num(string):
    try:
        int(string)
    except ValueError:
        print("Not a number!")
        sys.exit(0)

def scan_file(api, filedir):
    filepath = Path(filedir)
    if not filepath.is_file():
        print("Not a file path!")
        sys.exit(0)
    # print(filedir)
    rp = requests.post("https://www.virustotal.com/vtapi/v2/file/scan", data={'apikey': api, 'file': filepath})
    print(rp.status_code, rp.reason)
    jsonpost = json.loads(rp.text)
    print(jsonpost)
    resource = jsonpost.get("resource")
    print("")
    print(resource)
    print("Retreiving results! Waiting 15 sec so API doesn't get mad :D")
    time.sleep(15)
    rg = requests.get("https://www.virustotal.com/vtapi/v2/file/report" + "?apikey=" + api + "&resource=" + resource)
    print(rg.status_code, rg.reason)
    jsonget = json.loads(rg.text)
    scans = jsonget.get("scans")
    print("--------------------------------------")
    print("Scan date: ", jsonget.get("scan_date"))
    print("Total: ", jsonget.get("positives") + "/" jsonget.get("total"))
    print("Results: ")
    print("--------------------------------------")
    for i in scans:
        print(i)
        detect = scans.get(i)
        print("Detected: ", detect.get("detected"))
        if detect.get("detected") is "True":
            print("Result: ", detect.get("result"))
        print("--------")
    # print(jsonget)
    
    

def main():
    try:
        with open(os.getenv("HOME") + '/.virustotal.api') as keyfile:
            for line in keyfile:
                print(line)
                api_key = line.strip()
    except FileNotFoundError:
        api_key = input("What is your API key: ")
        with open(os.getenv("HOME") + '/.virustotal.api', "w") as file:
            file.write(api_key)

    
    print("""
    1.) Scan a file
    """)
    selector = input("Please choose an option (a number): ")
    if selector == "1":
        filedir = input("Please enter the file location: ")
        scan_file(api_key, filedir)
    else:
        print("Not an option!")
        return

if __name__ == "__main__":
    main()