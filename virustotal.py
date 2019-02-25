#!/usr/bin/python3

import sys
import hashlib
import os
import requests
import io
from pathlib import Path
import json
import time

class VirusTotal():
    def __init__(self, api_key):
        self.api_key = api_key
    
    def report_file(self, resource):
        rg = requests.get("https://www.virustotal.com/vtapi/v2/file/report" + "?apikey=" + self.api_key + "&resource=" + resource)
        print(rg.status_code, rg.reason)
        #print(rg.text)
        try:
            jsonget = json.loads(rg.text)
            print("VirusTotal is analyzing")
        except json.decoder.JSONDecodeError:
            print("Error loading json!")
        count = 0
        
        response_code = jsonget.get("response_code")

        while response_code is not 1:
            print(jsonget.get("response_code"))
            start_time = time.time()
            #print("Response code: ", jsonget.get("response_code"))
            for i in range(4):
                sys.stdout.write('\r')
                # the exact output you're looking for:
                sys.stdout.write("Analyzing%-3s" % ('.'*i))
                sys.stdout.flush()
                time.sleep(0.25) 
            time.sleep(5.0 - ((time.time() - start_time) % 5.0))
            rg = requests.get("https://www.virustotal.com/vtapi/v2/file/report" + "?apikey=" + self.api_key + "&resource=" + resource)
            #print(rg.text)
            count += 1
            #print(count)
            try:
                jsonget = json.loads(rg.text)
                response_code = jsonget.get("response_code")
            except json.decoder.JSONDecodeError:
                print("Failed to load json, maybe http error code 204?")
            
            
        print("\n")

        scans = jsonget.get("scans")
        print("--------------------------------------")
        print("Scan date: ", jsonget.get("scan_date"))
        print("Response: ", jsonget.get("response_code"))
        print("Total: ", str(jsonget.get("positives")) + "/" + str(jsonget.get("total")))
        print("Results: ")
        print("--------------------------------------")
        time.sleep(5)
        for i in scans:
            print(i)
            detect = scans.get(i)
            print("Detected: ", detect.get("detected"))
            if detect.get("detected") is "True":
                print("Result: ", detect.get("result"))
            print("--------")
        print("MD5: ", jsonget.get("md5"))
        # print(jsonget)

    def scan_file(self, filedir):
        filepath = Path(filedir)
        print(filepath)
        # Checking if it's an actual path
        if not filepath.is_file():
            print("Not a file path!")
            sys.exit(0)
        
        # Opening the file
        with open(filepath, 'r') as f: #open the file
            contents = f.readlines() #put the lines to a variable (list).
            #print(contents)

        # Scanning the file inputted
        rp = requests.post("https://www.virustotal.com/vtapi/v2/file/scan", data={'apikey': self.api_key, 'file': contents})
        print(rp.status_code, rp.reason)

        jsonpost = json.loads(rp.text)
        print(jsonpost)
        resource = jsonpost.get("scan_id")
        print("")
        print(resource)
        #print("Retreiving results! Waiting 15 sec so API doesn't get mad :D")
        #time.sleep(15)
        self.report_file(resource)