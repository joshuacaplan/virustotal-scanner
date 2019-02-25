#!/usr/bin/python3

import sys
import hashlib
import os
import requests
import io
from pathlib import Path
import json
import time

from VirusTotal import VirusTotal

def is_num(string):
    try:
        int(string)
    except ValueError:
        print("Not a number!")
        sys.exit(0)

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

    vt = VirusTotal(api_key)

    print("""
    1.) Scan a file
    2.) Get the report of a file
    """)
    selector = input("Please choose an option (a number): ")
    if selector == "1":
        filedir = input("Please enter the file location: ")
        filepath = Path(filedir)
        vt.scan_file(filepath)
    elif selector == "2":
        print("To get the report of a file, you need to put the MD5, SHA-1 or SHA-256 of a file")
        hash = input("Enter the hash: ")
        vt.report_file(hash)
    else:
        print("Not an option!")
        return

if __name__ == "__main__":
    main()