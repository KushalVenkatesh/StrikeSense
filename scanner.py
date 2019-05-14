#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import socket
import sys
import time
import argparse
import os
import datetime
import mysql.connector

#importing from package
import AuthDB
import os_details
import service
import port_f
from HostDiscovery import get_ip as discover_hosts

desc = '''
            StrikeSense Network Scanner
          -------------------------------
    StrikeSense is made for network administrators who
    actually care about what vulnerable software is b-
    eing run in their network. StrikeSense aims at he-
    lping network admins find out and patch vulnerable
    software before an adversary discovers it.

    Why StrikeSense?
        [+] 100% accurate OS detection.
        [+] Absolute version identification of
            services running on open ports.
        [+] Full webapp and background app visibility.
        [+] Manageable results, MariaDB and other MySQL
            variant compatible.

    Author:
            Kushagra Choudhary(@Pinpwn)
            https://pwnprone.wordpress.com
'''
about = "="*60 + "\n" + desc + "\n" + "="*60 + "\n"

def get_os_details(host, username, password, domain, os):
    print("=> OS Details:\n")
    display = ""
    now = datetime.datetime.now()
    date_t = now.strftime("%Y-%m-%d %H:%M:%S")
    if os == "windows":
        cpe_name = ''
        ret = os_details.get_windows(username, password, host, domain)
        version = ret[0]
        vendor = ret[1]
        product = ret[2]
        update = ret[3]
        #print("version:", version)
        #print("caption:", caption)
        #print("vendor:", vendor)
        #print("product:", product)
        #print("update:", update)
        print("\tOS type: Windows")
        if vendor != '':
            display += "\tVendor: "+vendor+"\n"
        if product != '':
            display += "\tProduct: "+product+"\n"
        if version != '':
            display += "\tVersion: "+version+"\n"
        if update != '':
            display += "\tUpdate: "+update+"\n"
        #cpe_name = ''
        if display != '':
            insert_ret = os_details.insert_db(date_t, host, vendor, product,
                                            version, update)
            if insert_ret:
                print("Insertion in db not successful, windows")
                return 1
    if os == "linux":
        vendor_update = vendor = ''
        ret = os_details.get_linux(username, password, host)
        if ret != -1:
            version = ret[0]
            product = ret[1]
            kern_ver = ret[2]
            #cpe_name = ret[3]
            print("\tOS type: Linux")
            if product != '':
                display += "\tProduct: "+product+"\n"
            if version != '':
                display += "\tVersion: "+version+"\n"
            if kern_ver != '':
                display += "\tKernel: "+kern_ver+"\n"
            if display != '':
                ret_insert = os_details.insert_linux_db(date_t, host, vendor,
                                                        product, version,
                                                        kern_ver)
                if ret_insert:
                    print("Insertion in db not successful, linux")
                    return 1
    print(display)
    return 0

#checking if host exists in scanner_hosts
#returns 0 if host present(already scanned)
def check_host_exist(host):
    query = "select * from scanner_hosts where host = '"+host+"'"
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor(buffered=True)
    cursor.execute(query)
    row_data = cursor.fetchone()
    if row_data is not None:
        return 1
    else:
        return 0


def scanner(host, username, password, domain, os,
            flag, start_port, end_port, scan_mode):
    print(about)
    ret = 1
    if scan_mode == "individual":
        if not check_host_exist(host):
            try:
                get_os_details(host, username, password, domain, os)
                ret = 0
            except Exception as e:
                print("[+] ERROR scanner_os:"+str(e))
        else:
            print("[+] Host "+host+" already exists in DB.\n")
        try:
            port_f.scan(host, flag, start_port, end_port)
            ret = 0
        except Exception as e:
            print("[+] ERROR scanner_port:"+str(e))
    else:
        discover_hosts()
    return ret



os_choices = ['windows', 'linux']
mode_choices = ['all', 'individual']

parser = argparse.ArgumentParser(description=about, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--mode', required=True, choices=mode_choices, help='Mode of scan.')
parser.add_argument('--host', required=True, help='IP of the host to scan.')
parser.add_argument('--username', required=True, help='Username of admin.')
parser.add_argument('--password', required=True, help='Password of admin.')
parser.add_argument('--domain', required=False, help='Domain of system.')
parser.add_argument('--os', required=True, choices=os_choices, help='OS family')
parser.add_argument('--sport', required=False, help='Starting port of port range.')
parser.add_argument('--eport', required=False, help='Ending port of port range.')

if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

args = parser.parse_args()

port_supplied = 1

if args.sport and args.eport:
    port_supplied = 0

scanner(args.host, args.username,
        args.password, args.domain,
        args.os, port_supplied,
        args.sport, args.eport, args.mode)
