#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import socket
import sys
import re
import datetime
from subprocess import PIPE, run
import mysql.connector

import AuthDB

def get_ssh(ip_address,port):
    product = version = vendor_update = ''
    try:
        s=socket.socket()
        try:
            s.connect((ip_address,port))
        except Exception as e:
            print("Connection Error:", e)
            return 1
        banner = str(s.recv(1024))
        #print(ip_address + ':' + banner)
        banner = banner.replace("b", "", 1).replace("'", "")
        banner = banner.replace("\\r","").replace("\\n", "")
        banner = banner.split("-")
        product = banner[2].split("_")[0]
        full_version = banner[2].replace(product, "").replace("_", "").split(" ")[0]
        vendor_updt_regx = re.compile("(\B\w*)")
        try:
            vendor_update = vendor_updt_regx.search(full_version).group(1)
        except:
            vendor_update = ""
        version = full_version.replace(vendor_update, "")

    except Exception as e:
        print(e)
    return [product.lower(), version, vendor_update]

def get_webserver(host, port):
    vendor = product = version = host_url = ''
    if port == '80':
        host_url = host
    elif port == '443':
        host_url = "https://"+host
    query = "curl -k -s -I "+host_url+":"+port+" | grep -e 'Server:'"
    #print(query)
    srv_banner = str(run(query, stdout=PIPE, stderr=PIPE, shell=True).stdout)
    if srv_banner == "b''":
        print("Couldn't get banner. | Not visible")
        return 1
    else:
        #print(srv_banner)
        srv_banner = srv_banner.replace("b", "", 1).replace("'", "")
        srv_banner = srv_banner.replace("\\r", "").replace("\\n", "").split(" ")
        full_version = srv_banner[1]
        if "/" in full_version:
            product = full_version.split("/")[0].lower()
            version = full_version.split("/")[1]
        else:
            product = full_version
    if "-" in product:                              #for microsoft-iis
        vendor = product.split("-")[0]
        product = product.split("-")[1]
    #print("vendor", vendor)
    #print("product", product)
    #print("version", version)
    return [vendor, product, version]

def get_poweredby(host, port):
    product = version = ''
    if port == '80':
        host_url = host
    elif port == '443':
        host_url = "https://"+host
    query = "curl -k -s -I "+host_url+":"+port+" | grep -e 'X-Powered-By:'"
    xpwr_banner = str(run(query, stdout=PIPE, stderr=PIPE, shell=True).stdout)
    if xpwr_banner == "b''":
        #print("Couldn't get background application. | No app visible.")
        return 1
    else:
        #print(xpwr_banner)
        xpwr_banner = xpwr_banner.replace("b", "", 1).replace("'", "")
        xpwr_banner = xpwr_banner.replace("\\r", "").replace("\\n", "").split(" ")
        full_version = xpwr_banner[1]
        if "/" in full_version:
            product = full_version.split("/")[0].lower()
            version = full_version.split("/")[1]
            if "-" in version:
                version = version.split("-")[0]
        else:
            product = full_version.lower()
    #print("product", product)
    #print("version", version)
    return [product, version]


def insert_db(scantime, host, port, vendor,
              product, version, vendor_update):
    part = 'a'
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor()
    insert_query = "insert into scanner_services (ScanInitTime, host, port, part, vendor, product, version, vendor_update) \
                    values(%s, %s, %s, %s, %s, %s, %s, %s)"
    try:
        cursor.execute(
        insert_query,
        (scantime,
        host,
        port,
        part,
        vendor,
        product,
        version,
        vendor_update)
        )
    except Exception as e:
        print("Error while inserting into DB:", e)
        cnx.commit()
        cnx.close()
        return 1
    cnx.commit()
    cnx.close()
    return 0
