#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import sys
import socket
import datetime
import mysql.connector

import AuthDB
import service

common_ports = {
    '21': 'FTP',
	'22': 'SSH',
	'23': 'TELNET',
	'25': 'SMTP',
	'53': 'DNS',
	'69': 'TFTP',
	'80': 'HTTP',
	'109': 'POP2',
	'110': 'POP3',
	'123': 'NTP',
	'137': 'NETBIOS-NS',
	'138': 'NETBIOS-DGM',
	'139': 'NETBIOS-SSN',
	'143': 'IMAP',
	'156': 'SQL-SERVER',
	'389': 'LDAP',
	'443': 'HTTPS',
	'546': 'DHCP-CLIENT',
	'547': 'DHCP-SERVER',
	'995': 'POP3-SSL',
	'993': 'IMAP-SSL',
	'2086': 'WHM/CPANEL',
	'2087': 'WHM/CPANEL',
	'2082': 'CPANEL',
	'2083': 'CPANEL',
	'3306': 'MYSQL',
	'8443': 'PLESK',
	'10000': 'VIRTUADMIN/WEBMIN'}

def scan(host, flag, start_port, end_port):
    print("~"*60)
    print("=> Services on open ports:\n")
    now = datetime.datetime.now()
    scantime = now.strftime("%Y-%m-%d %H:%M:%S")
    open_ports = []
    p_service = 1
    if flag:                                 # The flag is set, means the user did not give any port range
        for port in sorted(common_ports):
            sys.stdout.flush()
            #print(str(port))
            response = check(host, int(port))
            if not response:
                open_ports.append(port)
                if port=="22" or port=="80" or port=="443":
                    p_service = 0
    else:
        #print(type(start_port), type(end_port))
        for port in range(int(start_port), int(end_port)+1):
            sys.stdout.flush()
            #print(str(port))
            response = check(host, port)
            if not response:
                open_ports.append(port)
                if port=="22" or port=="80" or port=="443":
                    p_service = 0
    if p_service:
        print("\tNo open ports with services found.")
    if open_ports:
        print("~"*60)
        print("=> Open Ports: \n")
        for port in sorted(open_ports):
            service = get_service(str(port))
            if not service: # The service is not in the dictionary
                service = "Unknown service"
            print("\t%s\t%s: Open" % (port, service))
            insert_db(scantime, host, int(port))
    else:
        print("\tNo open ports with services found.")
        print("~"*60)
        print("=> Open Ports: \n")
        print("\tNo open ports found.")
    print("\n")

def check(host, port):
    result = 1
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
		# Connect to the socket
		# if the connection was successful, that means the port
		# is open, and the output 'reply' will be zero
        reply = sock.connect_ex((host, port))
        if not reply:
            result = 0
            if port==22 or port==80 or port==443:       #get services if port open
                get_port_services(host, str(port))
        sock.close()
    except Exception as e:
        print("[-]Exception encountered:", str(e))
    return result

def get_service(port):
	if port in common_ports: # check if the port is available in the common ports dictionary
		return common_ports[port]
	else:
		return 0

def get_port_services(host, port):
    print("\t[+] Port "+port+" -->")
    inserted = 0                                        #tells if the records are already inserted in db
    now = datetime.datetime.now()
    date_t = now.strftime("%Y-%m-%d %H:%M:%S")
    product = version = vendor = vendor_update = ''
    part = 'a'
    if port == '22':
        display = ""
        ssh = service.get_ssh(host, int(port))
        if ssh != 1:
            product = ssh[0]
            version = ssh[1]
            vendor_update = ssh[2]
            if product != '':
                display += "\t\tProduct : "+product+"\n"
            if version != '':
                display += "\t\tVersion : "+version+"\n"
            if vendor_update != '':
                display += "\t\tVendor Update : "+vendor_update+"\n"
        else:
            display += "\t\tCouldn't get SSH details.\n"
            print(display)
    elif port == '80' or port == '443':
        display = ""
        web_srv = service.get_webserver(host, port)
        display += "\t\tWebserver details:\n"
        if web_srv != 1:
            vendor = web_srv[0]
            product = web_srv[1]
            version = web_srv[2]
            if vendor != '':
                display += "\t\t\tVendor : "+vendor+"\n"
            if product != '':
                display += "\t\t\tProduct : "+product+"\n"
            if version != '':
                display += "\t\t\tVersion : "+version+"\n"
            service.insert_db(date_t, host, port, vendor,
                              product, version, vendor_update)
            inserted = 1
        else:
            display += "\t\t\tCouldn't get webserver details.\n"
            #print(display)
        xpwr_srv = service.get_poweredby(host, port)
        product = version = vendor = vendor_update = ''         #makes sure that values do not get carried over from port 80
        display += "\t\tBackground application details:\n"
        if xpwr_srv != 1:
            product = xpwr_srv[0]
            version = xpwr_srv[1]
            if product != '':
                display += "\t\t\tProduct : "+product+"\n"
            if version != '':
                display += "\t\t\tVersion : "+version+"\n"
            service.insert_db(date_t, host, port, vendor,
                              product, version, vendor_update)
            inserted = 1
        else:
            display += "\t\t\tNo background app visible.\n"
    print(display)
    if not inserted:                                       #insert in db if not already inserted
        if product == version == vendor == vendor_update == '':
            return 1
        else:
            service.insert_db(date_t, host, port, vendor,
                              product, version, vendor_update)

def insert_db(scantime, host, port):
    #now = datetime.datetime.now()
    #date_t = now.strftime("%Y-%m-%d %H:%M:%S")
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor()
    insert_query = "insert into scanner_ports (ScanInitTime, host, port) \
                    values(%s, %s, %s)"
    try:
        cursor.execute(
            insert_query,
            (scantime,
            host,
            port)
            )
    except Exception as e:
        print("Error while inserting into DB:", e)
        cnx.commit()
        cnx.close()
        return 1
    cnx.commit()
    cnx.close()
    return 0
