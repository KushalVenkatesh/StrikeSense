#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import socket
import datetime
import mysql.connector

import AuthDB
import scanner

def scanner(host, flag, start_port, end_port):
    open_ports = []
    if flag:                                 # The flag is set, means the user did not give any port range
        for port in sorted(common_ports):
            sys.stdout.flush()
            print(str(port))
            response = check(host, p)
            if not response:
                open_ports.append(port)
    else:
        for port in range(start_port, end_port+1):
            sys.stdout.flush()
            print(str(port))
            response = check(host, p)
            if not response:
                open_ports.append(port)
    if open_ports:
        print("Open Ports: ")
        for port in sorted(open_ports):
            service = get_service(str(port))
            if not service: # The service is not in the dictionary
                service = "Unknown service"
            print("\t%s %s: Open" % (port, service))
    else:
        print("No open ports found.")

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
            if port == '22' or port=='80' or port=='443':       #get services if port open
                scanner.get_services(host, port)
        sock.close()
    except Exception as e:
        print("[-]Exception encountered:", str(e))
    return result

def get_service(port):
	if port in common_ports: # check if the port is available in the common ports dictionary
		return common_ports[port]
	else:
		return 0
