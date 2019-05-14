#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import paramiko
import time
import datetime
import mysql.connector
from subprocess import PIPE, run

#importing from package
import AuthDB


def get_windows(username, password, host, usrdomain):
    #usrdomain = "acpl.com"
    userdetail = usrdomain+"\\\\"+username+"%"+password
    command = "wmic os get caption, buildnumber, csdversion /value"
    #args = "os get caption, buildnumber, csdversion /value"
    win_data = win_details = version = caption = vendor = product = update = ''
    query = r'/usr/bin/winexe -U "'+userdetail+'" //'+host+' "'+command+'"'
    #print("win_query: ", query)
    try:
        win_data = run(query, stdout=PIPE, stderr=PIPE, shell=True).stdout #.returncode
    except Exception as e:
        print("win_exe error: ",e)
    if win_data != '':
        #print("win_data: ", win_data)
        win_details = str(win_data).split("\\r")
        for item in win_details:
            if "BuildNumber" in item:
                version = item.replace("BuildNumber=", "").replace("\\n", "")
            if "Caption" in item:
                caption = item.replace("Caption=", "").replace("\\n", "")
                #add code to retreive vendor and product from Caption
                vendor = caption.split(" ")[0].strip().lower()
                product = caption.replace(caption.split(" ")[0], "").replace(caption.split(" ")[-1], "").strip().replace(" ", "_").lower()
            if "CSDVersion" in item:
                update = item.replace("CSDVersion=", "").replace("\\n", "")
    else:
        print("Error encountered")
    return [version, vendor, product, update]

def get_linux(username, password, hostname):
    product = version = kern_ver = ''
    rel_data = linux_details(username, password, hostname)
    if rel_data != -1:
        product = rel_data[0]
        version = rel_data[1]
        #cpe_name = rel_data[2]
    else:
        print("No data from linux_details.")
    uname_data = linux_detail_uname(username, password, hostname)
    if uname_data != -1:
        kern_ver = uname_data
    else:
        print("No data from linux_detail_uname")
        return -1

    #print("product:", product)
    #print("version:", version)
    #print("cpe_name:", cpe_name, type(cpe_name))
    #print("kern_ver:", kern_ver)
    #return [version, product, kern_ver, cpe_name]
    return [version, product, kern_ver]

def linux_details(username, password, hostname):
    nbytes = 4096
    port = 22
    version = product = ''
    read_release_file = 'cat /etc/os-release'
    client = paramiko.Transport((hostname, port))
    try:
        client.connect(username=username, password=password)
    except Exception as e:
        print("Connection Error:", e)
        return -1

    release_out_data = ''
    release_err_data = ''
    session = client.open_channel(kind='session')
    session.exec_command(read_release_file)
    time.sleep(1)
    while True:
        if session.recv_ready():
            release_out_data = release_out_data+str(session.recv(nbytes))
        if session.recv_stderr_ready():
            release_err_data = release_err_data+str(session.recv_stderr(nbytes), 'utf-8')
        if session.exit_status_ready():
            break

    #print('exit status: ', session.recv_exit_status())

    for item in release_out_data.split("\\n"):
        if 'VERSION_ID=' in item:
            item = item.replace('VERSION_ID=', '').replace('"', '')
            version = item
        elif 'ID=' in item:
            item = item.replace('ID=', '').replace('"', '')
            product = item
        '''
        elif 'CPE_NAME=' in item:
            item = item.replace('CPE_NAME=', '').replace('"', '')
            cpe_name = item
        '''
        #print(item)

    #print("product:", product)
    #print("version:", version)
    #print("cpe_name:", cpe_name)

    session.close()
    client.close()
    #return 0
    #return [product, version, cpe_name]
    return [product, version]

def linux_detail_uname(username, password, hostname):
    nbytes = 4096
    port = 22
    read_uname = "uname -r"
    client = paramiko.Transport((hostname, port))
    try:
        client.connect(username=username, password=password)
        #time.sleep(1)
    except Exception as e:
        print("Connection Error:", e)
        return -1
    uname_out_data = ''
    uname_err_data = ''
    session = client.open_channel(kind='session')
    session.exec_command(read_uname)
    time.sleep(1)
    while True:
        if session.recv_ready():
            #print(str(session.recv(nbytes)))
            uname_out_data = uname_out_data+str(session.recv(nbytes))
            #time.sleep(3)
        if session.recv_stderr_ready():
            uname_err_data = uname_err_data+str(session.recv_stderr(nbytes), 'utf-8')
        if session.exit_status_ready():
            break
    #print('exit status: ', session.recv_exit_status())
    #print(uname_out_data)
    kernel_ver = uname_out_data.replace('b','').replace('\\n','').replace("'","")
    #print(kernel_ver)
    session.close()
    client.close()
    return kernel_ver

#do we need to make 2 entries for linux? onw with name other as 'linux_kernel' with kernel rev as version

def insert_linux_db(scantime, host, vendor, product, version, kern_ver):
    l_vendor = 'linux'
    l_product = 'linux_kernel'
    vendor_update = ''
    ret_name = insert_db(scantime, host, vendor, product,
                              version, vendor_update)
    ret_kern = insert_db(scantime, host, l_vendor, l_product,
                              kern_ver, vendor_update)
    if ret_name or ret_kern:
        print("Linux host insertion failed")
        return 1
    return 0


def insert_db(scantime, host, vendor, product, version, vendor_update):
    part = "o"
    #now = datetime.datetime.now()
    #date_t = now.strftime("%Y-%m-%d %H:%M:%S")
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor()
    insert_query = "insert into scanner_hosts (ScanInitTime, host, part, vendor, product, version, vendor_update) \
                    values(%s, %s, %s, %s, %s, %s, %s)"
    try:
        cursor.execute(
            insert_query,
            (scantime,
            host,
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
