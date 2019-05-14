#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import os
import time
from datetime import datetime
import re
import mysql.connector
from subprocess import PIPE, run
import csv
import AuthDB


def current_proj_path():
    return os.path.dirname(os.path.abspath(__file__))


def try_parsing_date(data):
    #this function is use to convert endpoint time to mysql time formate
    #in for loop more time formate add according to endpoint time formate
    for fmt in ('%d-%m-%Y %I:%M:%S %p', '%d/%m/%Y %I:%M:%S %p',\
    '%d-%m-%Y %H:%M:%S','%d/%m/%Y %H:%M:%S','%m/%d/%Y %I:%M:%S %p'):
        try:
            #print(datetime.strptime(data, fmt))
            return datetime.strptime(data, fmt)
        except ValueError:
            pass


def push_files(HOST,AUTH,Domain):
        #this function is use for pull file and execute on endpoint
        pre_path="C:\Windows"
        share_path='SCANNER'
        scanner_path=current_proj_path()  #"/opt/ECR"
        com_path=pre_path+"\\"+share_path
        create_dir = "smbclient //'" + HOST + "'/admin$ -U '"+AUTH+"' -c \
        'lcd "+scanner_path+"; mkdir "+share_path+"\' -mSMB2"
        send_ps_file="smbclient //'" + HOST + "'/admin$ -U '"+AUTH+"' -c \
        'lcd "+scanner_path+"; cd "+share_path+"; prompt; mput get_ip.ps1 \
        ' -mSMB2"
        send_ps_file1="smbclient //'" + HOST + "'/admin$ -U '"+AUTH+"' -c \
        'lcd "+scanner_path+"; cd "+share_path+"; prompt; mput get_user_ad.ps1 \
        ' -mSMB2"
        #print(send_ps_file1,"+++++++++++++++++++++++++++")
        #print(create_dir,"--------------------------------------------------------")
        print("[+] Found Domain Controller:", str(HOST))
        print("[+] Triggered Host discovery on:", str(HOST))
        #print(create_dir)
        out = os.system(create_dir)
        #print(out)
        #check connection
        if out == 0:
            rv1 = os.system(send_ps_file)
            rv2 = os.system(send_ps_file1)
            cmd=com_path+"\\get_ip.ps1 -path "+com_path
            cmd1=com_path+"\\get_user_ad.ps1 -OuOnly | Export-csv "\
            +com_path+"\\active_users.csv"
            #-LastLogonOnly -OuOnly -MaxEvent 10000
            #winexe querys
            query= r'/usr/bin/winexe -U"'+ AUTH + '" //' + HOST +' '+  '\
            "powershell.exe -command ' + cmd +' "'
            query1= r'/usr/bin/winexe -U"'+ AUTH + '" //' + HOST +' '+  '\
            "powershell.exe -command ' + cmd1 +' "'
            #print(query)
            #print(query1)
            #retval = run(update_dns, stdout=PIPE, stderr=PIPE, shell=True).returncode
            #execute winexe query
            retval = run(query, stdout=PIPE, stderr=PIPE, shell=True).returncode                    # universal_newlines=True,
            retval = run(query1, stdout=PIPE, stderr=PIPE, shell=True).returncode
            print("ep_push_exec: ", retval)
            #pull file from host
            download_file = "smbclient //'"+ HOST +"'/admin$ -U '"+AUTH+"' -c \
            'lcd "+ scanner_path +"; cd "+share_path+"; prompt OFF; mget ip_address.csv \
            ' -mSMB2"
            os.system(download_file)
            download_file1 = "smbclient //'"+ HOST +"'/admin$ -U '"+AUTH+"' -c \
            'lcd "+ scanner_path +"; cd "+share_path+"; prompt OFF; mget active_users.csv \
            ' -mSMB2"
            #print(download_file)
            rv3 = os.system(download_file1)
            #check file pull successful
            if retval == 0:
                #after pull file call this function
                insert_data_db(Domain,scanner_path)
                insert_user(HOST,scanner_path)
            else:
                print("Unable to insert data : 0")
        else:
            print("connection error",HOST)
        print("[+] Host Discovery ended")

def insert_user(HOST,scanner_path):
    #this function is use for inserting active use in scanner_computer_info
    #get input form active_user.csv file and insert in db
    path=scanner_path+"/active_users.csv"
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor(buffered=True)
    check_table()
    with open(path, 'r') as fin:
        data = fin.read().splitlines(True)
    with open(path, 'w') as fout:
        #remove top 2 line from active_users.csv
        fout.writelines(data[2:])
    with open (path, 'r') as data:
        reader = csv.reader(data)
        for row in reader:
            row=[w.replace('localhost', HOST) for w in row]
            data=row[1]
            '''print(data,"----------------------")
            data1=data.replace('-','/')
            print(data1,"==============================")
            logon_time=datetime.strptime(data1, '%d/%m/%Y %H:%M:%S')
            '''
            logon_time1=try_parsing_date(data)
            if logon_time1 is not None:
                logon_time=str(logon_time1)
                user=row[2]
                ip=row[5]
                #this query give logon_time for a ip
                select_query="select logon_time from scanner_computer_info \
                where ip_addr='"+ip+"';"
                cursor.execute(select_query)
                row_data = cursor.fetchone()
                try:
                    if row_data[0] == None:
                        #if logon_time is null and insert logon_time
                        query="update scanner_computer_info set user_name=\
                        '"+user+"',logon_time='"+logon_time+"' where ip_addr=\
                        '"+ip+"' ;"
                        #print(query)
                        cursor.execute(query)
                    else:
                        #if logon_time is not null then check logon time in table is smaller or not
                        #if smaller then update
                        query="update scanner_computer_info set user_name=\
                        '"+user+"',logon_time='"+logon_time+"' where ip_addr=\
                        '"+ip+"' and logon_time <'"+logon_time+"';"
                        #print(query)
                        cursor.execute(query)
                    #print(query)
                    cnx.commit()
                except:
                    pass
    print("[+] Active users updated in database.")
    cursor.close()
    cnx.close()


def insert_data_db(Domain,scanner_path):
    #this function is use to insert ip address of domain computer in acr_ecr_computer_info
    path=scanner_path+"/ip_address.csv"
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor()
    check_table()
    with open (path, 'r') as data:
        reader = csv.reader(data)
        for row in reader:
            #datum = ','.join(row)
            os_srv_pack=row[4]
            try:
                os_ver=row[3].split('(', 1)[1].strip(')') or 'NULL'
                #print(os_ver)
            except:
                os_ver=row[3].strip()
            ip=row[2]
            fqdn=row[0]
            data=fqdn.split('.',2)
            Domain=str(data[1])
            window_ver=str(row[1])
            #print(Domain)
            if "Windows Server" in window_ver:
                win_typ="6"
            elif "Windows" in window_ver or "windows" in window_ver:
                win_typ="7"
            else:
                win_typ="8"
            select="select * from scanner_computer_info where fqdn='"+fqdn+"';"
            #print(select,"+++++++++++++++++++++++++++++++++++++++++++++++++++++")
            query1= "insert into scanner_computer_info (ip_addr,fqdn,\
            windows_ver,dev_gr_id,os_ver,os_srv_pack) values(%s, %s, %s, %s, %s, %s);"
            #print(query1)
            cursor.execute(select)
            select_data = cursor.fetchone()
            if select_data is None:
                try:
                    cursor.execute(query1,(ip,fqdn,window_ver,win_typ,os_ver,os_srv_pack))
                    cnx.commit()
                    #print("insert_data_db: 0")
                except Exception as e:
                    pass
                    #print(e)
                    #print("Try Again")
            else:
                update="update scanner_computer_info set ip_addr='"+ip+"',\
                windows_ver='"+window_ver+"',os_srv_pack='"+os_srv_pack+"',\
                os_ver='"+os_ver+"' where fqdn='"+fqdn+"';"
                #print(update)
                cursor.execute(update)
                cnx.commit()
    print("[+] Hosts updated in database.")
    cursor.close()
    cnx.close()

def check_table():
    #check table present or not in db
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor(buffered=True)
    sh_table = ("Show tables like 'scanner_computer_info';")
    cursor.execute(sh_table)
    row_data = cursor.fetchone()
    #print(row_data)
    if row_data is None:
        create_table="CREATE TABLE scanner_computer_info\
        (id int NOT NULL AUTO_INCREMENT,ip_addr varchar(50) DEFAULT NULL,\
        fqdn text,windows_ver text,dev_gr_id int(11) DEFAULT NULL,\
        os_ver text,os_srv_pack text ,user_name varchar(20) DEFAULT NULL,\
        logon_time datetime, created datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,\
        lastupdated datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP\
        , PRIMARY KEY (id));"
        try:
            status=cursor.execute(create_table)
        except:
            pass
    cursor.close()
    cnx.close()


def get_id():
    #this function return group id
    #function use scanner_device_group table
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor(buffered=True)
    query_get_id =("select * from scanner_device_group where dev_gr_type ='MICROSOFT_SERVERS';")
    cursor.execute(query_get_id)
    row_data = cursor.fetchone()
    dev_grp_id=str(row_data[0])
    #print(dev_grp_id)
    cursor.close()
    cnx.close()
    return dev_grp_id


def get_ip():
    #this is main function
    retval=1
    #get device group id
    dev_grp_id = get_id()
    cnx = mysql.connector.connect(**AuthDB.config)
    cursor = cnx.cursor()
    query_get = ("select mgmt_uid,mgmt_pwd,mgmt_ip_addr,\
    fqdn from scanner_device_info where dev_gr_id ='"+dev_grp_id+"'")
    cursor.execute(query_get)
    row_data = cursor.fetchone()
    while row_data is not None:
        User =row_data[0]
        Password = row_data[1]
        HOST = row_data[2]
        Domain1 = row_data[3]
        #print(Domain1)
        data=Domain1.split('.',2)
        print(data)
        Domain=str(data[1])
        AUTH = Domain+"\\"+User+"%"+Password
        push_files(HOST,AUTH,Domain)
        row_data = cursor.fetchone()
    cursor.close()
    cnx.close()


#if __name__ == "__main__":
#    get_ip()
