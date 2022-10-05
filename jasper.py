# MIT License
#
# Copyright (c) 2021 Hamad ALSHEHHI
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


#! /usip=Nonenv python3
import datetime
import multiprocessing
import time
from multiprocessing import Process, current_process

import keyboard
from PyQt5.QtWidgets import QApplication
from pyfiglet import Figlet
from scapy.all import *
from scapy.layers.http import http_request
from termcolor import colored
from dialogsGUI import *
from tqdm import tqdm
import prettytable
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from socket import getservbyname, getservbyport
from modules.pygmaps import pygmaps
import datetime as date
import pandas as pd
import numpy as np
import binascii



try:
    from scapy.all import *
except:
    print("pip3 install --pre scapy[complete]")

import sys


f = Figlet(font='standard')


conf.verb=1
ifacelist=[]
pkt= ""
ans_arpPing= ""
unans_arpPing=""
def advanceMode():
    interact(mydict=globals(),mybanner="== Jasper Advanced Mode ==",loglevel=2,)


def arpPing(net):
    ans=""
    if(net==""):
        print(colored("Enter The Network Details,ex: 192.168.1.0/24", "yellow"))
        print(conf.route)
        network=input()
    else:
        network=net
    try:
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),timeout=2)
    except OSError:
        print(colored("Unable To Scan The Network","red"))
        mainmenu()
        #raise Scapy_Exception("No host in the provided network")
    if(net==""):
        print (r"List of all hosts in the network:")
        for snd,rcv in ans:
            print (rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))
        input(colored("Press Enter To Return Back To Main Menu","yellow"))
    return ans, unans

def readPCAP(file):
    global pkt
    try:
        print("Reading.............",end='',flush=True)

        pkt=rdpcap(filename=file)
        print("[Completed]")
    except:
        print("Not able to read the file")

    return pkt

def savePCAP(file,pkt):
    try:
        wrpcap(filename=file,pkt=pkt)
    except:
        print("Not able to save the file")

#advanceMode()

def liveSniffing():
    global ifacelist
    if (len(ifacelist)==0):
        listeniface=conf.iface
    else:
        listeniface=ifacelist

    print(colored("Sniffig Traffic Will Start Using Interace: ","yellow"),listeniface)
    print(colored("To Stop Sniffing Use: ","yellow"),'Ctrl c')
    while (True):
        print(colored("To Start Sniffing Choose The Mode:\ns- Summery Mode\nd- Detailed Mode\nc- Cancel","yellow"))
        inp=input()
        if(inp =='d'):
            pkt=sniff(iface=listeniface,prn=lambda x:x.sniffed_on+": "+str(x.show()))
            break
        else:
            if(inp =='s'):
                pkt=sniff(iface=listeniface,prn=lambda x:x.sniffed_on+": "+str(x.summary()))
                break
            else:
                if(inp=="c"):
                    mainmenu()
                else:
                    print(colored("Wrong Opt","red"))

    return pkt


def addInterface():
    global ifacelist
    print(colored("Control One Or Multiple Interfaces At The Same Time","yellow"))
    print(colored("Current Used Interface(s):", "green"), ifacelist)
    while (True):
        print(colored("Add Interface ID From The List, 99 To Return Back To Main Menu:","yellow"))

        print("ID\t","NAME\t","IP\t\t", "MAC")
        for x in ifaces:
            print(ifaces.dev_from_name(x).index," \t",ifaces.dev_from_name(x).name," \t",ifaces.dev_from_name(x).ip," \t",ifaces.dev_from_name(x).mac)
        inp=input()
        if(inp=="99"):
            mainmenu()
        try:
            if(ifaces.dev_from_index(inp).name not in ifacelist):
                ifacelist+=[ifaces.dev_from_index(inp).name]
            print(colored("Current Used Interface(s):", "green"), ifacelist)
        except:
            print(colored("Interface Not Found", "red"))

    return ifacelist

def removeInterface():
    global ifacelist
    print(colored("Control One Or Multiple Interfaces At The Same Time","yellow"))
    print(colored("Current Used Interface(s):", "green"), ifacelist)
    while (True):
        print(colored("Remove Interface ID From The List, 99 To Return Back To Main Menu:","yellow"))

        print("ID\t","NAME\t","IP\t\t", "MAC")
        for x in ifaces:
            print(ifaces.dev_from_name(x).index," \t",ifaces.dev_from_name(x).name," \t",ifaces.dev_from_name(x).ip," \t",ifaces.dev_from_name(x).mac)
        inp=input()
        if(inp=="99"):
            mainmenu()
        try:
            if(ifaces.dev_from_index(inp).name in ifacelist):
                ifacelist.remove(ifaces.dev_from_index(inp).name)
            print(colored("Current Used Interface(s):", "green"), ifacelist)
        except:
            print(colored("Interface Not Found", "red"))
    return ifacelist

def scanOpenPorts():
    global ans_arpPing,unans_arpPing
    hostListIP=[]
    hostListMAC=[]
    ##add the technique, scan using SYN,Fin, XMAS
    if(len(ans_arpPing)==0):
        print(colored("The Host List is Empty, Kindly Choose an Option:\na- Back to Main Menue, Then"
                      " Choose List Hosts From Scan Section\nb- Enter IP Manually","yellow"))
        opt=input()
        if (opt =="a"):
            mainmenu()
        else:
            if(opt=="b"):
                ip=input("Enter The IP Address:")
    else:
        print(colored("Choose The Index Number For IP Address From The List:","yellow"))
        for snd, rcv in ans_arpPing:
            hostListIP+=[rcv.sprintf(r"%ARP.psrc%")]
            hostListMAC += [rcv.sprintf(r"%Ether.src%")]
        i=0
        table1=prettytable.PrettyTable(["INDEX","IP ADDRESS", "MAC"])
        table1.align["INDEX"] = "l"
        #print("INDEX", "IP Address", "\t", "MAC")
        while(i<len(hostListIP)):
            #print(i,"-",hostListIP[i],"\t",hostListMAC[i])
            table1.add_row([i,hostListIP[i],hostListMAC[i]])

            i+=1
        table1.add_row(['m', "Manual", "Manual"])
        print(table1)
        while(True):
            inp=input("$>: ")
            if(inp.isdigit()):
                inp=int(inp)
                if(inp<=len(hostListIP)):
                    ip = hostListIP[inp]
                    break
                else:
                    print(colored("Worng Option","red"))
            else:
                if(inp=='m'):
                    ip = input("Enter The IP Address:")
                    break
                else:
                    print(colored("Worng Option", "red"))

            print(colored("Choose The Index Number For IP Address From The List:","yellow"))
            i=0
            print(table1)

    print(colored("Scanning "+ip,"green"),"\t\t"+"Esc To Stop")
    table2=prettytable.PrettyTable(["Port Number","Port Name","Status"])

    for p in range(0,40404,100):
        ans, unans = sr(IP(dst=ip) /TCP(dport=[i for i in range(p, p+100)], sport = RandShort(), flags = "S"), timeout = 15,verbose=0)
        #ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",prn = lambda s, r: r.sprintf("%TCP.sport% is open\t [TCP]"))
        ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: table2.add_row([getservbyname(r.sprintf("%TCP.sport%")),r.sprintf("%TCP.sport%") ,"Open"]))
        #TODO: add stealth scanning
        time.sleep(0.5)
        os.system("clear")
        print(colored("IP:" + ip, "green"), "\t\t" + "Esc To Stop")

        print("[",p+100 ," Ports Scanned]\t\t Esc To Stop")
        print(table2)
        try:
            if(keyboard.is_pressed("Esc")):
                print("Exiting the San!")
                break
        except:
            #            print(colored("Permission Required for Terminal in OS","red"))
            continue
    return table2

def scanOpenPortsMass():
    global ans_arpPing,unans_arpPing
    hostListIP=[]
    hostListMAC=[]
    ip=[]
    ##add the technique, scan using SYN,Fin, XMAS
    if(len(ans_arpPing)==0):
        print(colored("The Host List is Empty, Kindly Choose an Option:\na- Back to Main Menue, Then"
                      " Choose List Hosts From Scan Section\nb- Enter IP Manually","yellow"))
        opt=input()
        if (opt =="a"):
            mainmenu()
        else:
            if(opt=="b"):
                ip=input("Enter The IP Addresses:")
    else:
        print(colored("Choose The Index Number For IP Address From The List:","yellow"))
        for snd, rcv in ans_arpPing:
            hostListIP+=[rcv.sprintf(r"%ARP.psrc%")]
            hostListMAC += [rcv.sprintf(r"%Ether.src%")]
        i=0
        table1=prettytable.PrettyTable(["INDEX","IP ADDRESS", "MAC"])
        table1.align["INDEX"] = "l"
        #print("INDEX", "IP Address", "\t", "MAC")
        while(i<len(hostListIP)):
            #print(i,"-",hostListIP[i],"\t",hostListMAC[i])
            table1.add_row([i,hostListIP[i],hostListMAC[i]])

            i+=1
        table1.add_row(['m', "Other IP", "Manual"])
        table1.add_row(['s', "Start Scanning", ""])
        table1.add_row(['b', "Back To Main Menu", ""])
        print(table1)
        while(True):
            inp=input("$>: ")
            if(inp.isdigit()):
                inp=int(inp)
                if(inp<=len(hostListIP) ):
                    if(hostListIP[inp] not in ip):
                        ip += [hostListIP[inp]]
                    print(colored("Scan List= " + str(ip), "yellow"))
                else:
                    print(colored("Worng Option","red"))
            else:
                if(inp=='m'):
                    tmp = [input("Enter The IP Address:")]
                    if(tmp not in ip):
                        ip +=tmp
                        print(colored("Scan List= " + str(ip), "yellow"))
                else:
                    if(inp=='s'):
                        break
                    else:
                        if(inp=="b"):
                            mainmenu()
                        else:
                            print(colored("Worng Option", "red"))

            print(colored("Choose The Index Number For IP Address From The List:","yellow"))
            i=0
            print(table1)

    print(colored("Scanning "+str(ip),"green"),"\t\t"+"Esc To Stop")
    table2=prettytable.PrettyTable(["Port Number","Port Name","IP Address","Status"])
    i=0
    for p in range(1,40404,100):
        ans,unans= sr(IP(dst=ip) /TCP(dport=[i for i in range(p, p+100)], sport = RandShort(), flags = "S"), timeout = 15,verbose=0)
        #ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",prn = lambda s, r: r.sprintf("%TCP.sport% is open\t  %IP.src%"))
        ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: table2.add_row([getservbyname(r.sprintf("%TCP.sport%")),r.sprintf("%TCP.sport%") ,r.sprintf("%IP.src%"),"Open"]))
        #ans.filter(lambda s, r: TCP in r and r[TCP].flags & 2).make_table(lambda s, r: (s.dst,s.dport, "X"))
        #TODO: add stealth scanning
        time.sleep(0.5)
        os.system("clear")
        print("[",p+100 ," Ports Scanned]\t\t Esc To Stop")
        print(table2.get_string(sortby="IP Address"))

        try:
            if(keyboard.is_pressed("Esc")):
                print("Exiting the San!")
                break
        except:
            #            print(colored("Permission Required for Terminal in OS","red"))
            continue

    return table2

def tcpTraceRoute(ip):
    if (ip == ""):
        ipaddress = input(colored("Enter IP Address:", "yellow"))
    else:
        ipaddress=ip
    paths=[]
    locations=[]
    traceRoutelist =[]
    ans,uans=traceroute(ipaddress,verbose=0)

        ##TCP traceroute
        #ans, unans = sr(IP(dst=ip, ttl=(4, 25), id=RandShort()) / TCP(flags=0x2))
    try:
        for snd, rcv in ans:
            paths+=[[snd.ttl, rcv.src, isinstance(rcv.payload,TCP)]]
            if(isinstance(rcv.payload,TCP)):
                break # if the right ip address for the domain detected then break
    except:
        print(colored("Unable to execute traceroute!", "red"))
        mainmenu()

    # Take the IP address only and translate it using ip-api.com service
    for p in paths:
        #print(p[1])
        req=http_request("ip-api.com", "/csv/"+p[1])
        for r in req:
             locations+=[str(r.load).split(",")]
    traceRouteTable=prettytable.PrettyTable(["TTL","IP Address","Translation","Country","City","Latitude","Longitude","Company"])
    traceRoutelist=[["TTL","IP Address","Translation","Country","City","Latitude","Longitude","Company"]]
    i=0
    for data in locations:

        if(data[0]=="b'success"):
            traceRouteTable.add_row([paths[i][0],paths[i][1],data[0],data[1],data[5],data[7],data[8],data[10]])
            traceRoutelist+=[[paths[i][0],paths[i][1],data[0],data[1],data[5],data[7],data[8],data[10]]]
        else:
            traceRouteTable.add_row([paths[i][0],paths[i][1],data[0],data[1],"","","",""])
            traceRoutelist+=[[paths[i][0], paths[i][1], data[0], data[1], "", "", "", ""]]
        i+=1

    if(ip==""):
        print(traceRouteTable)

    return traceRouteTable,traceRoutelist


def resolveDNS(ip):

    if (ip == ""):
        ipaddress = input(colored("Enter Domain name or IP Address:", "yellow"))
    else:
        ipaddress = ip
    paths = []
    locations = []
    ans, uans = traceroute(ipaddress, verbose=0)

    try:
        for snd, rcv in ans:
            if (isinstance(rcv.payload, TCP)):
                paths += [[snd.ttl, rcv.src, isinstance(rcv.payload, TCP)]]
                break  # if the right ip address for the domain detected then break
    except:
        print(colored("Unable to Resolve IP!", "red"))
        mainmenu()

    print (ipaddress)
    print (paths)

    # Take the IP address only and translate it using ip-api.com service

    # print(p[1])
    ResolveTable = prettytable.PrettyTable(
        ["TTL", "IP Address", "Translation", "Country", "City", "Latitude", "Longitude", "Company"])
    try:
        req = http_request("ip-api.com", "/csv/" + paths[0][1])
        for r in req:
            locations += [str(r.load).split(",")]

        i = 0
        for data in locations:
            if (data[0] == "b'success"):
                ResolveTable.add_row([paths[i][0], paths[i][1], data[0], data[1], data[5], data[7], data[8], data[10]])
            else:
                ResolveTable.add_row([paths[i][0],paths[i][1],data[0],data[1],"","","",""])
            i += 1

    except Exception as e:
        print (e)

    if (ip == ""):
        print(ResolveTable)

    return ResolveTable
#function require list not string
def ipAddressDetails(listIps):
    global tracerouteList

    locations = []
    # print(p[1])
    ResolveTable = prettytable.PrettyTable(
        ["TTL", "IP Address", "Translation", "Country", "City", "Latitude", "Longitude", "Company"])
    traceRoutelist=[["TTL","IP Address","Translation","Country","City","Latitude","Longitude","Company"]]
    idx=0
    try:
        for ip in listIps:
            print (idx,ip)

            req = http_request("ip-api.com", "/csv/" + str(ip))
            for r in req:
                locations += [str(r.load).split(",")]

            i = 0
            for data in locations:
                if (data[0] == "b'success"):
                    ResolveTable.add_row([idx, ip, data[0], data[1], data[5], data[7], data[8], data[10]])
                    traceRoutelist += [
                        [idx, ip, data[0], data[1], data[5], data[7], data[8], data[10]]]
                else:
                    ResolveTable.add_row([idx,ip,data[0],data[1],"","","",""])
                    traceRoutelist += [[idx, ip, data[0], data[1], "", "", "", ""]]
                i += 1
                idx+=1
            locations = []

    except Exception as e:
        print (e)

    print (ResolveTable)
    tracerouteList=traceRoutelist
    geoShow(tracerouteList,passive=1)

    return ResolveTable,tracerouteList

def geoShow(path,passive):
    global tracerouteTable,tracerouteList
    points = []
    #print(path)
    if(passive==0):
        if (path ==""):
            print(colored("The Path Tracing is Empty, Kindly Choose an Option:\na- Enter IP or Domain Manually\nb- Back to Main Menue", "yellow"))
            while(True):
                opt = input()
                if (opt == "b"):
                    mainmenu()
                else:
                    if (opt == "a"):
                        ip = input("Enter The IP or Domain Name:")
                        tracerouteTable,tracerouteList=tcpTraceRoute(ip)
                        path=tracerouteList
                        break
                    else:
                        print(colored("Wrong OPT","red"))
        else:
            print(colored(
                "The Path Tracing Contains Info, Kindly Choose an Option:\na- Show The Current Path on Map\nb- Enter IP or Domain Manually\nc- Back to Main Menue",
                "yellow"))
            while (True):
                opt = input()
                if (opt == "c"):
                    mainmenu()
                else:
                    if (opt == "b"):
                        ip = input("Enter The IP or Domain Name:")
                        tracerouteTable, tracerouteList = tcpTraceRoute(ip)
                        path=tracerouteList
                        break
                    else:
                        if(opt =="a"):
                            break
                        else:
                            print(colored("Wrong OPT", "red"))

    mymap = pygmaps(24.4539, 30.3773, 3)  # Starting point for the map and zoom level

    for i in range(1, len(path), 1):
        if(path[i][2]=="b'success"):
            #TODO: add company name to the points (label)
            mymap.addpoint(float(path[i][5]), float(path[i][6]), '#0000FF')
            temp = (float(path[i][5]), float(path[i][6]))
            if temp not in points:
                 points.append(temp)
        if((path[i][0]=="TTL") & (i>0)):
            #print(points)
            mymap.addpath(points, "#FF0000")
            points=[]

    #print(points)
    #mymap.addpath(points, "#F0FF00")
    ext=date.datetime.now()
    fileName="output/traceroute"+str(ext)+".html"
    mymap.draw(fileName)
    print(colored("The File Generated in "+fileName,"yellow"))
    return fileName

def convertToDataframe_core(pkt,ip_fields,tcp_fields,dataframe_fields,PID,dfData):
    df = pd.DataFrame(columns=dataframe_fields)
    df_append = pd.DataFrame(columns=dataframe_fields)

    current = current_process()
    print('', end='', flush=True)
    for packet in tqdm(pkt[IP], desc=str(current.name),
                  position=current._identity[0] - 1):
        field_values = []
        for field in ip_fields:
            field_values.append(packet[IP].fields[field])

        field_values.append(packet.time)

        layer_type = type(packet[IP].payload)
        for field in tcp_fields:
            try:
                field_values.append(packet[layer_type].fields[field])
            except:

                field_values.append(None)

        field_values.append(len(packet[layer_type].payload))

        # Add row to DF
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append].copy(), axis=0)

    dfData[PID]=df.copy()
    # if(not df.empty):
    #     del df
    # if(not df_append.empty):
    #     del df_append


def convertToDataframe(pkt):

    if(pkt==""):
        print(colored("No Packet Loaded In The Application. Read PCAP File or Sniff New Traffic From The Main Menu,\nThen Convert it to Dataframe,"
                      " Press Enter To Continue","yellow"))
        input()
        mainmenu()
    else:
        print("Converting in Process... ")
        # ip_fields = [field.name for field in IP().fields_desc]
        # tcp_fields = [field.name for field in TCP().fields_desc]
        # udp_fields = [field.name for field in UDP().fields_desc]
        ip_fields = ['src', 'dst']
        tcp_fields = ['sport', 'dport', 'chksum', 'urgptr']
        udp_fields = ['sport', 'dport', 'len', 'chksum']

        dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload_size']

        df = pd.DataFrame(columns=dataframe_fields)
        numberofCores = int(multiprocessing.cpu_count()) - 2

        print(colored("Work Will Be Divided For "+str(numberofCores)+" Cores", "yellow"))
        processes = []
        manager = multiprocessing.Manager()
        dfData = manager.dict()

        #grp_split = np.array_split(pkt, numberofCores)
        try:
            chunks=int(len(pkt)/numberofCores)
            #TODO: add the remaining pkts if exist, len(pkt)%numberofCores
        except:
            chunks=1
        if(chunks==1):
            p = Process(target=convertToDataframe_core, args=(pkt,0, dfData))
            time.sleep(0.2)
            processes.append(p)
        else:
            i=0
            for index in range(0,len(pkt),chunks):
                #grptmp = grp_split[index].reset_index(drop=True)
                grptmp = pkt[index:index+chunks]
                p = Process(target=convertToDataframe_core, args=(grptmp,ip_fields,tcp_fields,dataframe_fields,i,dfData ))
                i+=1
                time.sleep(0.2)
                processes.append(p)
            i=0
        # grp_split = np.array_split(pkt, numberofCores)
        # for index in range(numberofCores):
        #         grptmp = grp_split[index]
        #         #grptmp = grp_split[index].reset_index(drop=True)
        #
        #         p = Process(target=convertToDataframe_core, args=(grptmp, index, dfData))
        #         time.sleep(0.2)
        #         processes.append(p)
        # Start the processes2
        for p in processes:
            time.sleep(0.2)
            p.start()

        # Ensure all processes2 have finished execution
        print('', end='', flush=True)
        for p in processes:
            time.sleep(0.2)
            p.join()

        print(colored("\n\nIn progress ....Merging All Data", "yellow"))
        for index in range(len(processes)):
            if (not (dfData[index].empty)):
                df = df.append(dfData[index], ignore_index=True)

        # Reset Index
        df = df.reset_index()
        df = df.drop(columns="index")
        print("DONE... ")
        return df

def packetAnalysis():
    global df
    uniqueSRC = df['src'].unique()
    uniqueDST = df['dst'].unique()
    ip = []
    print("Analysis")

    print(colored("Choose The Index Number For IP Address From The List:", "yellow"))
    i = 0
    table1 = prettytable.PrettyTable(["INDEX", "IP ADDRESS"])
    table1.align["INDEX"] = "l"
    while (i < len(uniqueSRC)):
        table1.add_row([i, uniqueSRC[i]])
        i += 1
    table1.add_row(['s', "Start Analysis"])
    table1.add_row(['b', "Back To Main Menu"])
    print(table1)
    while (True):
        inp = input("$>: ")
        if (inp.isdigit()):
            inp = int(inp)
            if (inp < len(uniqueSRC)):
                if (uniqueSRC[inp] not in ip):
                    ip += [uniqueSRC[inp]]
                print(colored("The List= " + str(ip), "yellow"))

            else:
                print(colored("Worng Option", "red"))
        else:
            if (inp == 's'):
                break
            else:
                if (inp == "b"):
                    mainmenu()
                else:
                    print(colored("Worng Option", "red"))

        print(colored("Choose The Index Number For IP Address From The List:", "yellow"))
        i = 0
        print(table1)


    dfanalysis = [pd.DataFrame] * len(ip)
    for i in range(len(ip)):
        dfanalysis[i] = df.loc[(df['src'] == str(ip[i]))]
        #print(dfanalysis[i])

        sumDst= dfanalysis[i].groupby("dst")['payload_size'].sum()
        v = pd.DataFrame(sumDst)
        print(colored("The IP Address "+ str(ip[i])+" Communicated With The Following:","yellow"))
        sortedValues=v.sort_values(['payload_size'], ascending=False)

        print(sortedValues)

        # print(colored("More Details:","yellow"))
        # uniqueUserDst = dfanalysis[i]['dst'].unique()
        # for val in uniqueUserDst:
        #     resolveDNS(str(val))
        #     time.sleep(10)
        # print("")


    for i in range(len(ip)):
        #try:
            print(colored("The Unique Distinations Reached " + str(ip[i]) + " by Excluding Shared Distinations:", "yellow"))
            UniqueIpAddressList=[]
            NEWDST =dfanalysis[i]['dst'].unique()
            BaseDST=[]
            for rem in range(len(ip)):
                if(i==rem):
                    continue
                tmp=[dfanalysis[rem]['dst'].unique()]
                for tmp_v in tmp:
                    for tmp_v2 in tmp_v:
                        BaseDST+=[tmp_v2]

            # print("BASEDST",BaseDST)
            # print("NEWDST",NEWDST)
            for NEWDST_val in NEWDST:
                if (NEWDST_val not in BaseDST):
                    print(NEWDST_val)
                    UniqueIpAddressList.append(NEWDST_val)
            print("")
       # except Exception as e:
       #     print("Error"+str(e))

    ipAddressDetails(UniqueIpAddressList)


def packetConversations():
    global df
    # if(pkt==""):
    #     print(colored("No Packet Loaded In The Application. Read PCAP File or Sniff New Traffic From The Main Menu,\nThen Convert it to Dataframe,"
    #                   " Press Enter To Continue","yellow"))
    #     input()
    #     mainmenu()

    if (df.empty):
        print(colored(
            "No Dataframe Loaded, Use Option \"Converting to Dataframe\" in Main Menue"
            " Press Enter To Continue", "yellow"))
        input()
        mainmenu()



    while (True):
        print(colored("Choose An Option:\ng- List General Statistics\nx- Analysis\nc- Cancel","yellow"))
        inp=input()
        if(inp =='g'):
            print("General Statistics")

            print("\nTop Sending Addresses")
            #print(df[['src', 'dst', 'sport', 'dport']])
            sourceAddresses = df.groupby("src")['payload_size'].sum()
            v = pd.DataFrame(sourceAddresses)
            v1=v.sort_values(['payload_size'], ascending=False)
            print(v1)

            print("\n\nTop Recieving Addresses")
            destinationAddresses = df.groupby("dst")['payload_size'].sum()
            v = pd.DataFrame(destinationAddresses)
            v2=(v.sort_values(['payload_size'], ascending=False))
            print(v2)


        else:
            if(inp =='x'):
               packetAnalysis()
               mainmenu()

            else:
                if(inp=="c"):
                    mainmenu()
                else:
                    print(colored("Wrong Opt","red"))

def crossTwoPCAPS():
    global df
    print(colored("Choose Original PCAP File, Press Enter To Continue", "yellow"))
    input()

    dialog = dialogsGUI()
    fileName, ext = dialog.openFileNameDialog()
    if (str(ext) == ""):
        mainmenu()
    #pkt1 = readPCAP(fileName)

    print(colored("Choose New PCAP File, Press Enter To Continue", "yellow"))

    input()
    fileName, ext = dialog.openFileNameDialog()
    if (str(ext) == ""):
        mainmenu()
    pkt2 = readPCAP(fileName)


    print(colored("Converting Files to Dataframes", "yellow"))
    #df1=convertToDataframe(pkt1)
    df2=convertToDataframe(pkt2)

    #TODO: keep the data in the df and just select dst ip in df1, df2 df12, df2notdf1

    df=df2
    packetConversations()
    # print(colored("Number of Unique Distinations in New PCAP is "+ str(df2UniqueWithoutDF1.shape[0]), "yellow"))
    # df=df2UniqueWithoutDF1
    # if(df2UniqueWithoutDF1.shape[0]==0):
    #     print(colored("No Result Found !!", "yellow"))
    # else:
    #     packetConversations()


def packetStructure(pkt):

    if(pkt==""):
        print(colored("No Packet Loaded In The Application. Read PCAP File or Sniff New Traffic From The Main Menu,"
                      " Press Enter To Continue","yellow"))
        input()
        mainmenu()
    while (True):
        print(colored("Choose An Option:\nl- List Packets Summery\nd- Show Packet Detailes"
                      "\ne- Export Packet Stracture\nc- Cancel","yellow"))
        inp=input()
        if(inp =='l'):
            print("Packets Summary")
            for p in range(len(pkt)):
                print("["+str(p)+"]",pkt[p].summary())
        else:
            if(inp =='d'):
                print("Packet Details")
                start=input(colored("Enter Start Packet Index [0 - "+str(len(pkt)-1)+") ]:","yellow"))
                end=input(colored("Enter End Packet Index [0 - "+str(len(pkt)-1)+") ]:","yellow"))
                if(start==""):
                    start=0
                if(end==""):
                    end=len(pkt)
                for p in range(int(start),int(end)+1):
                    print("["+str(p)+"]",pkt[p].show())
            else:
                if(inp=="e"):
                    print("export packet structure")
                    start = int(input(colored("Enter Start Packet Index [0 - " + str(len(pkt) - 1) + ") ]:", "yellow")))
                    end = int(input(colored("Enter End Packet Index [0 - " + str(len(pkt) - 1) + ") ]:", "yellow")))
                    ext = date.datetime.now()
                    fileName = "output/Paket_Structure_" + str(ext) + ".pdf"
                    pkt[start:end+1].pdfdump(filename=fileName, layer_shift=1)
                    print(colored("File Exported in "+fileName,"green"))

                else:
                    if(inp=="c"):
                        mainmenu()
                    else:
                        print(colored("Wrong Opt","red"))




def setConfiguration():
    print(colored("Configuration\na- Add Interface\nb- Remove interface","yellow"))
    inp = input("Enter code name:")

    if (inp == "a"):
        ifacelist=addInterface()
    else:
        if (inp == "b"):
            ifacelist=removeInterface()
        else:
            print("Wrong OPT")

def typeWriter(message):
    for char in message:
        print(char,end='',flush=True)
        time.sleep(0.05)

def aboutJasper():
    msg="\nJasper Developed by Hamad ALSHEHHI 2021\n\nThe application built on top of SCAPY library,libOpenVas,PyQT5.\nIt can be used to analyze network's devices security.\nThe application comes with no warranty"
    os.system("clear")
    print(colored(f.renderText('Jasper >>>'), "red"))
    print(colored('\t\t\t\tEthical Hacking Toolkit', 'white'))
    typeWriter(msg)
    time.sleep(5)
    os.system("clear")


def mainmenu():
    global df,pkt,ans_arpPing,unans_arpPing,tracerouteTable,tracerouteList,scanPortSingleTable,scanPortMassTable

    if not os.path.exists("output"):
        os.makedirs("output")

    optionsProb =['-----PROBE--------\t','pa- Live Sniffing\t','pb- Read Capture File\t','pc- Save Capture File\t','pd- Convert to DataFrame','\t\t\t']
    optionsGeneral =['-----GENERAL--------','ga- About Jasper','xx- Exit Jasper\t','-----MODULES-------','ma- List Modules','mb- Add New Module']
    optionsAnalysis=['-----ANALYSIS--------\t','aa- Resolve DNS Names\t','ab- Geographic Trace Route',
                     'ac- Packet structure\t','ad- Conversations\t','ae- Crossover Two PCAPS']
    optionsScan =['-----SCAN--------\t','sa- List Hosts\t\t','sb- Open Ports(Single)\t','sc- Open Ports(Mass)\t',
                  'sd- Trace Route\t\t','\t\t\t','\t\t\t','\t\t\t','\t\t\t']
    optionsAttacks=['-----ATTACKS--------\t','ta- Vulnerability Scanning','tb- ARP Poisning (MiTMA)',
                    'tc- Fake SSL (MiTMA)','td- Fuzzing','te- Reply Attack','tf- Construct & Send Packet',
                    'tg- Deny of Service DoS','th- Save Vulnerability List']
    optionsConfiguration=['-----CONFIGURATION--','ca- Advanced Mode','cb- Configuration','\t\t','\t\t','\t\t','\t\t','\t\t','\t\t']

    os.system("clear")
    while(True):
        print(colored(f.renderText('  Jasper >>>'), "red"))
        print(colored('\t\t\t\t\t\t\t\tNetwork Probing Toolkit', 'white'))
        print(colored('\t\t\t\t\t\t\t\tVersion:', 'white'), colored('0.1', 'green'))
        for opt1,opt2 ,opt3 in zip(optionsProb,optionsAnalysis,optionsGeneral):
            print(colored(opt1,'green'),"\t",colored(opt2,'green'),"\t",colored(opt3,'green'))
        print("")
        for opt1,opt2,opt3 in zip(optionsScan,optionsAttacks,optionsConfiguration):
            print(colored(opt1,'green'),"\t",colored(opt2,'yellow'),"\t",colored(opt3,'green'))

        # for opt1 in optionsConfiguration:
        #     print(colored(opt1,'green'))

        inp=input("Enter code name:")

        if (inp=="pa"):
            pkt=liveSniffing()
        else:
            if(inp=="pb"):
                dialog = dialogsGUI()
                fileName, ext = dialog.openFileNameDialog()
                if (str(ext) == ""):
                    mainmenu()
                pkt=readPCAP(fileName)
            else:
                if (inp=="pc"):
                    dialog = dialogsGUI()
                    fileName, ext = dialog.saveFileDialog()
                    if (str(ext) == ""):
                        mainmenu()
                    savePCAP(fileName,pkt)
                else:
                    if(inp=="ga"):
                        aboutJasper()
                    else:
                        pass
                    if (inp == "sa"):
                        ans_arpPing, unans_arpPing=arpPing("")
                    else:
                        if(inp=="sb"):
                            scanPortSingleTable=scanOpenPorts()
                        else:
                            if (inp == "sc"):
                                scanPortSingleTable=scanOpenPortsMass()
                            else:
                                if (inp == "sd"):
                                    tracerouteTable,tracerouteList=tcpTraceRoute("")
                                else:
                                    if (inp == "cb"):
                                        setConfiguration()
                                    else:
                                        if (inp == "xx"):
                                            exit()
                                            sys.exit(app.exec_())
                                        else:
                                            if (inp == "ca"):
                                                advanceMode()
                                            else:
                                                if(inp=="aa"):
                                                    #from ipLists import iplistNewiPhoneSwitchSetup
                                                    #ipAddressDetails(iplistNewiPhoneSwitchSetup)
                                                    resolveDNS("")
                                                else:
                                                    if (inp=="ab"):
                                                        mapFile=geoShow(tracerouteList,passive=0)
                                                    else:
                                                        if (inp == "ac"):
                                                             packetStructure(pkt=pkt)
                                                        else:
                                                            if (inp == "ad"):
                                                                packetConversations()
                                                            else:
                                                                if (inp == "pd"):
                                                                    df=convertToDataframe(pkt=pkt)
                                                                else:
                                                                    if(inp=="ae"):
                                                                        crossTwoPCAPS()
                                                                    else:
                                                                        print("Wrong OPT")



tracerouteTable=""
tracerouteList=""
scanPortSingleTable=""
scanPortMassTable=""
df= pd.DataFrame()
app = QApplication(sys.argv)
mainmenu()

#####TESTS####
#ans_arpPing,unans_arpPing= arpPing(net="192.168.1.0/24")
#scanOpenPorts()

#tcpTraceRoute("")
#print(tcpTraceRoute(["www.google.com"]))

#print(resolveDNS(["www.python.org"]))
#print(resolveDNS("142.250.181.36"))
#tracerouteTable,tracerouteList=tcpTraceRoute("www.google.com")
#t1,t2=tcpTraceRoute("www.skynewsarabia.com")
#tracerouteList+=t2
#t1,t2=tcpTraceRoute("www.orange.fr")
#tracerouteList+=t2

#geoShow(path=tracerouteList,passive=1)

#packetStructure(pkt)