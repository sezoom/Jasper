#! /usip=Nonenv python3
import datetime
import time

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
        pkt=rdpcap(filename=file)
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

    # Take the IP address only and translate it using ip-api.com service

    # print(p[1])
    req = http_request("ip-api.com", "/csv/" + paths[0][1])
    for r in req:
        locations += [str(r.load).split(",")]
    ResolveTable = prettytable.PrettyTable(
        ["TTL", "IP Address", "Translation", "Country", "City",  "Latitude","Longitude", "Company"])
    i = 0
    for data in locations:
        if (data[0] == "b'success"):
            ResolveTable.add_row([paths[i][0], paths[i][1], data[0], data[1], data[5], data[7], data[8], data[10]])
        else:
            ResolveTable.add_row([paths[i][0],paths[i][1],data[0],data[1],"","","",""])
        i += 1

    if (ip == ""):
        print(ResolveTable)

    return ResolveTable

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
            mymap.addpath(points, "#"+hex(RandByte())[2:].upper()+hex(RandByte())[2:].upper()+hex(RandByte())[2:].upper())
            points=[]

    #print(points)
    mymap.addpath(points, "#F0FF00")
    ext=date.datetime.now()
    fileName="output/traceroute"+str(ext)+".html"
    mymap.draw(fileName)
    print(colored("The File Generated in "+fileName,"yellow"))
    return fileName

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
    global pkt,ans_arpPing,unans_arpPing,tracerouteTable,tracerouteList,scanPortSingleTable,scanPortMassTable

    if not os.path.exists("output"):
        os.makedirs("output")

    optionsProb =['-----PROBE--------','pa- Live Sniffing','pb- Read Capture File','pc- Save Capture File','\t\t','\t\t']
    optionsGeneral =['-----GENERAL--------','ga- About Jasper','xx- Exit Jasper\t','-----MODULES-------','ma- List Modules','mb- Add New Module']
    optionsAnalysis=['-----ANALYSIS--------\t','aa- Resolve DNS Names\t','ab- Geographic Trace Route',
                     'ac- Packet structure\t','ad- Conversations\t','ae- Crossover Two PCAPS']
    optionsScan =['-----SCAN--------','sa- List Hosts\t','sb- Open Ports(Single)','sc- Open Ports(Mass)',
                  'sd- Trace Route','\t\t','\t\t','\t\t','\t\t']
    optionsAttacks=['-----ATTACKS--------\t','ta- Vulnerability Scanning','tb- ARP Poisning (MiTMA)',
                    'tc- Fake SSL (MiTMA)','td- Fuzzing','te- Reply Attack','tf- Construct & Send Packet',
                    'tg- Deny of Service DoS','th- Save Vulnerability List']
    optionsConfiguration=['-----CONFIGURATION--','ca- Advanced Mode','cb- Configuration','\t\t','\t\t','\t\t','\t\t','\t\t','\t\t']

    os.system("clear")
    while(True):
        print(colored(f.renderText('  Jasper >>>'), "red"))
        print(colored('\t\t\t\t\t\t\t\tEthical Hacking Toolkit', 'white'))
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
                                                    resolveDNS("")
                                                else:
                                                    if (inp=="ab"):
                                                        mapFile=geoShow(tracerouteList,passive=0)
                                                    else:
                                                        if (inp == "ac"):
                                                             packetStructure(pkt=pkt)
                                                        else:
                                                            print("Wrong OPT")



tracerouteTable=""
tracerouteList=""
scanPortSingleTable=""
scanPortMassTable=""
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