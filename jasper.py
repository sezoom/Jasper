#! /usr/bin/env python3
import time

import keyboard
from PyQt5.QtWidgets import QApplication
from pyfiglet import Figlet
from termcolor import colored
from dialogsGUI import *
from tqdm import tqdm
import prettytable
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from socket import getservbyname, getservbyport

try:
    from scapy.all import *
except:
    print("pip3 install --pre scapy[complete]")

import sys


f = Figlet(font='standard')


conf.verb=1
ifacelist=[]
pkt= scapy.sendrecv
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
        print(colored("To Start Sniffing Choose The Mode:\ns- Summery Mode\nd- Detailed Mode","yellow"))
        inp=input()
        if(inp =='d'):
            pkt=sniff(iface=listeniface,prn=lambda x:x.sniffed_on+": "+str(x.show()))
            break
        else:
            if(inp =='s'):
                pkt=sniff(iface=listeniface,prn=lambda x:x.sniffed_on+": "+str(x.summary()))
                break

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

    for p in range(0,40404,100):
        ans, unans = sr(IP(dst=ip) /TCP(dport=[i for i in range(p, p+100)], sport = RandShort(), flags = "S"), timeout = 15,verbose=0)
        ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",prn = lambda s, r: r.sprintf("%TCP.sport% is open\t [TCP]"))
        #TODO: add stealth scanning
        time.sleep(0.5)
        print("\t\t\t\t\t[",p+100 ," Ports Scanned]")
        try:
            if(keyboard.is_pressed("Esc")):
                print("Exiting the San!")
                break
        except:
            #            print(colored("Permission Required for Terminal in OS","red"))
            continue

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
        table1.add_row(['m', "Manual", "Manual"])
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
                    ip += [input("Enter The IP Address:")]
                else:
                    if(inp=='s'):
                        break
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
        print("[",p+100 ," Ports Scanned]")
        print(table2.get_string(sortby="IP Address"))

        try:
            if(keyboard.is_pressed("Esc")):
                print("Exiting the San!")
                break
        except:
            #            print(colored("Permission Required for Terminal in OS","red"))
            continue



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
    global pkt,ans_arpPing,unans_arpPing
    optionsGeneral =['-----GENERAL--------','ga- Live Sniffing','gb- Read Capture File','gc- Save Capture File','gd- About Jasper','xx- Exit Jasper\t']
    optionsAnalysis=['-----ANALYSIS--------','aa- Resolve DNS Names','ab- Save GeoWord Trace Route',
                     'ac- Save Packet structure','ad- Save Conversations','ae- Generate Intensive Report']
    optionsScan =['-----SCAN--------','sa- List Hosts\t','sb- Open Ports(Single)','sc- Open Ports(Mass)',
                  'sd- Trace Route','\t\t','\t\t','\t\t','\t\t']
    optionsAttacks=['-----ATTACKS--------','ta- Vulnerability Scanning','tb- ARP Poisning (MiTMA)',
                    'tc- Fake SSL (MiTMA)','td- Fuzzing','te- Reply Attack','tf- Construct & Send Packet',
                    'tg- Deny of Service DoS','th- Save Vulnerability List']
    optionsConfiguration=['-----CONFIGURATION------','ca- Advanced Mode','cb- Configuration']

    os.system("clear")
    while(True):
        print(colored(f.renderText('Jasper >>>'), "red"))
        print(colored('\t\t\t\tEthical Hacking Toolkit', 'white'))
        print(colored('\t\t\t\tVersion:', 'white'), colored('0.1', 'green'))
        for opt1,opt2 in zip(optionsGeneral,optionsAnalysis):
            print(colored(opt1,'green'),"\t",colored(opt2,'yellow'))

        for opt1,opt2 in zip(optionsScan,optionsAttacks):
            print(colored(opt1,'green'),"\t",colored(opt2,'yellow'))

        for opt1 in optionsConfiguration:
            print(colored(opt1,'green'))

        inp=input("Enter code name:")

        if (inp=="ga"):
            pkt=liveSniffing()
        else:
            if(inp=="gb"):
                dialog = dialogsGUI()
                fileName, ext = dialog.openFileNameDialog()
                if (str(ext) == ""):
                    mainmenu()
                pkt=readPCAP(fileName)
            else:
                if (inp=="gc"):
                    dialog = dialogsGUI()
                    fileName, ext = dialog.saveFileDialog()
                    if (str(ext) == ""):
                        mainmenu()
                    savePCAP(fileName,pkt)
                else:
                    if(inp=="gd"):
                        aboutJasper()
                    else:
                        pass
                    if (inp == "sa"):
                        ans_arpPing, unans_arpPing=arpPing("")
                    else:
                        if(inp=="sb"):
                            scanOpenPorts()
                        else:
                            if (inp == "sc"):
                                scanOpenPortsMass()
                            else:
                                if (inp == "ca"):
                                    advanceMode()
                                else:
                                    if (inp == "cb"):
                                        setConfiguration()
                                    else:
                                        if (inp == "xx"):
                                            exit()
                                            sys.exit(app.exec_())
                                        else:
                                            print("Wrong OPT")



app = QApplication(sys.argv)
mainmenu()

#####TESTS####
#ans_arpPing,unans_arpPing= arpPing(net="192.168.1.0/24")
#scanOpenPorts()
