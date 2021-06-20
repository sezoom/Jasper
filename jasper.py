#! /usr/bin/env python3
from PyQt5.QtWidgets import QApplication
from pyfiglet import Figlet
from termcolor import colored
from dialogsGUI import *

try:
    from scapy.all import *
except:
    print("pip3 install --pre scapy[complete]")

import sys


f = Figlet(font='standard')


conf.verb=1
ifacelist=[]
pkt= scapy.sendrecv

def advanceMode():
    interact(mydict=globals(),mybanner="== Jasper Advanced Mode ==",loglevel=2,)


def arpPing(network):
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),timeout=2)
    print (r"List of all hosts in the network:")
    for snd,rcv in ans:
        print (rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))

    return ans ,unans

def readPCAP(file):
    global pkt
    try:
        pkt=rdpcap(filename=file)
    except:
        print("Not able to read the file")

    return pkt
#ans,unans= arpPing(network="192.168.1.0/24")

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


def mainmenu():
    global pkt
    optionsGeneral =['-----GENERAL--------','ga- Live Sniffing','gb- Read Capture File','gc- Save Capture File','gd- About Jasper','xx- Exit Jasper\t']
    optionsAnalysis=['-----ANALYSIS--------','aa- Resolve DNS Names','ab- Save GeoWord Trace Route',
                     'ac- Save Packet structure','ad- Save Conversations','ae- Generate Intensive Report']
    optionsScan =['-----SCAN--------','sa- Scan the Network','sb- Scan Open Port','sc- Scan using ACK',
                  'sd- Trace Route','\t\t','\t\t','\t\t','\t\t']
    optionsAttacks=['-----ATTACKS--------','ta- Vulnerability Scanning','tb- ARP Poisning (MiTMA)',
                    'tc- Fake SSL (MiTMA)','td- Fuzzing','te- Reply Attack','tf- Construct & Send Packet',
                    'tg- Deny of Service DoS','th- Save Vulnerability List']
    optionsConfiguration=['-----CONFIGURATION------','ca- Advanced Mode','cb- Configuration']

    while(True):
        print(colored(f.renderText('Jasper'), "red"))
        print(colored('\t\t\t\tEthical Hacking Toolkit', 'white'))
        print(colored('\t\t\t\tVersion:', 'white'), colored('0.1', 'green'))
        for opt1,opt2 in zip(optionsGeneral,optionsAnalysis):
            print(colored(opt1,'green'),"\t",colored(opt2,'yellow'))

        for opt1,opt2 in zip(optionsScan,optionsAttacks):
            print(colored(opt1,'yellow'),"\t",colored(opt2,'yellow'))

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
                if (inp == "ca"):
                    advanceMode()
                else:
                    if (inp=="cb"):
                        setConfiguration()
                    else:
                        if(inp=="xx"):
                            exit()
                        else:
                            print("Wrong OPT")


app = QApplication(sys.argv)
mainmenu()
