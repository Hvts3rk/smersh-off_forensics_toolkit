#!/bin/python
# coding=utf-8

from smersh_off_forensics import verified as vr
import threading
import requests
import keyboard
import re


class multiAddrVerifier(threading.Thread):

    def __init__(self, label, csv_url, header):
        threading.Thread.__init__(self)
        self.label = label
        self.csv_url = csv_url
        self.header = header

    def run(self):
        for ide, elem in enumerate(self.csv_url):
            address = ""
            if not elem in vr:
                vr.append(elem)
                try:
                    r = requests.get(url=elem, headers=self.header, verify=False)
                    address = re.findall(r"[0-9]{1,3}\.(?:\*|[0-9]{1,3})\.(?:\*|[0-9]{1,3})\.(?:\*|[0-9]{1,3})",
                                         elem.replace('%2A', '*'))[0]
                    if keyboard.is_pressed('s'):
                        print"\n   > Verifica IP: " + address
                    if keyboard.is_pressed('q'):
                        pass
                        # ToDo: Interrompi esecuzione threads e torna al menu

                    if "must not be empty" in r.text or r.text == "":
                        # Debug:
                        # print "\n[***] Nessuna rilevata per: " + address + " da: " + self.label
                        pass
                    else:
                        print "\n[!] Attivita rilevata per: " + address

                    if ide + 1 == len(self.csv_url):
                        return None
                except:
                    pass
                    # Debug
                    # print u"\n[!] Qualcosa è andato storto in {} per l\'indirizzo: {}".format(self.label, address)
            else:
                pass
