#!/bin/python
# coding=utf-8

'''
    Filename: smersh_off_forensics.py
    Author: Giorgio Rando
    Version: 4.2.2
    Created: 02/2020
    Modified: 11/05/2020
    Python: 2.7
    ToDo: un po di colorito non farebbe male! :)
'''
import json
import traceback
from base64 import b64encode
from online_smersh_poller import online_poller as op
from mail_sender import notify_service as nfs
from ipwhois import IPWhois as ipw
from tkinter.filedialog import *
from datetime import datetime
from os import listdir
from easygui import *
import ThreaderWorker as tw
import pyfiglet
import urllib2
import pandas
import subprocess
import requests
try:
    import winreg
except:
    print "[!] Sembra che tu stia usando SmershOff su Linux!\nLa libreria winreg non sarà importata!"
import urllib3
import getpass
import time
import pprint
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

verified = []

# Funzione per l'auto inserimento degli IP in blacklist una volta richiesta l'estrazione.
def blacklist_auto_updater(ip, label="", verbose=True):
    folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_blacklist.txt"

    with open(folder, mode='r') as file:
        content = file.read().splitlines()

    if not ip in content:
        label = raw_input("\n[*] Inserisci un label per l'IP " + ip + " [lasciare vuoto se desiderato]:\n"
                                                                      "\n>> ")
        try:
            with open(folder, mode="a") as file:
                if not label:
                    file.write("\n# [NO LABEL]")
                else:
                    # Prevista la possibilità di chiedere all'utente un label
                    file.write("\n# " + label)
                file.write("\n" + ip)
                print "\n[*] Blacklist file aggiornata con successo!"
        except:
            print "[!] Qualcosa è andato storto con l'inserimento dell'indirizzo {}".format(ip)
    else:
        if verbose:
            print "\n[!] IP {} già presente in blacklist!".format(ip)

# Funzione per l'estrazione automatica via web dei csv summary
def web_resource_crawler(check=False, provided=False, addr=[], poller=False, refresh_rate=0, ips="", time_type_end="", defined_seconds=None, verbose=True):
    folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_extractor_keywords.txt"
    with open(folder, mode="r") as file:
        content = file.read().splitlines()

    basic_path = content[0]
    csv_path_abs = content[1]
    csv_path_rel = content[2]

    if check:
        # Se devo verificare gli host in blacklist...
        if not provided:
            # print "\n[*] Prelevo IP list da blacklist (ricordati di non lasciare righe vuote!)"
            bll = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_blacklist.txt"
            with open(bll, mode="r") as listato:
                indirizzo = listato.read().splitlines()

            '''# Pulisco la blacklist dai commenti
            for idx, x in enumerate(indirizzo):
                if x.startswith("#"):
                    del indirizzo[idx]'''

        # Se devo verificare gli host in subnet auto-calcolata...
        else:
            indirizzo = addr

        if not poller:
            intervallo = raw_input('\nScegli un intervallo temporale da analizzare [ORE]:\n'
                                   '\n> ')
        else:
            intervallo = 0

        try:
            int(intervallo)
        except:
            print "[!] Inserito un valore non valido!"
            return None

        if poller:
            secondi = refresh_rate * 60
        else:
            secondi = 3600 * int(intervallo)

        relative_timestamp_path = "&type=relative&range=" + str(secondi)
        stream_path = content[4]
        field_path = "timestamp%2Cfarm%2CIP%2CIP_city_name%2Crequest%2Cresponse%2Cuseragent%2Csessionid"

        csv_url = []

        for ip in indirizzo:
            if ip.startswith("#") or ip == "":
                pass
            else:
                csv_url.append(basic_path + csv_path_rel + ip.replace('*',
                                                                      '%2A') + relative_timestamp_path + stream_path + field_path)

    else:
        if not ips:
            ips = raw_input("\n[*] Inserisci IP [multipli separati da ,]: \n\n>> ")

        if ips == "DEMO" or ips == "demo":
            ips = content[3]
            date_in = "2020-03-16"
            date_out = date_in
            time_in = "01:29:00"
            time_out = "01:35:00"
            absolute_timestamp_path = "&type=absolute&from=" + date_in + "T" + time_in.replace(":",
                                                                                               "%3A") + ".000Z&to=" + \
                                      date_out + "T" + time_out.replace(":", "%3A") + ".000Z"
            stream_path = content[4]
            time_type_end = "1"
            # fields = ["timestamp", "farm", "IP", "IP_city_name", "request", "response", "useragent"]
            # field_path = "timestamp%2Cfarm%2CIP%2CIP_city_name%2Crequest%2Cresponse%2Cuseragent"
            fields = ["timestamp", "farm", "IP", "IP_city_name", "request", "response", "useragent", "sessionid"]
            field_path = "timestamp%2Cfarm%2CIP%2CIP_city_name%2Crequest%2Cresponse%2Cuseragent%2Csessionid"
            csv_url = basic_path + csv_path_abs + ips + absolute_timestamp_path + stream_path + field_path
        else:
            ips = ips.split(',')
            ip_path = ""
            for idi, ip in enumerate(ips):

                # Aggiorna blacklist
                blacklist_auto_updater(ip, verbose=verbose)

                if idi > 0:
                    ip_path += "%20OR%20IP%3A" + ip.replace('*', '%2A')
                else:
                    ip_path += ip.replace('*', '%2A')

            time_type = ['RELATIVO (giorni)', 'ASSOLUTO (start-end date)']
            if not time_type_end:
                print u'\n[*] Scegli entità temporale desiderata:\n'
                for id, i in enumerate(time_type):
                    print '{}) {}'.format(id, i)
                time_type_end = raw_input('\n>> ')
                intVerification(time_type_end, len(time_type))

            # Se Assoluto
            if time_type_end == "1":
                date_in = raw_input("Inserisci Start Date [Es. 2020-03-16]: \n >> ")
                time_in = raw_input("Inserisci Start Time [Es. 03:00:00]: \n >> ")
                date_out = raw_input("Inserisci End Date [Es. 2020-03-16]: \n >> ")
                time_out = raw_input("Inserisci End Time [Es. 03:00:00]: \n >> ")
                absolute_timestamp_path = "&type=absolute&from=" + date_in + "T" + time_in.replace(":",
                                                                                                   "%3A") + ".000Z&to=" \
                                          + date_out + "T" + time_out.replace(":", "%3A") + ".000Z"
            else:
                if not defined_seconds:
                    # In un giorno ci sono 86400 secondi, quindi lo moltiplico per il numero di giorni per cui voglio estrarre i dati
                    giorni = raw_input("\n[*] Inserisci il numero di giorni da analizzare:\n"
                                       "\n>> ")
                    try:
                        int(giorni)
                    except:
                        print "[!] Numero di giorni non valido!"
                        exit(1)
                    secondi = 86400 * int(giorni)
                else:
                    secondi = defined_seconds
                relative_timestamp_path = "&type=relative&range=" + str(secondi)

            stream_path = content[5]

            # fields = ["timestamp", "farm", "IP", "IP_city_name", "request", "response", "useragent"]
            fields = ["timestamp", "farm", "IP", "IP_city_name", "request", "response", "useragent", "sessionid"]
            field_path = ""
            for idf, field in enumerate(fields):
                if idf > 0:
                    field_path += "%2C" + field
                else:
                    field_path += field

            if time_type_end == "1":
                csv_url = basic_path + csv_path_abs + ip_path + absolute_timestamp_path + stream_path + field_path
            else:
                csv_url = basic_path + csv_path_rel + ip_path + relative_timestamp_path + stream_path + field_path

    header = {content[6]: content[7],
              content[8]: content[9],
              "Referer": content[10]}

    # Se devo verificare IP in Blacklist o tutta la sottorete istanzio un multithread
    if provided:
        threads_num = 25
        global verified
        verified = []
        threads = []
        print "\n[*] Processamento IP in corso... " \
              "\n[*] L'operazione potrebbe richiedere diversi minuti. [premi 's' per status]"
        for num in range(0, threads_num):
            thread = tw.multiAddrVerifier("Thread" + str(num), csv_url, header)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        print "\n[*] Operazione completata con successo!"
        return None

    elif check:

        # Conterrà gli IP rilevati
        indirizzi = []
        # Conterrà i label degli IP rilevati
        labels_associati = []

        for ide, elem in enumerate(csv_url):
            address = ""
            r = requests.get(url=elem, headers=header, verify=False)
            address = re.findall(r"[0-9]{1,3}\.(?:\*|[0-9]{1,3})\.(?:\*|[0-9]{1,3})\.(?:\*|[0-9]{1,3})",
                                 elem.replace('%2A', '*'))[0]
            if "must not be empty" in r.text or r.text == "":
                # print u"\n[***] Nessuna rilevata per: " + address
                pass
            else:
                indirizzi.append(address)
                print u"\n   [!] Attività rilevata per: " + address
                try:
                    prec = indirizzo[indirizzo.index(address) - 1]
                    if prec.startswith("#"):
                        labels_associati.append(prec)
                        print "   " + prec
                    else:
                        labels_associati.append("[NO LABEL]")
                        print "   [!] No label per questo IP!"
                except:
                    pass

            if ide + 1 == len(csv_url):
                if poller:
                    return indirizzi, labels_associati
                else:
                    return None

    else:
        r = requests.get(url=csv_url, headers=header, verify=False)

        if "must not be empty" in r.text or r.text == "":
            if time_type_end == "1":  # Se tempo assoluto
                print "\nEstrazione vuota! Ricontrollare i parametri (Hai aggiornato il Bearer nel .config?):" \
                      "\n\n IPs: {};" \
                      "\n Timestamp in: {}:{};" \
                      "\n Timestamp out: {}:{};" \
                      "\n URL: {}" \
                      "\n Campi richiesti: {};" \
                      "\n Estrazione: {}".format(ips, date_in, time_in, date_out, time_out, csv_url, fields, r.text)

                raw_input("\nPremi qualsiasi tasto per chiudere.\n>>")
                exit(0)
            else:
                print "\nEstrazione vuota! Ricontrollare i parametri (Hai aggiornato il Bearer nel .config?):" \
                      "\n\n IPs: {};" \
                      "\n Giorni scanditi: {};" \
                      "\n URL: {}" \
                      "\n Campi richiesti: {};s" \
                      "\n Estrazione: {}".format(ips, giorni, csv_url, fields, r.text)

                raw_input("\nPremi qualsiasi tasto per chiudere.\n>>")
                exit(0)

        else:
            # Ricavo il path per la cartella Downloads
            sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
            downloads_guid = '{374DE290-123F-4565-9164-39C4925E467B}'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                save_path = winreg.QueryValueEx(key, downloads_guid)[0]
            # Quindi salvo quanto estratto all'interno del file
            with open(save_path + '\grabbed.csv', mode="w+") as f:
                #print "\n[+] Dati estratti con Successo! Salvati dentro la cartella 'Downloads'"
                f.write(r.text)

            return save_path + "\grabbed.csv"


# Estrattore dei log
def extract_values(kind, file, output, mode, verbose = True):
    pandas.set_option('display.max_rows', 10000)
    pandas.set_option('display.expand_frame_repr', False)

    df = pandas.read_csv(file, header=0)

    df["timestamp"] = pandas.to_datetime(df["timestamp"])
    df = df.groupby(['IP', pandas.DatetimeIndex(df['timestamp']).day])

    for each in df:
        filename = define_file_name(each, kind)

        #  For debug purpose-only #
        # print each[1].to_csv(index=False)
        # # # # # # # # # # # # # #

        if verbose:
            print "\n[+++] Extracted: {}".format(filename)

        # each[1].columns = ['timestamp', 'farm', 'IP', 'IP_city_name', 'request', 'response', 'useragent']
        each[1].columns = ['timestamp', 'farm', 'IP', 'IP_city_name', 'request', 'response', 'useragent', 'sessionid']

        if mode == '0':
            each[1].to_csv(output + '\\' + filename + ".csv", index=False, sep=';')
        elif mode == '1':
            each[1].to_excel(output + '\\' + filename + ".xlsx", index=False)


# Costruisce il nome del file da esportare
def define_file_name(each, kind):
    # Ricavo l'IP per il filename
    define_ip = str(each[1]['IP'][0:1]).split(' ')[4].split('\n')[0]

    # Ricavo il datetime per il filename
    define_date_day = str(each[1]['timestamp'][0:1]).split(' ')[3]

    return define_ip.replace('.', '_') + '_' + kind + '_' + define_date_day


# Elabora e predispone la matrice di valutazione degli alert
def import_matrix():
    entity = []
    recurency = []
    metrics = []
    todo = []

    folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_valuator_matrix.txt"
    with open(folder, mode="r") as file:
        content = file.read().splitlines()

    for idx, x in enumerate(content):
        matrix = x.split('|')
        if idx == 0:
            for y in matrix:
                entity.append((y.split(',')))
        elif idx == 1:
            for y in matrix:
                recurency.append(y.split(','))
        elif idx == 2:
            for y in matrix:
                metrics.append(y.split(','))
        else:
            for y in matrix:
                todo.append(y)

    return entity, recurency, metrics, todo


# Verifica la validità degli input numerici
def intVerification(val, length):
    try:
        int(val)
        if int(val) > length - 1 or int(val) < 0:
            exit(0)
        else:
            return True
    except:
        print '\n No correct value!'
        traceback.print_stack()
        exit(0)


# Funzione basica per il quick print dei menu contestuali
def print_action_menu(entry):
    for id, i in enumerate(entry):
        print '{}) {}'.format(id, i)
    action = raw_input('\n>> ')

    if intVerification(action, len(entry)):
        return int(action)


# Funzione per l'update automatico del bearer token quando scade il timeout delle 6 ore
def bearer_updater(u, p, file_path):
    try:
        import urllib3
        urllib3.disable_warnings()

        with open(file_path, mode="r") as file:
            config_file = file.read().splitlines()

        now = datetime.now()

        login = {"username": u,
                 "password": p}

        header = {'X-Requested-With': 'XMLHttpRequest',
                  'X-Requested-By': 'XMLHttpRequest'}

        r = requests.post(config_file[14], json=login, headers=header, verify=False)

        bearer = b64encode(json.loads(r.text.encode("utf-8"))['session_id'] + ":session")

        config_file[9] = "Basic " + bearer

        config_file[15] = str(now)

        with open(file_path, mode="w") as new_file:
            new_file.write("\n".join(config_file))

        print "\n[*] Bearer Token aggiornato con Successo!"
    except:
        print u"\n[!] Errore durante l'aggiornamento del Bearer Token!"


# Funzione per l'estrazione dei dati dai log grezzi alla conversione pulita
def estrattore_dati(choose="",ips="", intervallo=None, verbose=True, save_path=""):

    kind = ['Automated SQL Injection', 'nMap Scanning', 'Manual Vulnerability Probing', 'Automated Vulnerability '
                                                                                        'Probing', 'Spidering Events',
            '[AUTO-GENERATED-REPORT]']

    if not choose:
        print '\n[*] Scegli il vettore d\'attacco:\n'
        choose = print_action_menu(kind)


    exports = ['CSV', 'EXCEL']
    # print '\n[!] Scegli il tipo di file che vuoi generare:\n'
    # mode = print_action_menu(exports)
    mode = "1"

    modalita_prelevamento = ['FILE LOCALE', 'ESTRAZIONE DAL WEB']
    # print '\n[*] Scegli una sorgente dati (export: {}):\n'.format(exports[int(mode)])
    # source = print_action_menu(modalita_prelevamento)
    source = "1"

    if source == 0:
        Tk().withdraw()
        print '\n[!] Scegli quale file aprire: \n'
        file_path = askopenfilename()
    else:
        ########## Preleva il file da Graylog!
        file_path = web_resource_crawler(ips=ips, time_type_end="0", defined_seconds=intervallo, verbose=verbose)

    if not save_path:
        save_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop') + "\\Estrazioni_Elaborate"
        if not os.path.exists(save_path):
            os.mkdir(save_path)

    if verbose:
        print "\n[!] Directory di assemblamento: {}".format(save_path)

    #try:
    extract_values(kind[int(choose)].replace(' ', '_'), file_path, save_path, mode, verbose=verbose)

    if verbose:
        print "\n[+++] Estrazione completata con Successo!\n"
        subprocess.Popen(r'explorer /select,"' + save_path + '"')

    #except:
        #print u"[!] Fallito! Qualcosa è andato storto. " \
              #u"\nHai estratto un excel con colonne diverse da quelle di default? [timestamp, farm, IP, IP_city_name, request, response, useragent]"


# Funzione per il calcolo della severity degli eventi estratti in locale
def severity_evaluator():
    global count_events
    import Tkinter, tkFileDialog
    import xlrd  ## Necessaria per pandas' excel

    sfondi = ['SQL', 'nMap', 'Manual', 'Automated', 'Spidering']

    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    gen_path = desktop_path + "\\Estrazioni_Elaborate"

    root = Tkinter.Tk()
    filez = tkFileDialog.askopenfilenames(parent=root, title='Scegli i file da analizzare', initialdir=gen_path)
    files_list = root.tk.splitlist(filez)

    entity, recurency, metrics, todo = import_matrix()

    address = []

    aggregante = ["Aggrega per IP", "Conto generico"]
    print '\n[*] Scegli il tipo di aggregazione per il conto degli eventi:\n'
    conto = print_action_menu(aggregante)

    if conto == 0:
        pass
    else:
        count_events = len(files_list)

    for file in files_list:
        address1 = file.split("/")[5]
        address2 = address1.split("_")[:4]
        address3 = "_".join(address2)
        if not address3 in address:
            address.append(address3)

    for addr in address:
        for attack in sfondi:
            entity_event = []
            response = []
            for idf, file in enumerate(files_list):

                if attack in file and addr in file:
                    entity_event.append(len(pandas.read_excel(file)))

                if idf + 1 == len(files_list) and entity_event:
                    entity_event = max(entity_event)
                    for idx, x in enumerate(entity):
                        if x[0] in attack:
                            if entity_event < int(x[1]):
                                response.append(metrics[1][0])
                            elif entity_event >= int(x[1]) and entity_event < int(x[2]):
                                response.append(metrics[1][1])
                            elif entity_event >= int(x[2]):
                                response.append(metrics[1][2])

                            if conto == 0:
                                count_events = 0
                                for file in files_list:
                                    if addr in file:
                                        count_events += 1
                            else:
                                pass

                            if count_events <= int(recurency[idx][1]):
                                response.append(metrics[0][0])
                            elif count_events > int(recurency[idx][1]) and count_events <= int(recurency[idx][2]):
                                response.append(metrics[0][1])
                            elif count_events >= int(recurency[idx][2]):
                                response.append(metrics[0][2])

                            if response[0] == metrics[1][0] and response[1] == metrics[0][2]:
                                action_future = todo[1] + " + " + todo[2]

                            elif response[0] == metrics[1][1] and response[1] == metrics[0][1]:
                                action_future = todo[1]

                            elif response[0] == metrics[1][1] and response[1] == metrics[0][2]:
                                action_future = todo[1] + " + " + todo[3]

                            elif response[0] == metrics[1][2] and response[1] == metrics[0][0]:
                                action_future = todo[1]

                            elif response[0] == metrics[1][2] and response[1] == metrics[0][1]:
                                action_future = todo[1] + " + " + todo[4]

                            elif response[0] == metrics[1][2] and response[1] == metrics[0][2]:
                                action_future = todo[1] + " + " + todo[5] + " + " + todo[6]

                            else:
                                action_future = todo[0]

                            break

                    print "\nValutazione severity evento tipologia '{}', IP: {}: " \
                          u"\nEntità: {}" \
                          "\nRicorrenze: {}" \
                          "\nSeverity: {} | {}\n" \
                          "\n    >> Contromisura: {}".format(attack, addr.replace("_", "."), entity_event, count_events,
                                                             response[0],
                                                             response[1], action_future)


# Analizza le sottoreti agli IP indicati per rintracciare eventuale attività annessa
def subnet_analyser(ranges):
    sub_ips = []

    for x in ranges:
        if not "None" in x:
            netrange = x.replace(" ", "").encode("utf-8").split("-")

            nr1 = netrange[0].split(".")
            nr1 = [int(x) for x in nr1]
            nr2 = netrange[1].split(".")
            nr2 = [int(x) for x in nr2]

            while not (nr1[0] == nr2[0] and nr1[1] == nr2[1] and nr1[2] == nr2[2] and nr1[3] == nr2[3]):

                ipx = ".".join(str(x) for x in nr1)
                sub_ips.append(ipx)

                if nr1[3] < 255:
                    nr1[3] += 1

                else:
                    if nr1[2] < 255:
                        nr1[3] = 0
                        nr1[2] += 1
                    else:
                        if nr1[1] < 255:
                            nr1[2] = 0
                            nr1[1] += 1
                        else:
                            nr1[0] += 1

    web_resource_crawler(True, True, sub_ips)

    ''' DEBUG:
    Print del classico risultato -pero strings- di whois
    print who.get_whois()
    '''


# Eseguo una query whois per gli indirizzi specificati in blacklist
def whois_responder(plot):
    folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_extractor_keywords.txt"
    with open(folder, mode="r") as file:
        content = file.read().splitlines()

    if not plot:
        print u"\n[!] Avviso: l'estrazione per sottorete risulta essere parecchio lenta ed onerosa. " \
              u"\n            Si consiglia di effettuare la ricerca attraverso portale WEB prelevando da qui il NetRange." \
              u"\n Vuoi tornare al menù principale? [S/n]"
        choose = raw_input(" > ")
        if choose == "s" or choose == "S":
            return None
        else:
            pass

    ranges = []

    # Set proxy handler
    u = raw_input("\n[*] Connessione al proxy richiesta, autenticati.\nUser: ")
    p = getpass.getpass("Password: ")

    handler = urllib2.ProxyHandler({'http': 'http://' + u + ':' + p + '@' + content[11]})
    opener = urllib2.build_opener(handler)

    source = ['Blacklist File', 'IP File Simple List', 'Manual IP']
    print "\n Scegliere la sorgente degli IP (NB. Nessuno deve contenere il carattere * !)"
    action = print_action_menu(source)

    if action == 0:
        source = "\\smersh_blacklist.txt"
    elif action == 1:
        source = "\\simple_ip_list.txt"
    elif action == 2:
        ips = raw_input("\n IP(s) [multipli separati da ,]: ")

    if not action == 2:
        bll = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + source
        with open(bll, mode="r") as listato:
            ips = listato.read().splitlines()

            # Pulisco la blacklist dai commenti
            for idx, x in enumerate(ips):
                if x.startswith("#"):
                    del ips[idx]

    else:
        ips = ips.split(",")

    for ip in ips:
        try:
            who = ipw(ip, proxy_opener=opener).lookup_rdap()
        except:
            print "\n[!] Connessione al proxy fallita, credenziali errate!" \
                  "\n    Oppure presente un IP che contiene: * "
            return None

        if plot:

            # Print entire WhoIs result
            # pp = pprint.PrettyPrinter(indent=8)
            # pp.pprint(who)

            print "\n [*] IP:\n"
            print ip

            print "\n [**] Owner:\n"
            print who["network"]["name"]

            print "\n [**] NetRange:\n"
            print who["network"]["handle"]

            print "\n [***] Abuse Email:\n"
            ripe = who["entities"]
            for x in ripe:
                try:
                    print who["objects"][x]["contact"]["email"][0]["value"]
                except:
                    pass

            print "\n##### ##### ##### ##### ##### ##### #####"

        else:
            netrange = who["network"]["handle"]
            regex = re.compile(r"[0-9]{1,3}\.(?:\*|[0-9]{1,3})\.(?:\*|[0-9]{1,3})\.(?:\*|[0-9]{1,3})")
            if not regex.match(netrange):
                ranges.append("None for: {" + ip + "}")
                print "\n[!] Nessun netrange rilevato per: " + ip
            else:
                print "\n[+] Netrange per " + ip + " : " + netrange.encode("utf-8")
                ranges.append(netrange.encode("utf-8"))

    if plot:
        return None
    else:
        subnet_analyser(ranges)


# Funzione per il quick remove degli elementi locati dentro la cartella dei falsi positivi e la loro rimozione dalla blacklist
def clean_false_positive():
    false_positive_lists = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop') + "\\Estrazioni_Elaborate\\classificatori\\falsi_positivi"

    if not os.path.exists(false_positive_lists):
        os.mkdir(false_positive_lists)
        print "\n[!] Cartella vuota!"
        return None

    files_in_dir = listdir(false_positive_lists)

    if not files_in_dir:
        print "\n[*] Directory falsi positivi vuota, skip."
    else:
        for file in files_in_dir:
            ip = file.split("_")[:4]
            ip = ".".join(ip)
            try:
                confManagement(1, ip, True)
                os.remove(false_positive_lists + "\\" + file)
            except:
                print "\n\t[!] Impossibile rimuovere l'IP {} da Blacklistfile!".format(ip)

        print "\n[*] Blacklist aggiornata con successo!"


# Funzione per il quickrename necessario nel momento in cui si ha la necessità di rinominare estrazioni automatiche
def quick_file_rename():

    directory_files = os.path.join(os.path.join(os.environ['USERPROFILE']),'Desktop') + "\\Estrazioni_Elaborate"
    dirs = [directory_files + "\\classificatori\\automated", directory_files + "\\classificatori\\manual", directory_files + "\\classificatori\\spidering"]

    new_file_name = "[AUTO-GENERATED-REPORT]"

    for x in dirs:
        if not os.path.exists(x):
            os.mkdir(x)

    for idx, file in enumerate(dirs):
        files = listdir(file)
        for elem in files:
            if idx == 0 and "[AUTO-GENERATED-REPORT]" in elem :
                new_file_name = elem.replace("[AUTO-GENERATED-REPORT]", 'Automated_Vulnerability_Probing')
            elif idx == 1 and "[AUTO-GENERATED-REPORT]" in elem:
                new_file_name = elem.replace("[AUTO-GENERATED-REPORT]", 'Manual_Vulnerability_Probing')
            elif idx == 2 and "[AUTO-GENERATED-REPORT]" in elem:
                new_file_name = elem.replace("[AUTO-GENERATED-REPORT]", 'Spidering_Event')
            else:
                continue

            file_path = file + "\\" + elem
            try:
                os.rename(file_path, file + "\\" + new_file_name)
            except:
                print "\n[!] Qualcosa è andato storto con il rename del file: {}".format(file_path)

    print "\n[*] Extracted_files rinominati con successo!"


# Configuratore pratico per file di config locali
def confManagement(action = None, choose = None, automated = False):
    inside = True

    while inside:

        if not action:
            menu = ['[ADD IP] Blacklist Management', '[REMOVE IP] Blacklist Management', '[SHOW IP] Blacklist Management',
                    "[AUTOMAZIONE] Rinomina auto estrazioni + Clean Falsi Positivi da Blacklist", "[DEPRECATO] Update Auth Token", "Indietro"]
            print "\n.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#"
            print u'\n[*] Menù:\n'
            action = print_action_menu(menu)

        # Add IP
        if action == 0:

            add = raw_input("\n[+] Inserisci IP da aggiungere:\n  >> ")
            label = raw_input("\n[+] Inserisci label identificato:\n  >> ")

            folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_blacklist.txt"

            try:
                with open(folder, mode="a") as file:
                    file.write("\n#" + label)
                    file.write("\n" + add)
            except:
                print "\n[!] Qualcosa è andato storto!"
                inside = False
            action = None
            print "\n[*] Blacklist file aggiornata con successo!"

        # Remove IP
        elif action == 1:

            folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_blacklist.txt"

            with open(folder, mode="r") as file:
                content = file.read().splitlines()

                if not choose:
                    print "\n"
                    for ida, addr in enumerate(content):
                        if not addr.startswith("#"):
                            print "{}) {}".format(ida, addr)
                        else:
                            print addr

                    choose = raw_input("\n[+] Scegli l'indice dell'IP da rimuovere:\n> ")
                    try:
                        choose = int(choose)
                    except:
                        print "\n[!] Indice inserito non valido!\n"
                        return None
                else:
                    for ida, addr in enumerate(content):
                        if str(choose) in addr:
                            choose = ida
                            break

            # Rimuovo l'IP
            del content[choose]
            # Rimuovo il label se presente
            if content[choose - 1].startswith("#"):
                del content[choose - 1]

            try:
                with open(folder, mode="w") as file:
                    file.write("\n".join(content))
            except:
                print "\n[!] Qualcosa è andato storto."
                inside = False

            if automated:
                inside = False
            else:
                action = None
                print "\n[*] Blacklist file aggiornata con successo!"

        # Show IPs
        elif action == 2:

            folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_blacklist.txt"
            print "\n"

            with open(folder, mode="r") as file:
                for ida, addr in enumerate(file.read().splitlines()):
                    if not addr.startswith("#"):
                        print "{}) {}".format(ida, addr)
                    else:
                        print addr

            action = None

        # Auth Token Management
        elif action == 4:

            session = raw_input("\n[!] Con poller attivi Bearer si aggiorna automaticamente ogni 6 ore!\n"
                                "\n[+] Inserisci il Bearer aggiornato:\n> ")

            folder = os.path.join(os.path.join(os.environ['USERPROFILE']),
                                  'Documents') + "\\smersh_extractor_keywords.txt"
            with open(folder, mode="r") as file:
                content = file.read().splitlines()

            content[9] = "Basic " + session

            try:
                with open(folder, mode="w") as file:
                    file.write("\n".join(content))
            except:
                print "\n[!] Qualcosa è andato storto."
                return None

            print "\n[*] Config file aggiornato con successo!"
            action = None

        # Automazione rinominazione + clean falsi positivi
        elif action == 3:
            try:
                clean_false_positive()
                quick_file_rename()
                action = None
            except:
                print "\n\t[!] Qualcosa è andato storto con l'automazione!"
                inside = False

        # Indietro
        elif action == 5:
            inside = False


if __name__ == "__main__":

    print ".-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#"
    banner = pyfiglet.figlet_format("Smersh-Off \n Forensics ToolKit")
    print banner
    print "              Developed by Giorgio Rando  -  v4.2.2"

    while 1:
        menu = ["Smersh-On Poller", 'Estrai Dati', 'Valuta Severity Evento', 'Verifica Host in Blacklist', 'Verifica Subnet',
                'Whois Resolver', "Configurazioni", "Chiudi", ".-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-", "RedMine Report Management [UNDER BUILDING]"]
        print "\n.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#"
        print u'\n[*] Menù:\n'
        action = print_action_menu(menu)

        try:
            # Polling di verifica filtri su Smersh-Online
            if action ==0:
                print("\n[*] Refresh-rate fisso a 15 minuti!\n")
                refresh_rate = 15

                try:
                    int(refresh_rate)
                except:
                    print "[!] Valore di refresh rate non valido!"
                    break

                ips = op(refresh_rate)

            # Estrai Dati
            elif action == 1:
                estrattore_dati()

            # Valuta Severity Evento
            elif action == 2:
                severity_evaluator()

            # Verifica host in blacklist
            elif action == 3:
                print "\n"
                menu = ["Poller", "One-Shot"]
                action = print_action_menu(menu)

                # Poller
                if action == 0:
                    refresh_rate = raw_input("\n[*] Inserisci un refresh-rate [Minuti]:\n"
                                             "\n  >> ")

                    try:
                        int(refresh_rate)
                    except:
                        print "[!] Valore di refresh rate non valido!"
                        break
                    
                    u = raw_input("\n[*] Autenticazione richiesta.\n"
                                  "\nUser: ")
                    p = getpass.getpass("Password: ")

                    print "\n[!] Premere 'Ctrl + C' in qualsiasi momento per interrompere il polling.\n"

                    counter = 1

                    popup = raw_input("\n[*] Abilitare pop-up di notifica? (sconsigliato) [S/n]\n"
                                      "\n>> ")

                    while True:
                        # Scommentare per abilitare debug, quindi commentare sotto:
                        '''
                        print "\n.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-." \
                              "\n[*] {}/{}/{} - {}:{} | Iterazione [{}]:\n".format(datetime.now().day, datetime.now().month,
                                                                                   datetime.now().year, datetime.now().hour,
                                                                                   datetime.now().minute, counter)
                        res, labels = web_resource_crawler(True, poller=True, refresh_rate=int(refresh_rate))
                        if not res:
                            print u"   [+] Nessuna attività rilevata"
                        else:
                            nfs(refresh_rate, res, labels)
                            title = "[!] SECURITY ALERT [!]"
                            msg = "Rilevata attività per l'IP: {}\nLabel: {}".format(", ".join(res), ", ".join(labels))
                            msgbox(msg, title, ok_button="Chiudi")'''
                        # Commentare per abilitare invece debug
                        # Aggiorno bearer token se sono passate almeno 6 ore
                        from datetime import timedelta
                        now = datetime.now()

                        conf = os.path.join(os.path.join(os.environ['USERPROFILE']),
                                            'Documents') + "\\smersh_extractor_keywords.txt"
                        with open(conf, mode="r") as file:
                            strings = file.read().splitlines()

                        if not now - timedelta(hours=6) <= datetime.strptime(strings[15], '%Y-%m-%d %H:%M:%S.%f') <= now:
                              bearer_updater(u, p, conf)
                        res, labels = web_resource_crawler(True, poller=True, refresh_rate=int(refresh_rate))

                        if res:
                            now = datetime.now()
                            print "\n[!]Timestamp: {}".format(now.strftime("%d/%m/%Y %H:%M:%S"))
                            nfs(refresh_rate, res, labels, "Blacklist Poller", u=u, p=p)
                            if popup == "S" or popup == "s":
                                title = "[!] SECURITY ALERT [!]"
                                msg = "Rilevata attività per l'IP: {}\n" \
                                      "Label: {}\n" \
                                      "Timestamp: {}".format(", ".join(res), ", ".join(labels), now.strftime("%d/%m/%Y %H:%M:%S"))
                                msgbox(msg, title, ok_button="Chiudi")
                        ### ### ### ### ### ### ### ### ### ###

                        try:
                            print "\n   [~] In ascolto..."
                            # Minuti
                            time.sleep(int(refresh_rate) * 60)
                            # Secondi
                            # time.sleep(int(refresh_rate))
                        except KeyboardInterrupt:
                            print "\n-.-.-.-.-.-[!] Interrotto -.-.-.-.-.-\n"
                            break

                        counter += 1

                # One-Shot
                elif action == 1:
                    web_resource_crawler(True)

            # Verifica Subnet
            elif action == 4:
                whois_responder(False)

            # Whois Resolver
            elif action == 5:
                whois_responder(True)

            # Configurazioni
            elif action == 6:
                confManagement()

            # Chiudi
            elif action == 7:
                exit(0)
        except:
            print u"\n[!] Qualcosa è andato storto! Hai configurato correttamente il toolkit?\n"
            traceback.print_stack()
            raw_input("\nPremi qualsiasi tasto per concludere:\n  >> ")
            exit(0)
