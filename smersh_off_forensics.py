#!/bin/python
# coding=utf-8

'''
    Filename: smersh_off_forensics.py
    Author: Giorgio Rando
    Version: 3.0.0
    Created: 02/2020
    Modified: 06/04/2020
    Python: 2.7
    ToDo: aggiungi indirizzi estratti automaticamente in blacklist, quindi calcola netrange.
'''

from ipwhois import IPWhois as ipw
import ThreaderWorker as tw
import pyfiglet
import urllib2
import pandas
import subprocess
import requests
import winreg
import urllib3
import getpass
import pprint
import re
from tkinter.filedialog import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

verified = []


# Funzione per l'estrazione automatica via web dei csv summary
def web_resource_crawler(check=False, provided=False, addr=[]):
    folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_extractor_keywords.txt"
    with open(folder, mode="r") as file:
        content = file.read().splitlines()

    basic_path = content[0]
    csv_path_abs = content[1]
    csv_path_rel = content[2]

    if check:
        if not provided:
            print "\n [*] Prelevo IP list da blacklist"
            bll = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_blacklist.txt"
            with open(bll, mode="r") as listato:
                indirizzo = listato.read().splitlines()

        else:
            indirizzo = addr

        intervallo = raw_input('\nScegli un intervallo temporale da analizzare [ORE]:\n'
                               '\n> ')

        try:
            int(intervallo)
        except:
            print "Inserito un valore non valido!"
            exit(0)

        secondi = 3600 * int(intervallo)
        relative_timestamp_path = "&type=relative&range=" + str(secondi)
        stream_path = content[4]
        field_path = "timestamp%2Cfarm%2CIP%2CIP_city_name%2Crequest%2Cresponse%2Cuseragent%2Csessionid"

        csv_url = []

        for ip in indirizzo:
            csv_url.append(
                basic_path + csv_path_rel + ip.replace('*', '%2A') + relative_timestamp_path + stream_path + field_path)

    else:

        ips = raw_input("\nInserisci IP [multipli separati da ,]: \n\n>> ")

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
                if idi > 0:
                    ip_path += "%20OR%20IP%3A" + ip.replace('*', '%2A')
                else:
                    ip_path += ip.replace('*', '%2A')

            time_type = ['RELATIVO (giorni)', 'ASSOLUTO (start-end date)']
            print u'\n Scegli entità temporale desiderata:\n'
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
                # In un giorno ci sono 86400 secondi, quindi lo moltiplico per il numero di giorni per cui voglio estrarre i dati
                giorni = raw_input("\nInserisci il numero di giorni da analizzare: \n>> ")
                try:
                    int(giorni)
                except:
                    print "Numero di giorni non valido!"
                    exit(1)
                secondi = 86400 * int(giorni)
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

        for ide, elem in enumerate(csv_url):
            address = ""
            r = requests.get(url=elem, headers=header, verify=False)
            address = re.findall(r"[0-9]{1,3}\.(?:\*|[0-9]{1,3})\.(?:\*|[0-9]{1,3})\.(?:\*|[0-9]{1,3})",
                                 elem.replace('%2A', '*'))[0]
            if "must not be empty" in r.text or r.text == "":
                #print u"\n[***] Nessuna rilevata per: " + address
                pass
            else:
                print u"\n[!] Attività rilevata per: " + address

            if ide + 1 == len(csv_url):
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
                print "\n[+] Dati estratti con Successo! Salvati dentro la cartella 'Downloads'"
                f.write(r.text)

            return save_path + "\grabbed.csv"


# Estrattore dei log
def extract_values(kind, file, output, mode):
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
        exit(0)


def print_action_menu(entry):
    for id, i in enumerate(entry):
        print '{}) {}'.format(id, i)
    action = raw_input('\n>> ')

    if intVerification(action, len(entry)):
        return int(action)


# Funzione per l'estrazione dei dati dai log grezzi alla conversione pulita
def estrattore_dati():
    # Alcuni esempi...
    kind = ['Automated SQL Injection', 'nMap Scanning', 'Manual Vulnerability Probing', 'Automated Vulnerability '
                                                                                        'Probing', 'Spidering Events']
    print '\n[*] Scegli il vettore d\'attacco:\n'
    choose = print_action_menu(kind)

    exports = ['CSV', 'EXCEL']
    # print '\n[!] Scegli il tipo di file che vuoi generare:\n'
    # mode = print_action_menu(exports)
    mode = "1"

    modalita_prelevamento = ['FILE LOCALE', 'ESTRAZIONE DAL WEB']
    print '\n[*] Scegli una sorgente dati (export: {}):\n'.format(exports[int(mode)])
    source = print_action_menu(modalita_prelevamento)

    if source == 0:
        Tk().withdraw()
        print '\n[!] Scegli quale file aprire: \n'
        file_path = askopenfilename()
    else:
        file_path = web_resource_crawler()

    desktop_path = desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    save_path = (desktop_path + "\\Estrazioni_Elaborate")
    if os.path.exists(save_path):
        pass
    else:
        os.mkdir(save_path)

    print "\n[!] Directory di assemblamento: {}".format(save_path)

    try:
        extract_values(kind[choose].replace(' ', '_'), file_path, save_path, mode)
        print "\n[+++] Estrazione completata con Successo!\n"
        subprocess.Popen(r'explorer /select,"' + save_path + '"')
    except:
        print u"[!] Fallito! Qualcosa è andato storto. " \
              u"\nHai estratto un excel con colonne diverse da quelle di default? [timestamp, farm, IP, IP_city_name, request, response, useragent]"


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

    source = ['Blacklist File', 'IP Simple List', 'Defined NetRange']
    print "\n Scegliere la sorgente degli IP (NB. Nessuno deve contenere il carattere * !)"
    action = print_action_menu(source)

    if action == 0:
        source = "\\smersh_blacklist.txt"
    elif action == 1:
        source = "\\simple_ip_list.txt"
    elif action ==2:
        print "[!] TO DO"
        return None
        #source = "\\manual_defined_netrange.txt"

    bll = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + source
    with open(bll, mode="r") as listato:
        ips = listato.read().splitlines()

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


if __name__ == "__main__":

    print ".-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#"
    banner = pyfiglet.figlet_format("Smersh-Off \n Forensics Tool")
    print banner
    print "              Developed by Giorgio Rando  -  v3.0.1"
    print "\n.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#.-*#"

    while True:
        menu = ['Estrai Dati', 'Valuta Severity Evento', 'Verifica Host in Blacklist', 'Verifica Subnet',
                'Whois Resolver', "Chiudi"]
        print u'\n[*] Menù:\n'
        action = print_action_menu(menu)

        if action == 0:
            estrattore_dati()
        elif action == 1:
            severity_evaluator()
        elif action == 2:
            web_resource_crawler(True)
        elif action == 3:
            whois_responder(False)
        elif action == 4:
            whois_responder(True)
        elif action == 5:
            exit(0)

        op = raw_input("\nDesideri fare qualche altra operazione? [S/n]\n"
                       "\n>> ")
        if op == "S" or op == "s":
            pass
        else:
            raw_input("\nPress any button to quit...\n >> ")
            exit(0)
