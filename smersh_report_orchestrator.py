#!/bin/python
# coding=utf-8

'''
    File name: smersh_report_orchestrator.py
    Author: Giorgio Rando
    Version: 2.0.2
    Date created: 02/2020
    Date last modified: 16/03/2020
    Python Version: 2.7
    To Do: VERIFICARE TIPO ATTACCO SE PRESENTE + ALLORA COMBINA TIPOLOGIA ATTACCO; Verificare sintassi input
'''

import pandas
import subprocess
import requests
import winreg
import urllib3
from tkinter.filedialog import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Funzione per l'estrazione automatica via web dei csv summary
def estrattore():
    folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_extractor_keywords.txt"
    with open(folder, mode="r") as file:
        content = file.read().splitlines()

    basic_path = content[0]
    csv_path_abs = content[1]
    csv_path_rel = content[2]

    ips = raw_input("\nInserisci IP [multipli separati da ,]: \n\n>> ")

    if ips == "DEMO" or ips == "demo":
        ips = content[3]
        date_in = "2020-03-16"
        date_out = date_in
        time_in = "01:29:00"
        time_out = "01:35:00"
        time_type_end = "1"
        absolute_timestamp_path = "&type=absolute&from=" + date_in + "T" + time_in.replace(":", "%3A") + ".000Z&to=" + \
                                  date_out + "T" + time_out.replace(":", "%3A") + ".000Z"
        stream_path = content[4]
        fields = ["timestamp", "farm", "IP", "IP_city_name", "request", "response", "useragent"]
        field_path = "timestamp%2Cfarm%2CIP%2CIP_city_name%2Crequest%2Cresponse%2Cuseragent"
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
        print '\n Scegli entità temporale desiderata:\n'
        for id, i in enumerate(time_type):
            print '{}) {}'.format(id, i)
        time_type_end = raw_input('\n>> ')

        intVerification(time_type_end, len(time_type))

        # Se RELATIVO
        if time_type_end == "1":
            date_in = raw_input("Inserisci Start Date [Es. 2020-03-16]: \n >> ")
            time_in = raw_input("Inserisci Start Time [Es. 03:00:00]: \n >> ")
            date_out = raw_input("Inserisci End Date [Es. 2020-03-16]: \n >> ")
            time_out = raw_input("Inserisci End Time [Es. 03:00:00]: \n >> ")
            absolute_timestamp_path = "&type=absolute&from=" + date_in + "T" + time_in.replace(":", "%3A") + ".000Z&to=" \
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

        fields = ["timestamp", "farm", "IP", "IP_city_name", "request", "response", "useragent"]
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

    r = requests.get(url=csv_url, headers=header, verify=False)

    if "must not be empty" in r.text or r.text == "":
        if time_type_end == "1":  # Se tempo assoluto
            print "\nEstrazione vuota! Ricontrollare i parametri:" \
                  "\n\n IPs: {};" \
                  "\n Timestamp in: {}:{};" \
                  "\n Timestamp out: {}:{};" \
                  "\n URL: {}" \
                  "\n Campi richiesti: {}.\n".format(ips, date_in, time_in, date_out, time_out, csv_url, fields)

            raw_input("\nPremi qualsiasi tasto per chiudere.\n>>")
            exit(0)
        else:
            print "\nEstrazione vuota! Ricontrollare i parametri:" \
                  "\n\n IPs: {};" \
                  "\n Giorni scanditi: {};" \
                  "\n URL: {}" \
                  "\n Campi richiesti: {}.\n".format(ips, giorni, csv_url, fields)

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

        each[1].columns = ['timestamp', 'farm', 'IP', 'IP_city_name', 'request', 'response', 'useragent']

        if mode == '0':
            each[1].to_csv(output + '\\' + filename + ".csv", index=False, sep=';')
        elif mode == '1':
            each[1].to_excel(output + '\\' + filename + ".xlsx", index=False)


def define_file_name(each, kind):
    # Ricavo l'IP per il filename
    define_ip = str(each[1]['IP'][0:1]).split(' ')[4].split('\n')[0]

    # Ricavo il datetime per il filename
    define_date_day = str(each[1]['timestamp'][0:1]).split(' ')[3]

    return define_ip.replace('.', '_') + '_' + kind + '_' + define_date_day


def intVerification(val, length):
    try:
        int(val)
        if int(val) > length - 1 or int(val) < 0:
            exit(0)
        else:
            pass
    except:
        print '\n No correct value!'
        exit(0)


if __name__ == "__main__":
    # Alcuni esempi...
    kind = ['Automated SQL Injection', 'nMap Scanning', 'Manual Vulnerability Probing', 'Automated Vulnerability '
                                                                                        'Probing', 'Spidering Events']
    print '\n[!] Scegli il vettore d\'attacco:\n'
    for id, i in enumerate(kind):
        print '{}) {}'.format(id, i)
    choose = raw_input('\n>> ')

    intVerification(choose, len(kind))

    exports = ['CSV', 'EXCEL']
    print '\n[!] Scegli il tipo di file che vuoi generare:\n'
    for id, i in enumerate(exports):
        print '{}) {}'.format(id, i)
    mode = raw_input('\n>> ')

    intVerification(mode, len(exports))

    modalita_prelevamento = ['FILE LOCALE', 'ESTRAZIONE DAL WEB']
    print '\n[!] Scegli una sorgente dati:\n'
    for id, i in enumerate(modalita_prelevamento):
        print '{}) {}'.format(id, i)
    source = raw_input('\n>> ')

    intVerification(source, len(modalita_prelevamento))

    if source == "0":
        Tk().withdraw()
        print '\n[!] Scegli quale file aprire: \n'
        file_path = askopenfilename()
    else:
        file_path = estrattore()

    desktop_path = desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    save_path = (desktop_path + "\\Estrazioni_Elaborate")
    if os.path.exists(save_path):
        pass
    else:
        os.mkdir(save_path)

    print "\n[!] Directory di assemblamento: {}".format(save_path)

    try:
        extract_values(kind[int(choose)].replace(' ', '_'), file_path, save_path, mode)
        print "\n[+++] Estrazione completata con Successo!\n"
        subprocess.Popen(r'explorer /select,"' + save_path + '"')
        raw_input("[i] Premi un tasto qualsiasi per concludere.\n"
                  "\n >> ")
    except:
        print "[!] Fallito! Qualcosa è andato storto."