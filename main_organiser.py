#!/bin/python

'''
    File name: main_organiser.py
    Author: Giorgio Rando
    Date created: 02/2020
    Date last modified: 06/03/2020
    Python Version: 2.7
'''

import pandas
from tkinter.filedialog import *
from openpyxl import Workbook



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

        print "\n Extracted: {}".format(filename)

        each[1].columns = ['timestamp', 'IP',  'IP_city_name','farm','request', 'response', 'useragent']

        if mode == '0':
            each[1].to_csv(output + '\\' + filename + ".csv", index=False, sep=';')
        elif mode == '1':
            each[1].to_excel(output + '\\' + filename + ".xlsx", index=False)


def define_file_name(each, kind):
    # Ricavo l'IP per il filename
    define_ip = str(each[1]['IP'][0:1]).split(' ')[4].split('\n')[0]

    # Ricavo il datetime per il filename
    define_date_day = str(each[1]['timestamp'][0:1]).split(' ')[3]

    return define_ip.replace('.','_') + '_' + kind + '_' + define_date_day

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
    kind = ['Automated SQL Injection', 'nMap Scanning', 'Manual Vulnerability Probing', 'Automated Vulnerability '
                                                                                        'Probing', 'Spidering Events']
    print '\n Choose attack\'s vector:\n'
    for id, i in enumerate(kind):
        print '{}) {}'.format(id, i)
    choose = raw_input('\n>> ')

    intVerification(choose, len(kind))

    exports = ['CSV', 'EXCEL']
    print '\n Choose export\'s type:\n'
    for id, i in enumerate(exports):
        print '{}) {}'.format(id, i)
    mode = raw_input('\n>> ')

    intVerification(mode, len(exports))

    Tk().withdraw()
    print '\n Choose what file to open to: \n NB. The output will be written into Desktop\\EstrazioniAggregate\'s folder '
    file_path = askopenfilename()
    print "\n {}".format(file_path)

    print '\n Choose where to save organised files:'
    if os.path.exists('C:\\Users\\randog\\Desktop\\EstrazioniAggregate'):
        pass
    else:
        os.mkdir('C:\\Users\\randog\\Desktop\\EstrazioniAggregate')

    save_path = 'C:\\Users\\randog\\Desktop\\EstrazioniAggregate'

    print "\n {}".format(save_path)

    extract_values(kind[int(choose)].replace(' ', '_'), file_path, save_path, mode)
