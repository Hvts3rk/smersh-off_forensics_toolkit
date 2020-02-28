#!/bin/python

import pandas
from Tkinter import Tk
from tkinter.filedialog import *
from tkinter import filedialog

def extract_values(kind, file):
    pandas.set_option('display.max_rows', 10000)
    pandas.set_option('display.expand_frame_repr', False)

    df = pandas.read_csv(file, header=0)
    df["timestamp"] = pandas.to_datetime(df["timestamp"])
    df = df.groupby(['IP', pandas.DatetimeIndex(df['timestamp']).day])

    for each in df:
        filename = define_file_name(each, kind)

        # For debug purpose-only
        # print each[1].to_csv(index=False)
        ########################

        print "\n Extracted: {}".format(filename)

        each[1].to_csv(filename + ".csv", index=False)


def define_file_name(each, kind):
    # Ricavo l'IP per il filename
    define_ip = str(each[1]['IP'][0:1]).split(' ')[4].split('\n')[0]

    # Ricavo il datetime per il filename
    define_date_day = str(each[1]['timestamp'][0:1]).split(' ')[3]

    return define_ip + '_' + kind + '_' + define_date_day


if __name__ == "__main__":
    kind = ['Automated SQL Injection', 'nMap Scanning', 'Manual Vulnerability Probing', 'Automated Vulnerability '
                                                                                        'Probing', 'Spidering Events']
    print '\n Choose attack\'s vector:\n'
    for id, i in enumerate(kind):
        print '{}) {}'.format(id, i)
    choose = raw_input('\n> ')

    try:
        int(choose)
        if int(choose) > len(kind) - 1 or int(choose) < 0:
            exit(0)
        else:
            pass
    except:
        print '\n No correct value!'
        exit(0)

    Tk().withdraw()
    print '\n Choose what file to open to:'
    file_path = askopenfilename()
    print "\n {}".format(file_path)

    print '\n Choose where to save organised files:\n'
    save_path = filedialog.askdirectory
    print "\n {}".format(save_path)

    #extract_values(kind[int(choose)].replace(' ', '_'), file_path)
