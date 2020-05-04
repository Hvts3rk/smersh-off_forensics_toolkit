# coding=utf-8
import traceback
from datetime import datetime
import smtplib
import time
import os

def notify_service(intervallo, ip, labels, kind, u="", p=""):

    blck = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_blacklist.txt"
    mail_setting = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_mail_setting.txt"
    keywords = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_extractor_keywords.txt"

    done = False
    while not done:
        try:
            with open(mail_setting, mode="r") as file:
                content = file.read().split("|")
            done = True
        except:
            # Il file potrebbe essere usato contemporaneamente da smersh-on poller e blacklist poller se runnati
            # contemporaneamente. Pertanto ho previsto questa eccezione.
            time.sleep(3)

    now = datetime.now()
    timestamp = now.strftime("%d/%m/%Y %H:%M:%S")

    if not labels:
        fatto = False
        while not fatto:
            try:
                with open(blck, mode='r') as file:
                    listato = file.read().splitlines()
                fatto = True
            except:
                # Il file potrebbe essere usato contemporaneamente da smersh-on poller e blacklist poller se runnati
                # contemporaneamente. Pertanto ho previsto questa eccezione.
                time.sleep(3)

        for add in ip:
            for idx, x in enumerate(listato):
                if add in x:
                    labels.append(listato[idx-1])
                    break
                elif idx+1 == len(listato):
                    # Mi ricavo il net name tramite whois:
                    from ipwhois import IPWhois
                    import urllib2

                    with open(keywords, mode="r") as file:
                        config_file = file.read().splitlines()

                    handler = urllib2.ProxyHandler({'http': 'http://' + u + ':' + p + '@' + config_file[11]})
                    try:
                        opener = urllib2.build_opener(handler)
                        obj = IPWhois(add, proxy_opener=opener)
                        results = obj.lookup_rws()

                        netname = results["nets"][0]["name"]
                    except:
                        netname = "## INDIRIZZO NON RISOLTO!"

                    labels.append("# " + netname)
                    #labels.append("NUOVO IP")

                    # Quindi aggiungiamoli alla blacklist se dopo averla scorsa tutta non trovo corrispondenze
                    #label = "# NUOVO - DA VERIFICARE"

                    try:
                        with open(blck, mode="a") as blacklist:
                            blacklist.write("\n# " + netname)
                            blacklist.write("\n" + add)
                            print "\n[*] Blacklist file aggiornata con successo!"
                    except:
                        print u"\n[!] Qualcosa è andato storto nell'aggiornamento della blacklist!"
                        traceback.print_stack()

    for add in ip:
        # Infine estraiamo i dati generati dagli IP Segnalati...
        try:
            from smersh_off_forensics import estrattore_dati

            with open(blck, "r") as file:
                listone = file.read().splitlines()

            dest = [listone[idx-1] for idx, x in enumerate(listone) if add in x]
            dest = dest[0].replace("#","").replace(" ", "")
            folder_estrazione = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop') + "\\Estrazioni_Elaborate\\" + dest

            if not os.path.exists(folder_estrazione):
                os.makedirs(folder_estrazione)

            estrattore_dati(choose="5", ips=add, intervallo=(86400), verbose=False, save_path=folder_estrazione)

            print "\n[*] Estrazioni report avvenuta con successo!"
        except:
            print u"\n[!] Qualcosa è andato storto con il dump delle attività degli IP segnalati."
            traceback.print_stack()
            return None

    sender = content[0]
    receivers = content[1].split(',')
    message_payload = content[2].format(kind, str(intervallo),", ".join(ip), ", ".join(labels), timestamp)
    address = content[3]

    try:
        smtpObj = smtplib.SMTP(address)
        smtpObj.sendmail(sender, receivers, message_payload)
        print "\n   [***] Notificate figure interessate!"
    except smtplib.SMTPException:
        print "\n[!] Error: unable to send email"

    return None

'''if __name__ == "__main__":
    notify_service(5, ["1","2"])'''