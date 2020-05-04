# coding=utf-8

def online_poller(rr):
      from selenium.common.exceptions import TimeoutException
      from selenium.webdriver.chrome.options import Options
      from selenium.webdriver.common.keys import Keys
      from selenium.webdriver.support.ui import WebDriverWait
      from selenium.webdriver.support import expected_conditions as EC
      from selenium.webdriver.common.by import By
      from selenium import webdriver
      import getpass
      import time
      import os

      # Minuti: ricevo in secondi e moltiplico per 60
      intervallo = int(rr) * 60

      conf = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\smersh_extractor_keywords.txt"
      with open(conf, mode="r") as file:
            strings = file.read().splitlines()

      search_query = strings[12]
      url = strings[13].format(search_query, intervallo)

      print "[!] In attesa del form di login..."

      #chrome_driver_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents') + "\\chromedriver.exe"

      chrome_driver_path = "res/chromedriver.exe"

      chrome_options = Options()
      chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
      chrome_options.add_argument('--headless')
      # Questo try è necessario per quando lancio lo script tramite launcher che è collocato dentro la cartella res
      try:
            webdriver = webdriver.Chrome(executable_path=chrome_driver_path, options=chrome_options)
      except:
            chrome_driver_path = "chromedriver.exe"
            webdriver = webdriver.Chrome(executable_path=chrome_driver_path, options=chrome_options)

      webdriver.get(url)

      timeout = 2

      try:
            WebDriverWait(webdriver, timeout).until(EC.presence_of_element_located((By.XPATH, "/html/body/div/div/div/div/div/form/div[1]/span/input")))
      except TimeoutException:
            print("\n[!] In attesa di ricevere la pagina di login...")

      while 1:

            usr = webdriver.find_element_by_xpath("/html/body/div/div/div/div/div/form/div[1]/span/input")
            pwd = webdriver.find_element_by_xpath("/html/body/div/div/div/div/div/form/div[2]/span/input")


            u = raw_input("\n[*] Autenticazione richiesta.\n"
                          "\nUser: ")
            p = getpass.getpass("Password: ")

            usr.send_keys(u)
            pwd.send_keys(p + Keys.RETURN)

            try:
                  WebDriverWait(webdriver, timeout).until(EC.presence_of_element_located((By.XPATH, "//*[@id=\"main-row\"]/div[2]/div/div[1]/div/span/div/div[1]/div[1]/div/div[1]/span[1]")))
            except TimeoutException:
                  print("\n[!] In attesa di essere loggato...")

            if "Invalid credentials, please verify them and retry" in webdriver.page_source:
                  print "\n[!] Credenziali errate!"
            else:
                  break

      popup = raw_input("\n[*] Abilitare pop-up di notifica? (sconsigliato) [S/n]\n"
                        "\n>> ")

      print "\n[!] Premere 'Ctrl + C' in qualsiasi momento per interrompere il polling.\n"

      while True:
            try:
                  webdriver.get(url)
                  try:
                        WebDriverWait(webdriver, timeout).until(EC.presence_of_element_located((By.XPATH, "//*[@id=\"QueryEditor\"]/div[2]/div/div[3]/div/span[2]")))
                  except TimeoutException:
                      print("\n[!] Attendo la pagina di risposta...")

                  ips = []
                  x = 1

                  print "\n   [~] In ascolto..."

                  while True:
                        try:
                              val = webdriver.find_element_by_xpath("//*[@id=\"main-row\"]/div[2]/div/div[1]/div/span/div/div[1]/div/div/div[2]/div/div/div/table/tbody["+str(x)+"]/tr/td[1]/span").text
                              ips.append(val.encode("utf-8"))
                              x += 1
                        except:
                              break

                  #print webdriver.page_source

                  if ips:
                        from mail_sender import notify_service as nfs
                        from easygui import msgbox
                        from datetime import datetime

                        now = datetime.now()
                        timestamp = now.strftime("%d/%m/%Y %H:%M:%S")

                        for ip in ips:
                              print u"\n[!] Rilevata attività illecita per l'IP: {}" \
                                    "\n    Timestamp: {}".format(ip, timestamp)

                        nfs((intervallo/60), ips, [], "Smersh-On Poller", u=u, p=p)

                        if popup == "S" or popup == "s":
                              title = "[!] SECURITY ALERT [!]"
                              msg = "Rilevata attività per il NUOVO IP: {}\n" \
                                    "Timestamp: {}".format(", ".join(ips), timestamp)
                              msgbox(msg, title, ok_button="Chiudi")

                  time.sleep(intervallo)

            except KeyboardInterrupt:
                  print "\n-.-.-.-.-.-[!] Interrotto -.-.-.-.-.-\n"
                  break
