```
____                          _            ___   __  __ 
/ ___| _ __ ___   ___ _ __ ___| |__        / _ \ / _|/ _|
\___ \| '_ ` _ \ / _ \ '__/ __| '_ \ _____| | | | |_| |_ 
 ___) | | | | | |  __/ |  \__ \ | | |_____| |_| |  _|  _|
|____/|_| |_| |_|\___|_|  |___/_| |_|      \___/|_| |_|  
                                                         
 _____                        _           
|  ___|__  _ __ ___ _ __  ___(_) ___ ___  
| |_ / _ \| '__/ _ \ '_ \/ __| |/ __/ __| 
|  _| (_) | | |  __/ | | \__ \ | (__\__ \ 
|_|  \___/|_|  \___|_| |_|___/_|\___|___/ 
                                              
 ____                                        _        _   _             
|  _ \  ___   ___ _   _ _ __ ___   ___ _ __ | |_ __ _| |_(_) ___  _ __  
| | | |/ _ \ / __| | | | '_ ` _ \ / _ \ '_ \| __/ _` | __| |/ _ \| '_ \ 
| |_| | (_) | (__| |_| | | | | | |  __/ | | | || (_| | |_| | (_) | | | |
|____/ \___/ \___|\__,_|_| |_| |_|\___|_| |_|\__\__,_|\__|_|\___/|_| |_|

							by Giorgio Rando

```

# Smersh-Off Forensics Toolkit
Smersh-Off Forensics is an automatic forense toolkit with the aim of personalizing post-detection analysis
of alerts issued by Smersh (SIEM graduation project). This toolkit consists in a bounch of useful tools
to assist the SOC Analyst in understanding the entities in place and in the intersection of
apparently disconnected situations.

## Functions

 * Extract data from Log Manager
 * Evaluate events severity
 * Check Graylist/Blacklist hosts activity
   * Polling Mode
   * One-Shot Mode
 * Check subnet in Blacklist
 * Whois Resolver
 * Blacklist and Graylist management
 
 ## Usage
 First of all install all required packages: 
 ```
 pip install -r requirements.txt
 ```
 Then just... Read the readme file into /res folder. For the applicative documentation and config files contact me:
 [Giorgio Rando](https://www.linkedin.com/in/giorgio-rando-163710b4/)

![Image of Smersh-Off](https://github.com/Hvts3rk/smersh-off_forensics_toolkit/blob/master/images/screen.png)
