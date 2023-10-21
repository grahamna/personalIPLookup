# Nathan Graham - Personal Use
# Python 3.11.5

import webbrowser
import time

# Path to browser executable
browser = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe %s"

# List of Links used for IP lookup

links = ["https://www.abuseipdb.com/check/", "https://www.virustotal.com/gui/ip-address/",
         "https://talosintelligence.com/reputation_center/lookup?search=", "https://otx.alienvault.com/indicator/ip/", "https://www.shodan.io/host/"]

# function to iterate over links, opening new web browser page and new tabs with the passed in ip address. Sleep is required for correct tab order.

def lookup(ipAddress):
    webbrowser.open_new_tab(
        "https://www.virustotal.com/gui/ip-address/"+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new_tab(
        "https://talosintelligence.com/reputation_center/lookup?search="+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new_tab(
        "https://otx.alienvault.com/indicator/ip/"+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new_tab("https://www.shodan.io/host/"+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new("https://www.abuseipdb.com/check/"+ipAddress)


def main():
    while True:
        ipAddress = input("Q to exit | Enter IP\n   ==>")
        exitStatement = "q"
        if ipAddress == exitStatement:
            print("exiting")
            exit()
        print("Looking up IP " + ipAddress)
        lookup(ipAddress)


if __name__ == '__main__':
    main()
