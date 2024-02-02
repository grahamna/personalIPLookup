# Nathan Graham - Personal Use
# This application was developed in my own free time without company resources
# Python 3.11.5

import time
import webbrowser
import os
from ipwhois import IPWhois
import requests
import json
import threading
import pyperclip
import csv
from datetime import datetime

# Path to browser executable
browser = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe %s"

# These should be your API keys for each service

virusTotalAPIKey = []

abuseIPDBKey = []

alienVaultAPIKey = []

shodanAPIKey = []


class IPDb:
    def __init__(self, file):
        self.ipResultsDb = {}
        self.loadFromDatabase(file)

    def saveIpResults(self, ip, outString, output):
        timestamp = datetime.now()
        self.ipResultsDb[ip] = {'ipString': outString, 'output': output, 'timestamp': timestamp}

    def updateIpResults(self, ip, outString, output):
        if ip in self.ipResultsDb:
            timestamp = datetime.now()
            self.ipResultsDb[ip] = {'ipString': outString, 'output': output, 'timestamp': timestamp}

    def loadFromDatabase(self, file):
        try:
            with open(file, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    ip = row['ip']
                    outString = row['ipString']
                    output = row['output']
                    timestamp = datetime.strptime(row['timestamp'], '%m/%d/%Y %H:%M:%S.%f')
                    self.ipResultsDb[ip] = {'ipString': outString, 'output': output, 'timestamp': timestamp}
        except FileNotFoundError:
            print("DB file not found, blank ipResultObj ref")
            pass

    def writeToFile(self, file):
        with open(file, 'w', newline='') as csvfile:
            fieldnames = ['ip', 'ipString', 'output', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header if the file is empty
            if csvfile.tell() == 0:
                writer.writeheader()

            # Write all records to the CSV file
            for ip, data in self.ipResultsDb.items():
                writer.writerow({'ip': ip, 'ipString': data['ipString'], 'output': data['output'],'timestamp': data['timestamp'].strftime('%m/%d/%Y %H:%M:%S.%f')})

# function to iterate over links, opening new web browser page and new tabs with the passed in ip address. Sleep is required for correct tab order.

def lookupHead(ipAddress):
    webbrowser.open_new_tab(
        "https://www.virustotal.com/gui/ip-address/"+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new_tab("https://urlscan.io/search/#"+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new_tab(
        "https://talosintelligence.com/reputation_center/lookup?search="+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new_tab(
        "https://otx.alienvault.com/indicator/ip/"+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new_tab("https://www.shodan.io/host/"+ipAddress)
    time.sleep(0.1)
    webbrowser.open_new_tab("https://www.abuseipdb.com/check/"+ipAddress)


def lookupHeadless(ipAddress, num):
    count = 0
    total = 0
    threads = []
    responses = {}

    whois = False
    
    def abuseipdb_request():
        urlAbuseIP = 'https://api.abuseipdb.com/api/v2/check'
        querystringAbuseIP = {
            'ipAddress': ipAddress.strip(),
            'maxAgeInDays': '90'
        }
        headersAbuseIP = {
            'Accept': 'application/json',
            'Key': abuseIPDBKey [num]
        }
        responseAbuseIP = requests.request(method='GET', url=urlAbuseIP, headers=headersAbuseIP, params=querystringAbuseIP)
        responses['abuseipd'] = responseAbuseIP
    
    def virustotal_request():
        urlVirusTotal = "https://www.virustotal.com/api/v3/ip_addresses/"+ipAddress.strip()
        headersVirusTotal = {
            "accept": "application/json",
            "x-apikey": virusTotalAPIKey[num]
            }
        responseVirusTotal = requests.get(urlVirusTotal.strip(), headers=headersVirusTotal)
        responses['virustotal'] = responseVirusTotal
    
    def shodan_request():
        shodanURL = f'https://api.shodan.io/shodan/host/{ipAddress.strip()}?key={shodanAPIKey[num]}'
        responceShodan = requests.get(shodanURL)
        responses['shodan'] = responceShodan
    
    def alienvault_request():
        urlAlienVault = "https://otx.alienvault.com/api/v1/indicators/IPv4/"+ipAddress.strip()+"/general"
        headersAlienVault = {
            "accept": "application/json",
            "X-OTX-API-KEY" : alienVaultAPIKey[num]
            }
        responseAlienVault = requests.get(urlAlienVault.strip(), headers=headersAlienVault)
        responses['alienvault'] = responseAlienVault
    
    def whoIsIp():
        try:
            res = IPWhois(ipAddress)
            responses['whois'] = res.lookup_whois()
        except:
            print("whois lookup Failed")
    
    
    threads.append(threading.Thread(target=whoIsIp))
    threads.append(threading.Thread(target=abuseipdb_request))
    threads.append(threading.Thread(target=virustotal_request))
    threads.append(threading.Thread(target=alienvault_request))
    threads.append(threading.Thread(target=shodan_request))

    for thread in threads:
        thread.start()
    
    for thread in threads:
        thread.join()
        
    if responses.get('whois') != True:
        nets = responses['whois'].get('nets')
        data = nets[-1]
        if data.get('description') is not None:
            claimedISP = data.get('description')
        else: claimedISP = ''
        if data.get('country') is not None:
            claimedCountry = data.get('country')
        else: claimedCountry = ''
        if data.get('state') is not None:
            claimedState = data.get('state')
        else: claimedState = ''
        if data.get('city') is not None:
            claimedCity = data.get('city')
        else: claimedCity = ''
        if data.get('range') is not None:
            ipRange = data.get('range')
        else: ipRange = ''
    else: 
        claimedISP = ''
        claimedCountry = ''
        claimedState = ''
        claimedCity = ''
        ipRange = ''
    
    if responses.get('abuseipd') != None and responses['abuseipd'].status_code == 200:
            total = total+1
            contentAbuseIP = json.loads(responses['abuseipd'].text)
            data = contentAbuseIP.get('data')
            if data.get('isWhitelisted') is False:
                count = count+1
            else:
                count = count - 1
            if data.get('abuseConfidenceScore') > 6:
                count = count + (data.get('abuseConfidenceScore')/10)
            if data.get('isTor') == True:
                count = count + 1.5
            if data.get('isp') is not None and data.get('isp') != claimedISP:
                if claimedISP == '':
                    claimedISP = data.get('isp')
                claimedISP = claimedISP + "/"+data.get('isp')
                count = count + .5
            if data.get('usageType') is not None:
                claimedUsageType = data.get('usageType')
            else:
                claimedUsageType = 'Unknown'
            if data.get('countryCode') != claimedCountry and data.get('countryCode') is not None and claimedCountry != '':
                print("FOUND DIFFERENT COUNTRY CODE?? "+data.get('countryCode'))
            elif claimedCountry == '':
                claimedCountry = data.get('countryCode')
    else: pass
    
    
    if responses.get('virustotal') != None and responses['virustotal'].status_code == 200:
        total = total+1
        contentVirusTotal = json.loads(responses['virustotal'].text)
        data = contentVirusTotal.get('data').get('attributes')
        if data.get('as_owner') is not None and data.get('as_owner').lower() != claimedISP.lower():
            claimedISP = claimedISP+"/"+data.get('as_owner')
            count=count+1
        if data.get('country') is not None and data.get('country').lower() != claimedCountry.lower():
            claimedISP = claimedISP+"/"+data.get('country')
            count = count+1
        count = count + (data.get('last_analysis_stats').get('malicious') * 2.75) - (data.get('reputation')/10)
        if (count < -2):
            count = -2
    else: pass
    
    if responses.get('alienvault') != None and responses['alienvault'].status_code == 200:
        total = total+1
        contentAlienVault = json.loads(responses['alienvault'].text)
        if contentAlienVault.get('country_code') is not None and claimedCountry.__contains__(contentAlienVault.get('country_code')):
            if contentAlienVault.get('region') is not None:
                count = count - .1
            if contentAlienVault.get('city') is not None:
                count = count -.20
        elif contentAlienVault.get('country_code') is not None:
            claimedCountry = claimedCountry + "/"+contentAlienVault.get('country_code')
            count = count + 1
        else:
            count = count + 1
        if contentAlienVault.get('reputation') is not None:
            count = count + contentAlienVault.get('reputation')
    
    if responses.get('shodan') != None and responses['shodan'].status_code == 200:
        total = total+1
        contentShodan = json.loads(responses['shodan'].content)
        if claimedCountry.__contains__(contentShodan.get('country_code')) is False:
            count = count +1
        else:
            count = count -.25
    else: pass
    
    if (total != 0):
        outString = ''
        count = count / total
        if claimedISP != '':
            outString = claimedISP
        if claimedUsageType != '':
            outString = claimedISP + ' ['+claimedUsageType+']'
        if ipRange is not None or ipRange != '' or ipRange != 'None':
            outString = outString + f" <Ip Range: {ipRange}>"
        if claimedCountry != '': 
            if claimedState != '':
                if claimedCity != '':
                    outString = outString + f' ({claimedCountry}, {claimedState} - {claimedCity})'
            elif claimedCity != '':
                outString = outString + f' ({claimedCountry}, - {claimedCity})'
            else: outString = outString + f' ({claimedCountry})'
    
    else:
        outString = 'Unknown IP Address'
    
    return count, outString


def isPrivateIP(ip):
    # Class A: 10.0.0.0 to 10.255.255.255,
    # Class B: 172.16.0.0 to 172.31.255.255,
    # Class C: 192.168.0.0 to 192.168.255.255
    
    octets = ip.split('.')
    
    # Check if the IP address is in any of the private IP address ranges
    if octets[0] == '10' or (octets[0] == '172' and 16 <= int(octets[1]) <= 31) or (octets[0] == '192' and octets[1] == '168'):
        return True
    return False


def processIp(myIPDb, ip, num, out):
    if isPrivateIP(ip):
        print('\nPrivate IP address detected')
        return
        
    elif myIPDb.ipResultsDb.get(ip) and (datetime.now() - myIPDb.ipResultsDb[ip]['timestamp']).total_seconds() < 60 * 60 * 72:
        # IP is in the database and the timestamp is less than 72 hours old
        print("Found IP in database")
        outString = myIPDb.ipResultsDb[ip]['ipString']
        output = myIPDb.ipResultsDb[ip]['output']
        
    else:
        try:
            print("Looking up IP via API: " + ip)
            count, outString = lookupHeadless(ip, num)
            print('\nCount : ' + str(count))
            if count > 2.5:
                output = "Malicious activity suspected / reported"
            elif 0.9 < count <= 2.5:
                output = "Inconclusive evidence of malicious activity suspected / reported"
            else:
                output = "No malicious activity suspected / reported"
                
            # Save the IP lookup results to the database
            if(myIPDb.ipResultsDb.get(ip)):
                myIPDb.updateIpResults(ip, outString, output)
            else:
                myIPDb.saveIpResults(ip, outString, output)
        except:
            print("LookupHeadless had an error")
            return

    result = outString + " => " + output
    if not out:
        print('\n'+result)
        pyperclip.copy(' => ' + result)
    else:
        return result
    
def editIp(myIPDb, ip, inString):
    splitString = inString.split(' => ')
    try:
        assert len(splitString) == 2
        outString = splitString[0].strip()
        output = splitString[1].strip()
        assert outString != '' and output != '' and (output == 'Malicious activity suspected / reported' or output == 'Inconclusive evidence of malicious activity suspected / reported' or output == 'No malicious activity suspected / reported')
        if(myIPDb.ipResultsDb.get(ip)):
            myIPDb.updateIpResults(ip, outString, output)
        else:
            print(f"{ip} not found in IPDb, returning to main")
    except:
        print(f"editIP had an error, no change for IP : {ip}")
        return

def main():
    try:
        dirname = os.path.dirname(__file__)
        dbFile = os.path.join(dirname, '../ipDb.csv')
        myIPDb = IPDb(dbFile)
        
        num = -1
        ipAddress = ''
        intext = ''
        
        while True:
            intext = input("Q to exit | Enter IP\n\t==> ")
            exitStatement = "q"
            editStatement = "e"
            headLookupKey = ''
            if intext == headLookupKey and ipAddress != '':
                print("Manual Look Up: " + ipAddress)
                lookupHead(ipAddress)
                time.sleep(1.75)
            if intext == editStatement and ipAddress != '':
                print(f"Editing result for IP : {ipAddress}\n Use this format, IpDetails => Determination")
                inString = input(f"\t{ipAddress} => ")
                editIp(myIPDb, ipAddress, inString)
            elif intext == exitStatement:
                print("exiting...")
                exit()
            else:
                if num >= 7:
                    num = 0
                else:
                    num = num + 1
                ipAddress = intext
                processIp(myIPDb, ipAddress, num, False)
    except:
        print("Writing to "+dbFile)
        myIPDb.writeToFile(dbFile)

if __name__ == '__main__':
    main()
