# Nathan Graham - Personal Use
# This application was developed in my own free time without company resources
# Python 3.11.5

import time
import webbrowser
import requests
import json
import threading
import pyperclip

# Path to browser executable
browser = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe %s"

# These should be your API keys for each service

virusTotalAPIKey = []

abuseIPDBKey = []

alienVaultAPIKey = []

shodanAPIKey = []

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
    
    threads.append(threading.Thread(target=abuseipdb_request))
    threads.append(threading.Thread(target=virustotal_request))
    threads.append(threading.Thread(target=alienvault_request))
    threads.append(threading.Thread(target=shodan_request))

    for thread in threads:
        thread.start()
    
    for thread in threads:
        thread.join()
    
    if responses['abuseipd'].status_code == 200:
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
            if data.get('isp') is not None:
                claimedISP = data.get('isp')
            else:
                claimedISP = ''
            if data.get('usageType') is not None:
                claimedUsageType = data.get('usageType')
            else:
                claimedUsageType = 'Unknown'
            if data.get('countryCode') is not None:
                claimedCountry = data.get('countryCode')
            else:
                claimedCountry = ''
            if data.get('domain') is not None:
                claimedDomain = data.get('domain')
            else:
                claimedDomain = ''
    
    if responses['virustotal'].status_code == 200:
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
        
    if responses['alienvault'].status_code == 200:
        total = total+1
        contentAlienVault = json.loads(responses['alienvault'].text)
        if contentAlienVault.get('country_code') is not None and claimedCountry.__contains__(contentAlienVault.get('country_code')):
            if contentAlienVault.get('region') is not None:
                claimedCountry = claimedCountry + ', '+contentAlienVault.get('region')
                count = count - .1
            if contentAlienVault.get('city') is not None:
                claimedCountry = claimedCountry+ ' - '+contentAlienVault.get('city')
                count = count -.25
        elif contentAlienVault.get('country_code') is not None:
            claimedCountry = claimedCountry + "/"+contentAlienVault.get('country_code')
            count = count + 1
        else:
            count = count + 1
        if contentAlienVault.get('reputation') is not None:
            count = count + contentAlienVault.get('reputation')
    
    if responses['shodan'].status_code == 200:
        total = total+1
        contentShodan = json.loads(responses['shodan'].content)
        if claimedCountry.__contains__(contentShodan.get('country_code')) is False:
            claimedCountry = claimedCountry + "/"+contentAlienVault.get('country_code')
            count = count +1
        else:
            count = count -.25
    
    if (total != 0):
        outString = ''
        count = count / total
        if claimedISP is not None or claimedISP != '':
            outString = claimedISP
        if claimedUsageType is not None or claimedUsageType != '':
            outString = claimedISP + ' ['+claimedUsageType+']' 
        if claimedCountry is not None or claimedCountry != '':    
            outString = outString + ', ('+claimedCountry+')'
    
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

def processIp(ip, num, out):
    if isPrivateIP(ip):
        print('\nPrivate IP address detected')
    else:
        print("Looking up IP via API: " + ip)
        count, outString = lookupHeadless(ip, num)
        print('\nCount : ' + str(count) + '\n')
        if count > 2.5:
            output = "Malicious activity suspected / reported"
        elif 0.9 < count <= 2.5:
            output = "Inconclusive evidence of malicious activity suspected / reported"
        else:
            output = "No malicious activity suspected / reported"
        result = outString + " - " + output
        if (out == False):
            print('\n' + result)
            pyperclip.copy(result)
        else:
            return result


def main():
    num = -1
    ipAddress = ''
    intext = ''
    
    while True:
        intext = input("\nQ to exit | Enter IP\n   ==> ")
        exitStatement = "q"
        headLookupKey = ''

        if intext == exitStatement:
            print("exiting...")
            exit()
        elif intext == headLookupKey and ipAddress != '':
            print("Manual Look Up: " + ipAddress)
            lookupHead(ipAddress)
            time.sleep(1.75)
        else:
            if num >= 7:
                num = 0
            else:
                num = num + 1

            ipAddress = intext
            processIp(ipAddress, num, False)


if __name__ == '__main__':
    main()
