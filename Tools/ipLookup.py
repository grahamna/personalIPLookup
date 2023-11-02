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
virusTotalAPIKey = []
abuseIPDBKey = []
alienVaultAPIKey = []
shodanAPIKey = []

# List of Links used for IP lookup

links = ["https://talosintelligence.com/reputation_center/lookup?search=", "https://otx.alienvault.com/indicator/ip/", "https://www.shodan.io/host/","https://www.abuseipdb.com/check/","https://www.virustotal.com/gui/ip-address/",]

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
        if (count < 0):
            count = 0
        
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
    
    count = count / total
    outString = ''
    if claimedISP is not None or claimedISP != '':
        outString = claimedISP
    if claimedUsageType is not None or claimedUsageType != '':
        outString = claimedISP + ' ['+claimedUsageType+']' 
    if claimedCountry is not None or claimedCountry != '':    
        outString = outString + ', ('+claimedCountry+')'
    
    return count, outString

def main():
    #  For debugging using file as input for searching IPs
    # 
    # temp = []
    # with open('test.txt', 'r') as f:
    #     temp = f.read().splitlines()
    # f.close()
    # num = -1
    # with open('res.txt', 'w')as wr:
    #     for strings in temp:
    #         if (num >=7):
    #             num = 0
    #         else:
    #             num = num + 1
    #         ipAddress = strings
    #         print(f"{num} Looking up IP via API: {ipAddress}")
    #         count, outString = lookupHeadless(ipAddress, num)
    #         time.sleep(2)
    #         print('\nCount : '+str(count)+'\n')
    #         if count > 3.5:
    #             output = "Malicious activity suspected / reported"
    #         elif count <=3.5 and count > 1:
    #             output = "Insufficient evidence of malicious activity reported"
    #         else:
    #             output = "No malicious activity suspected / reported"
    #         res = outString + " - " + output
    #         print(res)
    #         wr.write(res+'\n')
    # wr.close()
    
    num = -1
    ipAddress = ''
    intext = ''
    while True:
        intext = input("\nQ to exit | Enter IP\n   ==> ")
        exitStatement = "q"
        headLookupKey = ''
        if intext == exitStatement:
            print("exiting")
            exit()
        elif intext == headLookupKey and ipAddress != '':
            print("Manual Look Up: "+ipAddress)
            lookupHead(ipAddress)
            time.sleep(1.75)
        else:
            if (num >=7):
                num = 0
            else:
                num = num + 1
            ipAddress = intext
            print("Looking up IP via API: " + ipAddress)
            count, outString = lookupHeadless(ipAddress, num)
            print('\nCount : '+str(count)+'\n')
            if count > 2.5:
                output = "Malicious activity suspected / reported"
            elif count <= 2.5 and count > 0.9:
                output = "Insufficient evidence of malicious activity reported"
            else:
                output = "No malicious activity suspected / reported"
            res = outString + " - " + output
            print ('\n'+res)
            pyperclip.copy(res)


if __name__ == '__main__':
    main()
