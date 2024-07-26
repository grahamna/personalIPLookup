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
from datetime import datetime

import iPAddressDb as IPAdb


class IpLookup():

    # Path to browser executable, whatever yours may be
    _browser = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe %s"

    # These should be your API keys for each service

    _virusTotalAPIKey = []

    _abuseIPDBKey = []

    _alienVaultAPIKey = []

    _shodanAPIKey = []
        
    def __init__(self, browser=None):

        if browser is not None:
            self._browser = browser
        
            
    
    # function to iterate over links, opening new web browser page and new tabs with the passed in ip address. Sleep is required for correct tab order.
    
    def lookupHead(self, ipAddress):
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
    
    
    def lookupHeadless(self, ipAddress, num):
        count = 0
        total = 0
        threads = []
        responses = {}
    
        def abuseipdb_request(self):
            urlAbuseIP = 'https://api.abuseipdb.com/api/v2/check'
            querystringAbuseIP = {
                'ipAddress': ipAddress.strip(),
                'maxAgeInDays': '90'
            }
            headersAbuseIP = {
                'Accept': 'application/json',
                'Key': self._abuseIPDBKey [num]
            }
            responseAbuseIP = requests.request(method='GET', url=urlAbuseIP, headers=headersAbuseIP, params=querystringAbuseIP)
            responses['abuseipd'] = responseAbuseIP
    
        def virustotal_request(self):
            urlVirusTotal = "https://www.virustotal.com/api/v3/ip_addresses/"+ipAddress.strip()
            headersVirusTotal = {
                "accept": "application/json",
                "x-apikey": self._virusTotalAPIKey[num]
                }
            responseVirusTotal = requests.get(urlVirusTotal.strip(), headers=headersVirusTotal)
            responses['virustotal'] = responseVirusTotal
    
        def shodan_request(self):
            shodanURL = f'https://api.shodan.io/shodan/host/{ipAddress.strip()}?key={self._shodanAPIKey[num]}'
            responceShodan = requests.get(shodanURL)
            responses['shodan'] = responceShodan
    
        def alienvault_request(self):
            urlAlienVault = "https://otx.alienvault.com/api/v1/indicators/IPv4/"+ipAddress.strip()+"/general"
            headersAlienVault = {
                "accept": "application/json",
                "X-OTX-API-KEY" : self._alienVaultAPIKey[num]
                }
            responseAlienVault = requests.get(urlAlienVault.strip(), headers=headersAlienVault)
            responses['alienvault'] = responseAlienVault
    
        def whoIsIp():
            try:
                res = IPWhois(ipAddress.strip())
                responses['whois'] = res.lookup_whois()
            except:
                print("whois lookup Failed")
    
        threads.append(threading.Thread(target=whoIsIp))
        threads.append(threading.Thread(target=abuseipdb_request(self)))
        threads.append(threading.Thread(target=virustotal_request(self)))
        threads.append(threading.Thread(target=alienvault_request(self)))
        threads.append(threading.Thread(target=shodan_request(self)))
    
        for thread in threads:
            thread.start()
    
        for thread in threads:
            thread.join()
    
        if responses.get('whois') != None:
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
            if data.get('range') is not None and data.get('range') != '' and data.get('range') != 'None' and data.get('range') != ' ':
                ipRange = data.get('range')
                lowerIpRange = ipRange.split(' - ')[0]
                upperIpRange = ipRange.split(' - ')[1]
                ipRangeDto = f"{lowerIpRange.split('.')[0]}-{upperIpRange.split('.')[0]}.{lowerIpRange.split('.')[1]}-{upperIpRange.split('.')[1]}.{lowerIpRange.split('.')[2]}-{upperIpRange.split('.')[2]}.{lowerIpRange.split('.')[3]}-{upperIpRange.split('.')[3]}"
            else:
                ipRangeDto, lowerIpRange, upperIpRange = self.unknownIpRange(ipAddress)
        else:
            claimedISP = ''
            claimedCountry = ''
            claimedState = ''
            claimedCity = ''
            ipRangeDto, lowerIpRange, upperIpRange = self.unknownIpRange(ipAddress)
    
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
                if data.get('isp') is not None and data.get('isp').lower() != claimedISP.lower():
                    if claimedISP == '':
                        claimedISP = data.get('isp')
                    else : 
                        claimedISP = claimedISP + "/"+data.get('isp')
                        count = count + .5
                if data.get('usageType') is not None:
                    claimedUsageType = data.get('usageType')
                else:
                    claimedUsageType = 'Unknown'
                if data.get('countryCode') != claimedCountry and data.get('countryCode') is not None and claimedCountry != '':
                    claimedCountry = claimedCountry + '/'+data.get('countryCode')
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
            if claimedUsageType != '' and claimedUsageType != "Unknown":
                outString = claimedISP + ' ['+claimedUsageType+']'
            outString = outString + f" <Ip Range: {lowerIpRange} - {upperIpRange}>"
            if claimedCountry != '':
                if claimedState != '':
                    if claimedCity != '':
                        outString = outString + f' ({claimedCountry}, {claimedState} - {claimedCity})'
                elif claimedCity != '':
                    outString = outString + f' ({claimedCountry}, - {claimedCity})'
                else: outString = outString + f' ({claimedCountry})'
    
        else:
            print('Unknown IP Address')
    
        return count, outString, ipRangeDto
    
    def unknownIpRange(self, ipAddress):
        fact = True
        while(fact):
            strIn = input(f"Failed to find IpRange data for this IP : {ipAddress.strip()}\n  Please enter in IP Range data (format should be ipLower - ipUpper )\n\t==> ")
            if strIn is not None and strIn != '' and strIn != 'None' and strIn != ' ' and strIn.find(' - ') != -1:
                lowerIpRange = strIn.split(' - ')[0]
                upperIpRange = strIn.split(' - ')[1]
                check = True
                lowerCheck = lowerIpRange.split('.')
                upperCheck = upperIpRange.split('.')
                if (len(lowerCheck) == 4 and len(upperCheck) == 4):
                    for x in range(0,3,1):
                        if (int(lowerCheck[x]) > int(upperCheck[x])):
                            check = False
                    if check:
                        ipRangeDto = f"{lowerIpRange.split('.')[0]}-{upperIpRange.split('.')[0]}.{lowerIpRange.split('.')[1]}-{upperIpRange.split('.')[1]}.{lowerIpRange.split('.')[2]}-{upperIpRange.split('.')[2]}.{lowerIpRange.split('.')[3]}-{upperIpRange.split('.')[3]}"
                        if (self.testIpRange(ipAddress, ipRangeDto)):
                            fact = False
                        else: print("IP address must be contained within the proposed IP range")
            elif (strIn == str(ipAddress)):
                print("Making a single IP address Entry")
                lowerIpRange = ipAddress
                upperIpRange = ipAddress
                ipRangeDto = f"{lowerIpRange.split('.')[0]}-{upperIpRange.split('.')[0]}.{lowerIpRange.split('.')[1]}-{upperIpRange.split('.')[1]}.{lowerIpRange.split('.')[2]}-{upperIpRange.split('.')[2]}.{lowerIpRange.split('.')[3]}-{upperIpRange.split('.')[3]}"
                fact = False
        return ipRangeDto, lowerIpRange, upperIpRange
    
    def isPrivateIP(self, ip):
        # Class A: 10.0.0.0 to 10.255.255.255,
        # Class B: 172.16.0.0 to 172.31.255.255,
        # Class C: 192.168.0.0 to 192.168.255.255
    
        octets = ip.split('.')
    
        # Check if the IP address is in any of the private IP address ranges
        if octets[0] == '10' or (octets[0] == '172' and 16 <= int(octets[1]) <= 31) or (octets[0] == '192' and octets[1] == '168'):
            return True
        return False
    
    def testIpRange(self, ipAddress, ipRange):
            ipOct = ipAddress.split('.')
            lOct1, uOct1  = ipRange.split('.')[0].split('-')
            if (int(lOct1) <= int(ipOct[0]) and int(ipOct[0]) <= int(uOct1)) == False :
                return False
            lOct2, uOct2  = ipRange.split('.')[1].split('-')
            if (int(lOct2) <= int(ipOct[1]) and int(ipOct[1]) <= int(uOct2)) == False :
                return False
            lOct3, uOct3  = ipRange.split('.')[2].split('-')
            if (int(lOct3) <= int(ipOct[2]) and int(ipOct[2]) <= int(uOct3)) == False :
                return False
            lOct4, uOct4  = ipRange.split('.')[3].split('-')
            if (int(lOct4) <= int(ipOct[3]) and int(ipOct[3]) <= int(uOct4)) == False :
                return False
            return True
    
    def processIp(self, refToDB, ip, num, out):
        if self.isPrivateIP(ip):
            print('\nPrivate IP address detected')
            return
    
        ipRange = refToDB.getIpResults(ip)
    
        if ipRange != False and (datetime.now() - refToDB.ipResultsDb[ipRange]['timestamp']).total_seconds() < 60 * 60 * 72:
            # IP is in the database and the timestamp is less than 72 hours old
            outString = refToDB.ipResultsDb[ipRange]['ipString']
            output = refToDB.ipResultsDb[ipRange]['output']
            print("Found recent match for IP: " + ip)
    
        else:
            try:
                print("Looking up IP via API: " + ip)
                count, outString, ipRangeDto = self.lookupHeadless(ip, num)
                assert outString != "" and count != None
                print('\nCount : ' + str(count))
                if count > 2.5:
                    output = "Strong evidence for Malicious activity"
                elif 0.9 < count <= 2.5:
                    output = "Inconclusive evidence for Malicious activity"
                else:
                    output = "Little to No evidence for Malicious activity"
    
                # Save the IP lookup results to the local version of the database
                if(refToDB.ipResultsDb.get(ipRangeDto) != None):
                    refToDB.updateIpResults(ipRangeDto, outString, output)
                else:
                    refToDB.saveIpResults(ipRangeDto, outString, output)
            except:
                print(f"LookupHeadless had an error with IP : {ip}")
                return
    
        result = outString + " => " + output
        if not out:
            print('\n'+result)
            pyperclip.copy(result)
        else:
            return result
    
    def editIp(self, refToDB, ip, inString):
        splitString = inString.split(' => ')
        try:
            assert len(splitString) == 2
            outString = splitString[0].strip()
            output = splitString[1].strip()
            assert outString != '' and output != '' and (output == 'Strong evidence for Malicious activity' or output == 'Inconclusive evidence for Malicious activity' or output == 'Little to No evidence for Malicious activity')
            dbHasIP = refToDB.getIpResults(ip)
            if(dbHasIP != False):
                refToDB.updateIpResults(dbHasIP, outString, output)
            else:
                print(f"{ip} not found in IPDb, returning to main")
        except:
            print(f"editIP had an error, no change for IP : {ip}")
            return
 
    def run(self):

        try:
            dirname = os.path.dirname(__file__)
            dbFile = os.path.join(dirname, '../ipAddressDataBase.csv')
            refToDB = IPAdb.IPAddressDatabaseObj(dbFile)
    
            num = -1
            ipAddress = ''
            intext = ''
    
            while True:
                intext = input("Q to exit | Enter IP\n\t==> ")
                quitStatement = "q"
                editStatement = "e"
                headLookupKey = ''
                if intext == headLookupKey and ipAddress != '':
                    print("Manual Look Up: " + ipAddress)
                    self.lookupHead(ipAddress)
                    time.sleep(1.75)
                elif intext == editStatement and ipAddress != '':
                    print(f"Editing result for IP : {ipAddress}\n Use this format: IpDetails => Determination")
                    inString = input(f"\t{ipAddress} => ")
                    self.editIp(refToDB, ipAddress, inString)
                elif intext == quitStatement:
                    print("exiting...")
                    exit()
                else:
                    
                    # This should be the number of API keys you've got access to
                    
                    if num >= len(self._virusTotalAPIKey)-1:
                        num = 0
                    else:
                        num = num + 1
                    ipAddress = intext
                    if (ipAddress != ''):
                        self.processIp(refToDB, ipAddress, num, False)
                    else:
                        print("IpAddress is currently blank.")
        except:
            print("Writing to "+dbFile)
            refToDB.writeToFile(dbFile)
 
if __name__ == '__main__':
    temp = IpLookup()
    temp.run()
