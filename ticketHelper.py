import json


# Opens local file named temp.json, then loads it into a json obj (you can copy pasta from whatever and paste it, local string vars don't really work)
def importJsonFile(fileLocation):
    with open(fileLocation, 'r') as file:
        importedJson = json.load(file)
    return importedJson

# Prints out template data populated with data from json obj


def printTicketTemplate(importedJson):
    print()
    print("@timestamp : " + importedJson['_source']['@timestamp'])
    print("agent.hostname : " + importedJson['_source']['agent']['hostname'])
    print()
    print("direction of traffic : " + importedJson['_source']['tags'][-1])
    print()
    print("suricata.eve.alert.category : " +
          importedJson['_source']['suricata']['eve']['alert']['category'])
    print("suricata.eve.alert.signature : " +
          importedJson['_source']['suricata']['eve']['alert']['signature'])
    print()
    print("source.address : " + importedJson['_source']['source']['address'])
    print("source.port : " + str(importedJson['_source']['source']['port']))
    print("source.packets : " +
          str(importedJson['_source']['source']['packets']))
    print("source.bytes : " + str(importedJson['_source']['source']['bytes']))
    print()
    print("dest.address : " +
          importedJson['_source']['destination']['address'])
    print("dest.port : " + str(importedJson['_source']['destination']['port']))
    print("dest.packets : " +
          str(importedJson['_source']['destination']['packets']))
    print("dest.bytes : " +
          str(importedJson['_source']['destination']['bytes']))
    print()
    print("network.transport : " +
          importedJson['_source']['network']['transport'])
    print()
    print()
    if importedJson['_source']['tags'][-1] == "in2out":
        ipAddress = importedJson['_source']['destination']['address']
    else:
        ipAddress = importedJson['_source']['source']['address']
    print("https://www.abuseipdb.com/check/"+ipAddress)
    print("https://www.virustotal.com/gui/ip-address/"+ipAddress)
    print("https://talosintelligence.com/reputation_center/lookup?search="+ipAddress)
    print("https://otx.alienvault.com/indicator/ip/"+ipAddress)
    print("https://www.shodan.io/host/"+ipAddress)
    print()


def main():
    importedJson = importJsonFile('temp.json')
    printTicketTemplate(importedJson)


if __name__ == '__main__':
    main()
