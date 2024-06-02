from datetime import datetime
import csv

class IPAddressDatabaseObj:
    def __init__(self, file):
        self.ipResultsDb = {}
        self.loadFromDatabase(file)
 
    def getIpResults(self, ipAddress):
        ipOct = ipAddress.split('.')

        if len(ipOct) != 4:
            print('misconfigured ip detected')
            return False

        for ipRangeKey in self.ipResultsDb.keys():
            lOct1, uOct1  = ipRangeKey.split('.')[0].split('-')
            if (int(lOct1) <= int(ipOct[0]) and int(ipOct[0]) <= int(uOct1)) == False :
                continue
            lOct2, uOct2  = ipRangeKey.split('.')[1].split('-')
            if (int(lOct2) <= int(ipOct[1]) and int(ipOct[1]) <= int(uOct2)) == False :
                continue
            lOct3, uOct3  = ipRangeKey.split('.')[2].split('-')
            if (int(lOct3) <= int(ipOct[2]) and int(ipOct[2]) <= int(uOct3)) == False :
                continue
            lOct4, uOct4  = ipRangeKey.split('.')[3].split('-')
            if (int(lOct4) <= int(ipOct[3]) and int(ipOct[3]) <= int(uOct4)) == False :
                continue
            return ipRangeKey
 
        return False
 
    def saveIpResults(self, ipRangeDto, outString, output):
        timestamp = datetime.now()
        self.ipResultsDb[ipRangeDto] = {'ipString': outString, 'output': output, 'timestamp': timestamp}
 
    def updateIpResults(self, ipRangeDto, outString, output):
        if ipRangeDto in self.ipResultsDb:
            timestamp = datetime.now()
            self.ipResultsDb[ipRangeDto] = {'ipString': outString, 'output': output, 'timestamp': timestamp}
 
    def loadFromDatabase(self, file):
        try:
            with open(file, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    ipRangeDto = row['ipRange']
                    outString = row['ipString']
                    output = row['output']
                    timestamp = datetime.strptime(row['timestamp'], '%m/%d/%Y %H:%M:%S.%f')
                    self.ipResultsDb[ipRangeDto] = {'ipString': outString, 'output': output, 'timestamp': timestamp}
        except FileNotFoundError:
            print("DB file not found, blank ipResultObj ref")
            pass
 
    def writeToFile(self, file):
        with open(file, 'w', newline='') as csvfile:
            fieldnames = ['ipRange', 'ipString', 'output', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
 
            # Write header if the file is empty
            if csvfile.tell() == 0:
                writer.writeheader()
 
            # Write all records to the CSV file
            for ipRange, data in self.ipResultsDb.items():
                writer.writerow({'ipRange': ipRange, 'ipString': data['ipString'], 'output': data['output'],'timestamp': data['timestamp'].strftime('%m/%d/%Y %H:%M:%S.%f')})