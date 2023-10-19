# Nathan Graham
# Python 3.11.5

import re
import ipLookup

# Opens local file named temp.txt, then loads it into a str map obj (you can copy pasta from whatever and paste it, local string vars don't really work)

def importTxtFile(fileLocation):
      with open(fileLocation, 'r') as file:
            importedTxt = file.read().splitlines()
      file.close()
      return importedTxt

# Prints out template data populated with data from imported txt obj to res.txt

def printTicketTemplate(importedTxt):
      Alarm_Title = 'INSERT'
      Alarm_ID = 'INSERT'
      Date = 'INSERT'
      User_origin = 'DELETE_ME'
      User_impacted = 'DELETE_ME'
      Hosts_origin = 'DELETE_ME'
      Hosts_impacted = 'DELETE_ME'
      Port_origin = 'DELETE_ME'
      Port_impacted = 'DELETE_ME'
      Host_KBytes_Total = 'DELETE_ME'
      Log_Count = 'DELETE_ME'
      Common_Event = 'DELETE_ME'
      Direction = 'DELETE_ME'
      Group = 'DELETE_ME'
      Log_Source = 'DELETE_ME'
      MPE_Rule_Name = 'DELETE_ME'
      Subject = 'DELETE_ME'
      Vendor_Message_ID = 'DELETE_ME'
      Hash = 'DELETE_ME'
      URL_Obj = 'DELETE_ME'
      User_Agent = 'DELETE_ME'
      Domain_origin = 'DELETE_ME'
      Domain_impacted = 'DELETE_ME'
      
      for line in importedTxt:
            if (line.startswith("User")):
                  temp = re.split(r'\s+|\t',line)
                  User_origin = temp[1].strip()
                  User_impacted = temp[2].strip()
            elif (line.startswith("Host") and not line.startswith("Host (I")):
                  temp = line.split('\t')
                  Hosts_origin = temp[1].strip()
                  Hosts_impacted = temp[2].strip()
            elif (line.startswith("TCP/UDP Port")):
                  temp = line.split("\t", )
                  Port_origin = temp[1].strip()
                  Port_impacted = temp[2].strip()
            elif (line.startswith("Host (Impacted) KBytes Total")):
                  temp = line.split("Host (Impacted) KBytes Total", )
                  Host_KBytes_Total = temp[1].strip()
            elif (line.startswith("Log Count")):
                  temp = line.split("Log Count", )
                  Log_Count = temp[1].strip()
            elif (line.startswith("Common Event")):
                  temp = line.split("Common Event", )
                  Common_Event = temp[1].strip()
            elif (line.startswith("Direction")):
                  temp = line.split("Direction", )
                  Direction = temp[1].strip()
            elif (line.startswith("Group")):
                  temp = line.split("Group", )
                  Group = temp[1].strip()
            elif (line.startswith("Log Source") and not line.startswith("Log Source ")):
                  temp = line.split("Log Source", )
                  Log_Source = temp[1].strip()
            elif (line.startswith("MPE Rule Name")):
                  temp = line.split("MPE Rule Name", )
                  MPE_Rule_Name = temp[1].strip()
            elif (line.startswith("Subject")):
                  temp = line.split("Subject", )
                  Subject = temp[1].strip()
            elif (line.startswith("Vendor Message ID")):
                  temp = line.split("Vendor Message ID")
                  Vendor_Message_ID = temp[1].strip()
            elif (line.startswith("Hash")):
                  temp = line.split("Hash")
                  Hash = temp[1].strip()
            elif (line.startswith("URL")):
                  temp = line.split("URL")
                  URL_Obj = temp[1].strip()
            elif (line.startswith("Domain (Impacted)")):
                  temp = line.split("Domain (Impacted)",line)
                  Domain_impacted = temp[1].strip()
            elif (line.startswith("Domain (Origin)")):
                  temp = line.split("Domain (Origin)",line)
                  Domain_origin = temp[1].strip()
            line = None
      
      output_template = [
        "[{Log_Count}] log(s) @ {Alarm_Title}",
        "Alarm ID#: {Alarm_ID}",
        "Date: {Date}",
        "Host(s) origin: {Hosts_origin}",
        "Host(s) impacted: {Hosts_impacted}",
        "Common Event: {Common_Event}",
        "User origin: {User_origin}",
        "User impacted: {User_impacted}",
        "MPE Rule Name: {MPE_Rule_Name}",
        "Port origin: {Port_origin}",
        "Port impacted: {Port_impacted}",
        "Subject: {Subject}",
        "Group: {Group}",
        "Hash: {Hash}",
        "URL: {URL_Obj}",
        "Vendor ID: {Vendor_Message_ID}",
        "Domain (origin): {Domain_origin}",
        "Domain (impacted): {Domain_impacted}",
        "Host (Impacted) KBytes Total: {Host_KBytes_Total}",
        "User Agent: {User_Agent}",
        "Log Source: {Log_Source}",
    ]

      formatted_output = "\n".join(output_template).format(
            Log_Count=Log_Count, Alarm_Title=Alarm_Title, Alarm_ID=Alarm_ID,
            Date=Date, Hosts_origin=Hosts_origin, Hosts_impacted=Hosts_impacted,
            Common_Event=Common_Event, User_origin=User_origin, User_impacted=User_impacted,
            MPE_Rule_Name=MPE_Rule_Name, Port_origin=Port_origin, Port_impacted=Port_impacted,
            Subject=Subject, Group=Group, Hash=Hash, URL_Obj=URL_Obj,
            Vendor_Message_ID=Vendor_Message_ID, Domain_origin=Domain_origin, Domain_impacted=Domain_impacted,
            Host_KBytes_Total=Host_KBytes_Total, User_Agent=User_Agent, Log_Source=Log_Source)
      
      final_output = formatted_output.split('\n')

      with open("temp.txt", "w") as f:
            for line in final_output:
                  if line.__contains__("DELETE_ME"):
                        line = None
                  else:
                        f.write(line+'\n')
      
      # if (Direction == "Outbound"):
      #       ipLookup.lookup(Hosts_impacted)
      # elif (Direction == "External"):
      #       ipLookup.lookup(Hosts_origin)
      
def main():
    importedTxt = importTxtFile('temp.txt')
    printTicketTemplate(importedTxt)


if __name__ == '__main__':
    main()
