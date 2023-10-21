# Nathan Graham
# Python 3.11.5

import re
import ticketObjClass
import ipLookup

# Opens local file named temp.txt, then loads it into a str map obj (you can copy pasta from whatever and paste it, local string vars don't really work)

def importTxtFile(fileLocation):
      with open(fileLocation, 'r') as file:
            importedTxt = file.read().splitlines()
      file.close()
      return importedTxt

# Prints out template data populated with data from imported txt obj to res.txt

def printTicketTemplate(importedTxt):
      Alarm_Title = '-^--^--^--^--^--^--^--^--^--^-'
      Alarm_ID = '-^--^--^--^--^-'
      Date = '-^--^--^--^--^--^-'
      User_origin = ticketObjClass.TicketObj()
      User_impacted = ticketObjClass.TicketObj()
      Hosts_origin = ticketObjClass.TicketObj()
      Hosts_impacted = ticketObjClass.TicketObj()
      Port_origin = ticketObjClass.TicketObj()
      Port_impacted = ticketObjClass.TicketObj()
      Host_KBytes_Total = ticketObjClass.TicketObj()
      Log_Count = 0
      Common_Event = ticketObjClass.TicketObj()
      Group = ticketObjClass.TicketObj()
      Log_Source = ticketObjClass.TicketObj()
      MPE_Rule_Name = ticketObjClass.TicketObj()
      Subject = ticketObjClass.TicketObj()
      Vendor_Message_ID = ticketObjClass.TicketObj()
      Hash = ticketObjClass.TicketObj()
      URL_Obj = ticketObjClass.TicketObj()
      User_Agent = ticketObjClass.TicketObj()
      Domain_origin = ticketObjClass.TicketObj()
      Domain_impacted = ticketObjClass.TicketObj()
      
      for line in importedTxt:
            if (line.startswith("User") and not line.startswith("User I")):
                  if (line.startswith("User Agent")):
                        temp = line.split("User Agent")
                        temp[1] = temp[1].strip()
                        User_Agent[temp[1]] =+ 1
                  else:
                        temp = re.split(r'\s+|\t',line)
                        if (temp[1].strip()!=''):
                              temp[1] = temp[1].strip()
                              User_origin[temp[1]] =+ 1
                        if (temp[2].strip()!=''):
                              temp[2] = temp[2].strip()
                              User_Agent[temp[1]] =+ 1
            elif (line.startswith("Host") and not line.startswith("Host (I") and not line.startswith("Hostname")):
                  temp = line.split('\t')
                  if (temp[1].strip()!=''):
                        temp[1] = temp[1].strip()
                        Hosts_origin[temp[1]] =+ 1
                  if (temp[2].strip()!=''):
                        temp[2] = temp[2].strip()
                        Hosts_impacted[temp[1]] =+ 1
            elif (line.startswith("TCP/UDP Port")):
                  temp = line.split("\t", )
                  if (temp[1].strip()!=''):
                        temp[1] = temp[1].strip()
                        Port_origin[temp[1]] =+ 1
                  if (temp[2].strip()!=''):
                        temp[2] = temp[2].strip()
                        Port_impacted[temp[1]] =+ 1
            elif (line.startswith("Host (Impacted) KBytes Total")):
                  temp = line.split("Host (Impacted) KBytes Total", )
                  temp[1] = temp[1].strip()
                  Host_KBytes_Total[temp[1]] =+ 1
            elif (line.startswith("Log Count")):
                  temp = line.split("Log Count", )
                  Log_Count = Log_Count+1
            elif (line.startswith("Common Event")):
                  temp = line.split("Common Event", )
                  temp[1] = temp[1].strip()
                  Common_Event[temp[1]] =+ 1
            elif (line.startswith("Group")):
                  temp = line.split("Group", )
                  temp[1] = temp[1].strip()
                  Group[temp[1]] =+ 1
            elif (line.startswith("Log Source") and not line.startswith("Log Source ")):
                  temp = line.split("Log Source", )
                  temp[1] = temp[1].strip()
                  Log_Source[temp[1]] =+ 1
            elif (line.startswith("MPE Rule Name")):
                  temp = line.split("MPE Rule Name", )
                  temp[1] = temp[1].strip()
                  MPE_Rule_Name[temp[1]] =+ 1
            elif (line.startswith("Subject")):
                  temp = line.split("Subject", )
                  temp[1] = temp[1].strip()
                  Subject[temp[1]] =+ 1
            elif (line.startswith("Vendor Message ID")):
                  temp = line.split("Vendor Message ID")
                  temp[1] = temp[1].strip()
                  Vendor_Message_ID[temp[1]] =+ 1
            elif (line.startswith("Hash")):
                  temp = line.split("Hash")
                  temp[1] = temp[1].strip()
                  Hash[temp[1]] =+ 1
            elif (line.startswith("URL")):
                  temp = line.split("URL")
                  temp[1] = temp[1].strip()
                  URL_Obj[temp[1]] =+ 1
            elif (line.startswith("Domain (Impacted)")):
                  temp = line.split("Domain (Impacted)")
                  temp[1] = temp[1].strip()
                  Domain_impacted[temp[1]] =+ 1
            elif (line.startswith("Domain (Origin)")):
                  temp = line.split("Domain (Origin)")
                  temp[1] = temp[1].strip()
                  Domain_origin[temp[1]] =+ 1
      
      output_template = [
        "[{Log_Count}] log(s) @ {Alarm_Title}",
        "Alarm ID# : {Alarm_ID}",
        "Date : {Date}",
        "Host(s) origin : {Hosts_origin}",
        "Host(s) impacted : {Hosts_impacted}",
        "Common Event : {Common_Event}",
        "User origin : {User_origin}",
        "User impacted : {User_impacted}",
        "MPE Rule Name : {MPE_Rule_Name}",
        "Port origin : {Port_origin}",
        "Port impacted : {Port_impacted}",
        "Subject : {Subject}",
        "Group : {Group}",
        "Hash : {Hash}",
        "URL : {URL_Obj}",
        "Vendor ID : {Vendor_Message_ID}",
        "Domain (origin) : {Domain_origin}",
        "Domain (impacted) : {Domain_impacted}",
        "Host (Impacted) KBytes Total : {Host_KBytes_Total}",
        "User Agent : {User_Agent}",
        "Log Source : {Log_Source}",
    ]

      formatted_output = "\n".join(output_template).format(
            Log_Count=Log_Count,
            Alarm_Title=Alarm_Title,
            Alarm_ID=Alarm_ID,
            Date=Date,
            Hosts_origin=Hosts_origin.toString(),
            Hosts_impacted=Hosts_impacted.toString(),
            Common_Event=Common_Event.toString(), 
            User_origin=User_origin.toString(), 
            User_impacted=User_impacted.toString(),
            MPE_Rule_Name=MPE_Rule_Name.toString(),
            Port_origin=Port_origin.toString(), 
            Port_impacted=Port_impacted.toString(),
            Subject=Subject.toString(),
            Group=Group.toString(),
            Hash=Hash.toString(), 
            URL_Obj=URL_Obj.toString(),
            Vendor_Message_ID=Vendor_Message_ID.toString(), 
            Domain_origin=Domain_origin.toString(), 
            Domain_impacted=Domain_impacted.toString(),
            Host_KBytes_Total=Host_KBytes_Total.toString(),
            User_Agent=User_Agent.toString(), 
            Log_Source=Log_Source.toString()
      )
      
      final_output = re.split(r'\n(?!\t)', formatted_output)

      with open("out.txt", "a") as f:
            for line in final_output:
                  if line.__contains__("DELETE_ME"):
                        line = None
                  else:
                        f.write(line+'\n')
      
      # if (Direction == "Outbound"):
      #       print(Direction)
      #       ipLookup.lookup(Hosts_impacted)
      # elif (Direction == "External"):
      #       print(Direction)
      #       ipLookup.lookup(Hosts_origin)
      
def main():
    importedTxt = importTxtFile('temp.txt')
    printTicketTemplate(importedTxt)


if __name__ == '__main__':
    main()
