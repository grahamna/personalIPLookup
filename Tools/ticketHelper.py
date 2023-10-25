# Nathan Graham
# Python 3.11.5

import re
import ticketObjClass
import os

def importTxtFile(fileLocation):
      with open(fileLocation, 'r') as file:
            importedTxt = file.read().splitlines()
            file.close()
      
      return importedTxt

# Custom written parser for personal use case.

def parseInputs(importedTxt):
      alarmTitle = '-^--^--^--^--^--^--^--^--^--^-'
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
                        temp = re.split(r'\t',line)
                        if (temp[1].strip()!=''):
                              temp[1] = temp[1].strip()
                              User_origin[temp[1]] =+ 1
                        if (temp[2].strip()!=''):
                              temp[2] = temp[2].strip()
                              User_impacted[temp[2]] =+ 1
            elif (line.startswith("Host") and not line.startswith("Host (I") and not line.startswith("Hostname")):
                  temp = line.split('\t')
                  if (temp[1].strip()!=''):
                        temp[1] = temp[1].strip()
                        Hosts_origin[temp[1]] =+ 1
                  if (temp[2].strip()!=''):
                        temp[2] = temp[2].strip()
                        Hosts_impacted[temp[2]] =+ 1
            elif (line.startswith("TCP/UDP Port")):
                  temp = line.split("\t", )
                  if (temp[1].strip()!=''):
                        temp[1] = temp[1].strip()
                        Port_origin[temp[1]] =+ 1
                  if (temp[2].strip()!=''):
                        temp[2] = temp[2].strip()
                        Port_impacted[temp[2]] =+ 1
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

            # Applying parsed data to ticket template

            outputTemplate = [
            f"[{Log_Count}] log(s) @ {alarmTitle}",
            f"Alarm ID# : {Alarm_ID}",
            f"Date : {Date}",
            f"Host(s) origin : {Hosts_origin}",
            f"Host(s) impacted : {Hosts_impacted}",
            f"Common Event : {Common_Event}",
            f"User origin : {User_origin}",
            f"User impacted : {User_impacted}",
            f"MPE Rule Name : {MPE_Rule_Name}",
            f"Port origin : {Port_origin}",
            f"Port impacted : {Port_impacted}",
            f"Subject : {Subject}",
            f"Group : {Group}",
            f"Hash : {Hash}",
            f"URL : {URL_Obj}",
            f"Vendor ID : {Vendor_Message_ID}",
            f"Domain (origin) : {Domain_origin}",
            f"Domain (impacted) : {Domain_impacted}",
            f"Host (Impacted) KBytes Total : {Host_KBytes_Total}",
            f"User Agent : {User_Agent}",
            f"Log Source : {Log_Source}",
      ]
            
      return outputTemplate

def printTicketTemplate(outputTemplate, inputLocation, outputLocation):

      formatted_output = "\n".join(outputTemplate)

      # Unused fields are discarded
      
      with open(outputLocation, "a") as f:
            for line in formatted_output.split('\n'):
                  if "DELETE_ME" not in line:
                        f.write(line + '\n')
      
      # Optional - Deleting the input file and remaking a blank fresh one
      with open(inputLocation, "w") as file:
            file.close()

def main():
      dirname = os.path.dirname(__file__)
      input = os.path.join(dirname, '../a')
      output = os.path.join(dirname, '../out.txt')
      importedTxt = importTxtFile(input)
      formattedOutput = parseInputs(importedTxt)
      printTicketTemplate(formattedOutput, input, output)

if __name__ == '__main__':
      main()