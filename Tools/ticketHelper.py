# Nathan Graham - Personal Use
# This application was developed in my own free time without company resources
# Python 3.11.5

import re
import os
import keyboard
import pyperclip

import ticketObjClass

def importTxtFile(fileLocation):
      with open(fileLocation, 'r') as file:
            importedTxt = file.read().splitlines()
            file.close()
      
      return importedTxt

# Custom written parser for personal use case.

def parseInputs(importedTxt, fInput):
      
      # Fields based off of (https://docs.logrhythm.com/lrsiem/7.12.0/lists-in-the-client-console)
      
      Log_Count = 0
      Alarm_ID = '-^--^--^--^--^-'
      Date = '-^--^--^--^--^--^-'
      alarmTitle = '-^--^--^--^--^--^--^--^--^--^-'
      IP_Address_From = ticketObjClass.IpTicketObj()
      IP_Address_To = ticketObjClass.IpTicketObj()
      Log_Source = ticketObjClass.TicketObj()
      Common_Event = ticketObjClass.TicketObj()
      MPE_Rule_Name = ticketObjClass.TicketObj()
      Vendor_Message_ID = ticketObjClass.TicketObj()
      User_impacted = ticketObjClass.TicketObj()
      Hosts_impacted = ticketObjClass.TicketObj()
      Port_impacted = ticketObjClass.TicketObj()
      User_Agent = ticketObjClass.TicketObj()
      Domain_impacted = ticketObjClass.TicketObj()
      Host_KBytes_Total = ticketObjClass.TicketObj()
      User_origin = ticketObjClass.TicketObj()
      Hosts_origin = ticketObjClass.TicketObj()
      Port_origin = ticketObjClass.TicketObj()
      Domain_origin = ticketObjClass.TicketObj()
      Subject = ticketObjClass.TicketObj()
      Group = ticketObjClass.TicketObj()
      Hash_File = ticketObjClass.TicketObj()
      URL_Obj = ticketObjClass.TicketObj()

      try:
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
                        Hash_File[temp[1]] =+ 1
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
                  elif (line.startswith("IP Address")):
                        temp = re.split(r'\t',line)
                        if (temp[1].strip()!=''):
                              temp[1] = temp[1].strip()
                              IP_Address_From[temp[1]] =+ 1
                        if (temp[2].strip()!=''):
                              temp[2] = temp[2].strip()
                              IP_Address_To[temp[2]] =+ 1
                  
      except:
            with open(fInput, "w") as file:
                  file.close()
            print("Parse failed, fileInput Cleared")
            
            # Applying parsed data to supplied ticket template from 

      outputTemplate = [
            f"Alarm# : {Alarm_ID}",
            f"Date : {Date}",
            f"{alarmTitle}",
            f"{Log_Count} logs From Log Source : {Log_Source}",
            f"Event Names : {Common_Event}",
            f"MPE Rules : {MPE_Rule_Name}",
            f"Message IDs : {Vendor_Message_ID}",
            f"\n"
            f"From : {Hosts_origin}",
            f"\tUser : {User_origin}",
            f"\tUsing IP : {IP_Address_From}",
            f"\tUsing Port : {Port_origin}",
            f"\tWith Domain : {Domain_origin}",
            f"\tUsing User Agent : {User_Agent}",
            f"Total KByte Transferred: {Host_KBytes_Total}",
            f"\n"
            f"To : {Hosts_impacted}",
            f"\tUser : {User_impacted}",
            f"\tUsing IP : {IP_Address_To}",
            f"\tUsing Port : {Port_impacted}",
            f"\tWith Domain : {Domain_impacted}",
            f"\n"
            f"Affecting Subject : {Subject}",
            f"Pertaining to Group ID: {Group}",
            f"Hash of File : {Hash_File}",
            f"URL Reference : {URL_Obj}",
            f'\n\n========================================================\n\n'
      ]
            
      return outputTemplate

def importTxtFile(fileLocation):
      with open(fileLocation, 'r') as file:
            importedTxt = file.read().splitlines()
            file.close()
      return importedTxt
 
def plumeParser(importedTxt, fInput):
      dictionary = {
            "tenantname" : "DELETE_ME",
            "eventid" : "DELETE_ME",
            "eventtime" : "DELETE_ME",
            "policyname" : "DELETE_ME",
            "category" : "DELETE_ME",
            "riskthreatname" : "DELETE_ME",
            "message" : "DELETE_ME",
            "accountname" : "DELETE_ME",
            "preferredname" : "DELETE_ME",
            "sourceusername" : "DELETE_ME",
            "sourceuserprivileges" : "DELETE_ME",
            "destinationusername" : "DELETE_ME",
            "destinationuserprivileges" : "DELETE_ME",
            "devicehostname" : "DELETE_ME",
            "ipaddress" : "DELETE_ME",
            "sourcehostname" : "DELETE_ME",
            "sourceaddress" : "DELETE_ME",
            "sourcemacaddress" : "DELETE_ME",
            "destinationhostname" : "DELETE_ME",
            "destinationaddress" : "DELETE_ME",
            "sourceport" : "DELETE_ME",
            "destinationport" : "DELETE_ME",
            "sourcentdomain" : "DELETE_ME",
            "destinationntdomain" : "DELETE_ME",
            "emailsender" : "DELETE_ME",
            "emailsenderdomain" : "DELETE_ME",
            "emailrecipient" : "DELETE_ME",
            "emailrecipientdomain" : "DELETE_ME",
            "emailsubject" : "DELETE_ME",
            "requestclientapplication" : "DELETE_ME",
            "deviceeventcategory" : "DELETE_ME",
            "deviceprocessname" : "DELETE_ME",
            "destinationprocessname" : "DELETE_ME",
            "resourcecustomfield8" : "DELETE_ME",
            "sourceprocessname" : "DELETE_ME",
            "resourcecustomfield7" : "DELETE_ME",
            "resourcecustomfield1" : "DELETE_ME",
            "resourcecustomfield2" : "DELETE_ME",
            "customstring5" : "DELETE_ME",
            "resourcecustomfield3" : "DELETE_ME",
            "devicecustomstring6" : "DELETE_ME",
            "devicecustomstring1" : "DELETE_ME",
            "applicationprotocol" : "DELETE_ME",
            "filename" : "DELETE_ME",
            "filetype" : "DELETE_ME",
            "filepath" : "DELETE_ME",
            "filehash" : "DELETE_ME",
            "filesize" : "DELETE_ME",
            "deviceaction" : "DELETE_ME",
            "eventoutcome" : "DELETE_ME",
            "deviceseverity" : "DELETE_ME",
            "requesturl" : "DELETE_ME",
            "resourcename" : "DELETE_ME",
            "devicecustomstring4" : "DELETE_ME",
            "transactionstring1" : "DELETE_ME",
            "resourcecustomfield2" : "DELETE_ME",
            "baseeventid" : "DELETE_ME",
            "customnumber1" : "DELETE_ME",
            "bytesin" : "DELETE_ME",
            "bytesout" : "DELETE_ME"
            }
 
      try:
            for key in dictionary.keys():
                  for line in importedTxt:
                        if line.startswith(key):
                              temp = line.split(' = ')
                              dictionary[key] = (temp[1].strip())
                              break
      except:
            if (fInput != None):
                  with open(fInput, "w") as file:
                        file.close()
                  print("Parse failed, fileInput Cleared")
 
      plumeTemplate = [
            f"Tenant Name : {dictionary['tenantname']}",
            f"EventID : {dictionary['eventid']}",
            f"Date : {dictionary['eventtime']}",
            f"Policy : {dictionary['policyname']}",
            f"Category : {dictionary['category']}",
            f"Risk/Threat : {dictionary['riskthreatname']}",
            f"Message : {dictionary['message']}",
            f"AccountName : {dictionary['accountname']}",
            f"PreferredName :{dictionary['preferredname']}",
            f"SourceUser : {dictionary['sourceusername']}",
            f"SourceUserPriv : {dictionary['sourceuserprivileges']}",
            f"DestinationUser : {dictionary['destinationusername']}",
            f"DestinationUserPriv : {dictionary['destinationuserprivileges']}",
            f"DeviceHostName : {dictionary['devicehostname']}",
            f"IPAddress : {dictionary['ipaddress']}",
            f"SourceHost : {dictionary['sourcehostname']}",
            f"SourceAddress : {dictionary['sourceaddress']}",
            f"SourceMacAddress : {dictionary['sourcemacaddress']}",
            f"DestinationHostname : {dictionary['destinationhostname']}",
            f"DestinationAddress : {dictionary['destinationaddress']}",
            f"SourcePort : {dictionary['sourceport']}",
            f"DestinationPort : {dictionary['destinationport']}",
            f"SourceDomain : {dictionary['sourcentdomain']}",
            f"DestinationDomain : {dictionary['destinationntdomain']}",
            f"EmailSender : {dictionary['emailsender']}",
            f"EmailSenderDomain : {dictionary['emailsenderdomain']}",
            f"EmailRecipient : {dictionary['emailrecipient']}",
            f"EmailRecipientDomain : {dictionary['emailrecipientdomain']}",
            f"EmailSubject : {dictionary['emailsubject']}",
            f"RequestClientApplication : {dictionary['requestclientapplication']}",
            f"UserAgent : {dictionary['requestclientapplication']}",
            f"DeviceEventCategory : {dictionary['deviceeventcategory']}",
            f"DeviceProcessName : {dictionary['deviceprocessname']}",
            f"ProcessName : {dictionary['destinationprocessname']}",
            f"ChildProcessPath : {dictionary['resourcecustomfield8']}",
            f"ParentProcessName : {dictionary['sourceprocessname']}",
            f"ParentProcessFullPath : {dictionary['resourcecustomfield7']}",
            f"ChildProcessCommandLine : {dictionary['resourcecustomfield1']}",
            f"ParentProcessCommandLine : {dictionary['resourcecustomfield2']}",
            f"CommandData : {dictionary['customstring5']}",
            f"CommandLine : {dictionary['resourcecustomfield3']}",
            f"DBName : {dictionary['devicecustomstring6']}",
            f"SQLString : {dictionary['devicecustomstring1']}",
            f"ApplicationProtocol : {dictionary['applicationprotocol']}",
            f"FileName : {dictionary['filename']}",
            f"FileType : {dictionary['filetype']}",
            f"FilePath : {dictionary['filepath']}",
            f"FileHash : {dictionary['filehash']}",
            f"FileSize : {dictionary['filesize']}",
            f"DeviceAction : {dictionary['deviceaction']}",
            f"EventOutcome : {dictionary['eventoutcome']}",
            f"DeviceSeverity : {dictionary['deviceseverity']}",
            f"RequestUrl : {dictionary['requesturl']}",
            f"ResourceName : {dictionary['resourcename']}",
            f"RecordType : {dictionary['devicecustomstring4']}",
            f"TransactionString : {dictionary['transactionstring1']}",
            f"TransactionType : {dictionary['resourcecustomfield2']}",
            f"WinEventId : {dictionary['baseeventid']}",
            f"LogonType : {dictionary['customnumber1']}",
            f"BytesIn : {dictionary['bytesin']}",
            f"BytesOut : {dictionary['bytesout']}"
            f'\n\n========================================================\n\n'
      ]
      return plumeTemplate
 
def parseInputs(importedTxt, fInput):
      # Fields based off of (https://docs.logrhythm.com/lrsiem/7.12.0/lists-in-the-client-console)
      Log_Count = 0
      Alarm_ID = '-^--^--^--^--^-'
      Date = '-^--^--^--^--^--^-'
      alarmTitle = '-^--^--^--^--^--^--^--^--^--^-'
      Log_Source = TicketObj()
      Common_Event = TicketObj()
      MPE_Rule_Name = TicketObj()
      Vendor_Message_ID = TicketObj()
      User_impacted = TicketObj()
      Hosts_impacted = TicketObj()
      Port_impacted = TicketObj()
      User_Agent = TicketObj()
      Domain_impacted = TicketObj()
      Host_KBytes_Total = TicketObj()
      User_origin = TicketObj()
      Hosts_origin = TicketObj()
      Port_origin = TicketObj()
      Domain_origin = TicketObj()
      Subject = TicketObj()
      Group = TicketObj()
      Hash_File = TicketObj()
      URL_Obj = TicketObj()
 
      try:
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
                        Hash_File[temp[1]] =+ 1
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
      except:
            with open(fInput, "w") as file:
                  file.close()
            print("Parse failed, fileInput Cleared")

            # Applying parsed data to supplied ticket template from
 
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
            f"Hash : {Hash_File}",
            f"URL : {URL_Obj}",
            f"Vendor ID : {Vendor_Message_ID}",
            f"Domain (origin) : {Domain_origin}",
            f"Domain (impacted) : {Domain_impacted}",
            f"Host (Impacted) KBytes Total : {Host_KBytes_Total}",
            f"User Agent : {User_Agent}",
            f"Log Source : {Log_Source}",
            f'\n\n========================================================\n\n'
      ]
      return outputTemplate
 
def printTicketTemplate(outputTemplate, inputLocation, outputLocation):
 
      formattedOutput = "\n".join(outputTemplate)
 
      res_output = []
      # Unused fields are discarded
      with open(outputLocation, "w") as f:
            for line in formattedOutput.split('\n'):
                  if "DELETE_ME" not in line:
                        f.write(line + '\n')
                        res_output.append(line)
      # Optional - Send formatted_output directly to user's clipboard
      final_output = "\n".join(res_output)
      pyperclip.copy(final_output)
      # Optional - Deleting the input file and remaking a blank fresh one
      with open(inputLocation, "w") as file:
            file.close()
 
def printTicketCombo():
      global strCheck, numCount
      dirname = os.path.dirname(__file__)
      fInput = os.path.join(dirname, '../zZz')
      fOutput = os.path.join(dirname, '../zOut.txt')
      importedTxt = importTxtFile(fInput)
      output = "printTicketCombo failed"
      if (('accountname =') in importedTxt[0]):
            formattedOutput = plumeParser(importedTxt, fInput)
            output ="Plume Detected"
      else:
            formattedOutput = parseInputs(importedTxt, fInput)
            output = "LR Detected"
      printTicketTemplate(formattedOutput, fInput, fOutput)
      print(f"{output}")
      strCheck = ""
      numCount = 0
            
def copyClipboardCombo():
      global strCheck, numCount
      dirname = os.path.dirname(__file__)
      fInput = os.path.join(dirname, '../zZz')
      clipboardContent = pyperclip.paste()
      if (strCheck != clipboardContent):
            with open(fInput, 'a', encoding='utf-8') as file:
                  file.write(clipboardContent)
            strCheck = clipboardContent
            numCount = numCount + 1
            print(f"  {numCount}")
      else : print(" ~REPEAT~")
 
def main():
      global strCheck, numCount
      strCheck = ""
      numCount = 0
      keyboard.add_hotkey("alt + shift + f9", lambda: copyClipboardCombo())
      keyboard.add_hotkey("alt + shift + f10", lambda: printTicketCombo())
      print("ticketHelper is listening..")
      try: 
            while(True):
                  keyboard.wait()
      except KeyboardInterrupt:
            print("ticketHelper exited gracefully")
 
if __name__ == '__main__':
      main()