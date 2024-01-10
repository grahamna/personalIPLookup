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

def printTicketTemplate(outputTemplate, inputLocation, outputLocation):

      formatted_output = "\n".join(outputTemplate)

      res_output = []
      
      # Unused fields are discarded
      
      with open(outputLocation, "w") as f:
            for line in formatted_output.split('\n'):
                  if "DELETE_ME" not in line:
                        f.write(line + '\n')
                        res_output.append(line)
                        
      # Optional - Send formatted_output directly to user's clipboard
      final_output = "\n".join(res_output)
      pyperclip.copy(final_output)
      
      # Optional - Deleting the input file and remaking a blank fresh one
      with open(inputLocation, "w") as file:
            file.close()

def key_event(e):
      dirname = os.path.dirname(__file__)
      fInput = os.path.join(dirname, '../zZz')
      fOutput = os.path.join(dirname, '../zOut.txt')

      # Check if the printTicketCombo sequence has been pressed (ex: ctrl, alt, f10)
      if e.event_type == keyboard.KEY_DOWN and e.name == 'f10' and keyboard.is_pressed('alt') and keyboard.is_pressed('ctrl'):
            print("printTicketCombo")
            importedTxt = importTxtFile(fInput)
            formattedOutput = parseInputs(importedTxt, fInput)
            printTicketTemplate(formattedOutput, fInput, fOutput)
            print("Done")
      
      # Check if the captureClipBoardCombo sequence has been pressed (ex: ctrl, alt f9)
      elif e.event_type == keyboard.KEY_DOWN and e.name == 'f9' and keyboard.is_pressed('alt') and keyboard.is_pressed('ctrl'):
            print("captureClipBoardCombo")
            clipboard_content = pyperclip.paste()
            with open(fInput, 'a') as file:
                  file.write(clipboard_content)
            print("Done")

def main():

      keyboard.hook(key_event)
      print("ticketHelper is listening..")
      
      try:
            while(True):
                  keyboard.wait()
      except KeyboardInterrupt:
            print("ticketHelper exited gracefully")

if __name__ == '__main__':
      main()