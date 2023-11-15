# Nathan Graham - Personal Use
# This application was developed in my own free time without company resources
# Python 3.11.5

import re
import os
import keyboard
import ticketObjClass
import pyperclip

def importTxtFile(fileLocation):
      with open(fileLocation, 'r') as file:
            importedTxt = file.read().splitlines()
            file.close()
      
      return importedTxt

# Custom written parser for personal use case.

def parseInputs(importedTxt):
      
      # Fields based off of (https://docs.logrhythm.com/lrsiem/7.12.0/lists-in-the-client-console)
      
      a = '-^--^--^--^--^--^--^--^--^--^-'
      b = '-^--^--^--^--^-'
      c = '-^--^--^--^--^--^-'
      d = ticketObjClass.TicketObj()
      e = ticketObjClass.TicketObj()
      f = ticketObjClass.TicketObj()
      g = ticketObjClass.TicketObj()
      h = ticketObjClass.TicketObj()
      i = ticketObjClass.TicketObj()
      j = ticketObjClass.TicketObj()
      k = 0
      l = ticketObjClass.TicketObj()
      m = ticketObjClass.TicketObj()
      n = ticketObjClass.TicketObj()
      o = ticketObjClass.TicketObj()
      p = ticketObjClass.TicketObj()
      q = ticketObjClass.TicketObj()
      r = ticketObjClass.TicketObj()
      s = ticketObjClass.TicketObj()
      t = ticketObjClass.TicketObj()
      u = ticketObjClass.TicketObj()
      v = ticketObjClass.TicketObj()

      for line in importedTxt:
            if (line.startswith("User") and not line.startswith("User I")):
                  if (line.startswith("User Agent")):
                        temp = line.split("User Agent")
                        temp[1] = temp[1].strip()
                        t[temp[1]] =+ 1
                  else:
                        temp = re.split(r'\t',line)
                        if (temp[1].strip()!=''):
                              temp[1] = temp[1].strip()
                              d[temp[1]] =+ 1
                        if (temp[2].strip()!=''):
                              temp[2] = temp[2].strip()
                              e[temp[2]] =+ 1
            elif (line.startswith("Host") and not line.startswith("Host (I") and not line.startswith("Hostname")):
                  temp = line.split('\t')
                  if (temp[1].strip()!=''):
                        temp[1] = temp[1].strip()
                        f[temp[1]] =+ 1
                  if (temp[2].strip()!=''):
                        temp[2] = temp[2].strip()
                        g[temp[2]] =+ 1
            elif (line.startswith("TCP/UDP Port")):
                  temp = line.split("\t", )
                  if (temp[1].strip()!=''):
                        temp[1] = temp[1].strip()
                        h[temp[1]] =+ 1
                  if (temp[2].strip()!=''):
                        temp[2] = temp[2].strip()
                        i[temp[2]] =+ 1
            elif (line.startswith("Host (Impacted) KBytes Total")):
                  temp = line.split("Host (Impacted) KBytes Total", )
                  temp[1] = temp[1].strip()
                  j[temp[1]] =+ 1
            elif (line.startswith("Log Count")):
                  temp = line.split("Log Count", )
                  k = k+1
            elif (line.startswith("Common Event")):
                  temp = line.split("Common Event", )
                  temp[1] = temp[1].strip()
                  l[temp[1]] =+ 1
            elif (line.startswith("Group")):
                  temp = line.split("Group", )
                  temp[1] = temp[1].strip()
                  m[temp[1]] =+ 1
            elif (line.startswith("Log Source") and not line.startswith("Log Source ")):
                  temp = line.split("Log Source", )
                  temp[1] = temp[1].strip()
                  n[temp[1]] =+ 1
            elif (line.startswith("MPE Rule Name")):
                  temp = line.split("MPE Rule Name", )
                  temp[1] = temp[1].strip()
                  o[temp[1]] =+ 1
            elif (line.startswith("Subject")):
                  temp = line.split("Subject", )
                  temp[1] = temp[1].strip()
                  p[temp[1]] =+ 1
            elif (line.startswith("Vendor Message ID")):
                  temp = line.split("Vendor Message ID")
                  temp[1] = temp[1].strip()
                  q[temp[1]] =+ 1
            elif (line.startswith("Hash")):
                  temp = line.split("Hash")
                  temp[1] = temp[1].strip()
                  r[temp[1]] =+ 1
            elif (line.startswith("URL")):
                  temp = line.split("URL")
                  temp[1] = temp[1].strip()
                  s[temp[1]] =+ 1
            elif (line.startswith("Domain (Impacted)")):
                  temp = line.split("Domain (Impacted)")
                  temp[1] = temp[1].strip()
                  v[temp[1]] =+ 1
            elif (line.startswith("Domain (Origin)")):
                  temp = line.split("Domain (Origin)")
                  temp[1] = temp[1].strip()
                  u[temp[1]] =+ 1

            # Applying parsed data to supplied ticket template from 

            outputTemplate = [] # Is secret, I guess?
            
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
            formattedOutput = parseInputs(importedTxt)
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
      print("ticketHelper is listening...")
      
      try:
            while(True):
                  keyboard.wait()
      except KeyboardInterrupt:
            print("ticketHelper exited gracefully")

if __name__ == '__main__':
      main()