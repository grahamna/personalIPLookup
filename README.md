# **Disclaimer**
 This project has been worked on in my own free time, and not with company resources. Logrhythm provides public documentation as to the format of their data and the field names. (https://docs.logrhythm.com/?l=en) Specifically (https://docs.logrhythm.com/lrsiem/7.12.0/lists-in-the-client-console)

# **personalIPLookUp**
 This Python script allows users to quickly lookup an IP address across multiple websites. It utilizes the webbrowser and time modules to open new tabs in a web browser for each of the provided links.

## Setup
 Before running the script, ensure that you have a compatible web browser installed and the path to the browser executable is correctly specified in the browser variable at the top of the script. Additionally, ensure that the links used for IP lookup are accurate and up to date.

## Usage
 To use the IP Lookup Tool, simply run the script and enter an IP address when prompted. The tool will automatically open new tabs in the web browser for each of the provided links. To exit the tool, enter "q" when prompted for an IP address.  
 This program now allows for querying the API available at VirusTotal, AlienVault, AbuseIPDB, and Shodan.io. You can press ENTER again (input with no IP) to manually bring up the previously searched IP into the browser.

## Dependencies
  time,
  webbrowser,
  os,
  ipwhois,
  requests,
  json,
  threading,
  pyperclip,
  csv,
  datetime
 
## Compatibility
 This script was developed and tested on Windows 11 using Python 3.11.5. It may require modifications to be compatible with other operating systems or Python versions.

 ------------------------------------------------------------------

 # **personalTicketHelper**
 This Python script printTicketTemplate.py is used to extract and print data from a JSON / txt file temp.json. The JSON file is expected to contain network traffic logs in a specific format. The extracted data is then printed in a specific template format. (Feel free to modify to your personal use case.)
  
 This now also uses a custom class to facilitate formatting the edge cases of ticket generation.

## Usage
 Ensure that temp.json (file is now called zZz) is present in the directory one level outside the script.
 Run the script using the command python printTicketTemplate.py
 The script will extract the required data from temp.json (a) and print it in the specified format.

 The new version of the script is tailored to a unique input. (Basically I wrote my own parser to my own requirements.) Feel free to modify to your personal use case.

 The program now uses user's clipboard as a temp memory / file location, bridging the two functions of the program.

## Functionality
 This script includes two functions:

 importTxtFile(fileLocation): This function opens a local file named zZz and loads it into a parsed object. (an example is provided, feel free to modify it to match the output required by your dashboard)

 printTicketTemplate(importedJson): This function prints out data from the JSON object in a specific format. The printed data includes timestamp, agent hostname, direction of traffic, alert category, alert signature, source IP address and port, number of source packets and bytes, destination IP address and port, number of destination packets and bytes, and transport protocol used. (It also prints links for IP address lookups on various websites, such as abuseipdb.com, virustotal.com, talosintelligence.com, otx.alienvault.com, and shodan.io.) 

 The previous was true for an earlier version of the script. Tickets at my current workplace don't want such a thing now. Program now uses .txt files and a rather bare-bones custom object class instead of JSON.

 The program now is able to take input/output from the clipboard, and will listen for a hotkey to be pressed before calling methods.

 ## Dependencies
  re,
  os,
  keyboard,
  pyperclip,
  random

## Example
 An example use case for this script would be in a security operations center (SOC), where analysts need to quickly extract and analyze network traffic logs to identify potential security incidents. The script would allow them to quickly extract the required data and view relevant IP address reputation information on various websites.

# Contributors
 Nathan Graham
