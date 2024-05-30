# **personalIPLookUp**
 This Python script allows users to quickly lookup an IP address across multiple websites. It utilizes the web browser and time modules to open new tabs in a web browser for each of the provided links.

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
  threading,
  pyperclip,
  datetime
 
## Compatibility
 This script was developed and tested on Windows 11 using Python 3.11.5. It may require modifications to be compatible with other operating systems or Python versions.


# Contributors
 Nathan Graham
