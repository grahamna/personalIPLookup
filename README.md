# **personalIPLookUp**

 This Python script allows users to quickly lookup an IP address across multiple websites. It utilizes the web browser and time modules to open new tabs in a web browser for each of the provided links.

## Setup

 Before running the program, ensure that you have a compatible web browser installed and the path to the browser executable is correctly specified in the browser variable at the top of the program. Additionally, ensure that the links used for IP lookup are accurate and up to date. Finally, populate the api key fields for all applicable IP Database sites.

## Usage

 To use the IP Lookup Tool, simply run the program and enter an IP address when prompted. The tool will automatically open new tabs in the web browser for each of the provided links. To exit the tool, enter "q" when prompted for an IP address.  

 This program now allows for querying the API available at VirusTotal, AlienVault, AbuseIPDB, and Shodan.io. You can press 'ENTER' again (input with no IP) to manually bring up the previously searched IP into the browser.

 If you wish to edit an API result, you can enter 'e'

 This program produces entries in a csv file in the following format:  

  ipRange,ipString,output,timestamp

 > ipSearchString,"IP's Company [Usage] \<Ip Range: lower - higher \> (Location of IP)",First Impressions, timestamp  
  
 > 8-8.8-8.8-8.0-255,"Google LLC [Data Center/Web Hosting/Transit] <Ip Range: 8.8.8.0 - 8.8.8.255> (US, CA - Mountain View)",No malicious activity suspected / reported,05/06/2024 21:00:02.200904

  The data has a "lifetime" of 72hrs. After those 72hrs, the db entry will be overwritten with the results of a new search.

## Dependencies

  time,  
  webbrowser,  
  os,  
  requests,  
  datetime,  
  threading,  
  ipwhois  

## Compatibility

 This program was developed and tested on Windows 11 using Python 3.11.5. It may require modifications to be compatible with other operating systems or Python versions.

## Contributors

 Nathan Graham
