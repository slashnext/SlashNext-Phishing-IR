# SlashNext Phishing Incident Response Console (Terminal User Interface)
SlashNext Phishing Incident Response Console allows users to manually perform certain data enrichment using SlashNext On-demand Threat Intelligence cloud APIs.
 
**SlashNext On-demand Threat Intelligence** analyzes the provided IoCs (URL, IPv4 or FQDN) with the **SlashNext SEER™** threat detection cloud to get definitive, binary verdicts (malicious or benign) along with IOCs, screen-shots, and more.  

SlashNext threat detection uses browsers in a purpose-built cloud to dynamically inspect page contents and site behavior in real-time. This method enables SlashNext to follow URL re-directs and multi-stage attacks to more thoroughly analyze the final page(s) and made a much more accurate, binary determination with near-zero false positives. It also detects all six major categories of phishing and social engineering sites. These include credential stealing, rogue software / malware sites, scareware, phishing exploits (sites hosting weaponized documents, etc.), and social engineering scams (fake deals, giveaways, etc.).  

Use cases include abuse inbox management where SOC teams can automate URL analysis in phishing emails to save hundreds of hours versus more manual methods. Playbooks that mine and analyze network logs can also leverage SlashNext URL analysis on demand.  

SlashNext not only provides accurate, binary verdicts (rather than threat scores), it provides IOC metadata and screen shots of detected phishing pages. These enables easier classification and reporting. Screen shots can be used as an aid in on-going employee phishing awareness training and testing.  

The SlashNext Phishing Incident Response Console app uses an API key to authenticate with SlashNext cloud. If you don't have a valid API key, contact the SlashNext team: support@slashnext.com

SlashNext On-demand Threat Intelligence Console consists of two parts;
1. **SlashNext Phishing IR Console Back-end** - Implements all the actions. Invokes APIs with required parameters and get response.
2. **SlashNext Phishing IR Console TUI** - Prompts user for input action and displays the API response output from Back-end.

Please note that this README file contains limited info. For more details, please see the documents in the **docs** directory.

### Requirements

SlashNext Phishing Incident Response Console requires python 3.6 with setuptools installed on your system and have access to internet.
If you don't have python3.6 installed please use following commands.

```
sudo apt install python3 
sudo apt install python3-pip
sudo python3 -m pip install setuptools
```
You will also need a copy-paste mechanism to be installed on your system in case to Linux. To do that, you can select one from the options given
below.
```
sudo apt-get install xclip
or
sudo apt-get install xsel
```
### Installation

Please follow the steps given below to install the SlashNext Phishing IR Console on your system.

1. Unzip the package provided by SlashNext.
1. Open a Terminal and go to the 'src' directory.
1. Go to the directory where **setup.py** file is present along with SlashNextPhishingIRConsole directory.
1. Execute following.

```
sudo python3 -m pip install .
```

1. In order to uninstall the SlashNext Phishing IR Console package, run the following command.

```
sudo python3 -m pip uninstall slashnext-phishing-ir-console
```

### Configuration Variables

The below configuration variables are required for this console to operate properly.

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">VARIABLE</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">TYPE</th>

<th>DESCRIPTION</th>

</tr>

<tr>

<td>**SlashNext API Base URL**</td>

<td>optional</td>

<td>string</td>

<td>Optional configuration. Change the default value only if specifically provided by SlashNext</td>

</tr>

<tr>

<td>**SlashNext API Key**</td>

<td>required</td>

<td>password</td>

<td>The system uses this API key to authenticate with SlashNext Cloud. If you don’t have a valid API key, please reach us at support@slashnext.com</td>

</tr>

</tbody>

</table>

### Supported Actions

1. **slashnext-api-quota** - Find information about your API quota, like current usage, quota left etc.  
1. **slashnext-host-reputation** - Search in SlashNext cloud database and retrieve reputation of a host. 
1. **slashnext-host-report** - Search in SlashNext cloud database and retrieve a detailed report for a host and associated URL.
1. **slashnext-host-urls** - Search in SlashNext cloud database and retrieve list of all URLs associated with the specified host.
1. **slashnext-url-scan** - Perform a real-time URL reputation scan with SlashNext cloud-based SEER Engine.
1. **slashnext-url-scan-sync** - Perform a real-time URL scan with SlashNext cloud-based SEER Engine in a blocking mode.
1. **slashnext-scan-report** - Retrieve URL scan results against a previous scan request.
1. **slashnext-download-screenshot** - Download webpage screenshot against a previous URL scan request.
1. **slashnext-download-html** - Download webpage html against a previous URL scan request. 
1. **slashnext-download-text** - Download webpage text against a previous URL scan request.  
 
## Action: 'slashnext-api-quota'

Find information about your API quota, like current usage, quota left etc.

### Action Parameters

No parameters are required for this action.

## Action: 'slashnext-host-reputation'

Search in SlashNext cloud database and retrieve reputation of a host.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**host**</td>

<td>required</td>

<td>Host can either be a domain name or an IPv4 address.</td>

<td>string</td>

<td><span class="highlight">domain</span> <span class="highlight">ip</span></td>

</tr>

</tbody>

</table>



<a id="test-connectivity"></a>

## Action: 'slashnext-host-report'

Search in SlashNext cloud database and retrieve a detailed report for a host and associated URL.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**host**</td>

<td>required</td>

<td>Host can either be a domain name or IPv4 address.</td>

<td>string</td>

<td><span class="highlight">domain</span> <span class="highlight">ip</span></td>

</tr>

</tbody>

</table>

## Action: 'slashnext-host-urls'

Search in SlashNext cloud database and retrieve list of all URLs associated with the specified host.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**host**</td>

<td>required</td>

<td>Host can either be a domain name or IPv4 address.</td>

<td>string</td>

<td><span class="highlight">domain</span> <span class="highlight">ip</span></td>

</tr>

<tr>

<td>**limit**</td>

<td>optional</td>

<td>Maximum number of URL records to fetch. This is an optional parameter with a default value of 10.</td>

<td>numeric</td>

<td></td>

</tr>

</tbody>

</table>

## Action: 'slashnext-url-scan'

Perform a real-time URL reputation scan with SlashNext cloud-based SEER Engine. If the specified URL already exists in the cloud database, scan results will get returned immediately. If not, this action will submit a URL scan request and return with ‘check back later’ message along with a unique Scan ID. User can check results of this scan with ‘scan report’ action after 30 seconds or later using the returned Scan ID.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**url**</td>

<td>required</td>

<td>The URL that needs to be scanned.</td>

<td>string</td>

<td><span class="highlight">url</span></td>

</tr>

<tr>

<td>**extended_info**</td>

<td>optional</td>

<td>If extented_info is true, the system along with URL reputation also downloads forensics data like screenshot, HTML and rendered text.</td>

<td>string</td>

<td></td>

</tr>

</tbody>

</table>

## Action: 'slashnext-url-scan-sync'

Perform a real-time URL scan with SlashNext cloud-based SEER Engine in a blocking mode. If the specified URL already exists in the cloud database, scan result will get returned immediately. If not, this action will submit a URL scan request and wait for the scan to finish. The scan may take up to 30 seconds to finish.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**url**</td>

<td>required</td>

<td>The URL that needs to be scanned.</td>

<td>string</td>

<td><span class="highlight">url</span></td>

</tr>

<tr>

<td>**extended_info**</td>

<td>optional</td>

<td>If extented_info is true, the system along with URL reputation also downloads forensics data like screenshot, HTML and rendered text.</td>

<td>string</td>

<td></td>

</tr>

<tr>

<td>**timeout**</td>

<td>optional</td>

<td>A timeout value in seconds. If the system is unable to complete a scan within the specified timeout, a timeout error will be returned. User may try again with a different timeout. If no timeout value is specified, a default value of 60 seconds will be used.</td>

<td>numeric</td>

<td></td>

</tr>

</tbody>

</table>

## Action: 'slashnext-scan-report'

Retrieve URL scan results against a previous Scan request. If the scan is finished, result will be returned immediately; otherwise a ‘check back later' message will be returned.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**scanid**</td>

<td>required</td>

<td>Scan ID returned by an earlier call to ‘slashnext-url-scan’ or ‘slashnext-url-scan-sync’ action.</td>

<td>string</td>

<td><span class="highlight">snx scan id</span></td>

</tr>

<tr>

<td>**extended_info**</td>

<td>optional</td>

<td>If extented_info is true, the system along with URL reputation also downloads forensics data like screenshot, HTML and rendered text.</td>

<td>string</td>

<td></td>

</tr>

</tbody>

</table>

## Action: 'slashnext-download-screenshot'

Download webpage screenshot against a previous URL scan request.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**scanid**</td>

<td>required</td>

<td>Scan ID returned by an earlier call to ‘slashnext-url-scan’ or ‘slashnext-url-scan-sync’ action.</td>

<td>string</td>

<td><span class="highlight">snx scan id</span></td>

</tr>

</tbody>

</table>

## Action: 'slashnext-download-html'

Download webpage html against a previous URL scan request.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**scanid**</td>

<td>required</td>

<td>Scan ID returned by an earlier call to ‘slashnext-url-scan’ or ‘slashnext-url-scan-sync’ action.</td>

<td>string</td>

<td><span class="highlight">snx scan id</span></td>

</tr>

</tbody>

</table>

## Action: 'slashnext-download-text'

Download webpage text against a previous URL scan request.

### Action Parameters

<table>

<tbody>

<tr class="plain">

<th style="padding-right:5px;">PARAMETER</th>

<th style="padding-right:5px;">REQUIRED</th>

<th style="padding-right:5px;">DESCRIPTION</th>

<th style="padding-right:5px;">TYPE</th>

<th>CONTAINS</th>

</tr>

<tr>

<td>**scanid**</td>

<td>required</td>

<td>Scan ID returned by an earlier call to ‘slashnext-url-scan’ or ‘slashnext-url-scan-sync’ action.</td>

<td>string</td>

<td><span class="highlight">snx scan id</span></td>

</tr>

</tbody>

</table>
