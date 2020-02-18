# Cognitive Intelligence Syslog Exporter
This script will get Cognitive Intelligence incidents from a Stealthwatch Enterprise SMC and send them as syslog to a specified destination. It is designed to be run as a cronjob, to ensure new alerts and updates are constantly being pushed to the destinations. On the initial run, it will the last 1000 events and record the time the script was run. After that, it will only pull events that are new or modified since the previous run's timestamp.

This script is available for use by the Cisco DevNet community through Code Exchange. For more information on the Stealthwatch Enterprise REST API, please see the following link: https://developer.cisco.com/docs/stealthwatch/enterprise/

## Requirements
1. Python 3.x
    - Additional python modules required, please see [requirements.txt](requirements.txt) for details
2. Stealthwatch Enterprise v7.1.0 or higher
    - Updates files and documentation can be found in the Network Visibility and Segementation product category on [software.cisco.com](https://software.cisco.com/download/home/286307082)
3. Stealthwatch user credentials with the "Master Admin" role assigned
    - User roles are configured in the Stealthwatch web interface... simply navigate to `Global Settings -> User Management`

## Installation
1. Ensure Python 3 is installed
   * To download and install Python 3, please visit https://www.python.org
2. Download the files [cognitive-intelligence-syslog-exporter.py](cognitive-intelligence-syslog-exporter.py) and [requirements.txt](requirements.txt)
3. Install the necessary python modules with the command: `pip install -r requirements.txt`
    * *ensure you use the correct `pip` executable for your instance of Python 3*

*Alternatively, advanced users can also use git to checkout / clone this project.*

## Configuration
The file `env.conf` will be generated upon your first run of the script, and will contain the following fields:
```
[STEALTHWATCH]
SMC = (The IP address of the SMC)
USER = (The username on the SMC to use, with 'Master Admin' role)
PASSWORD = (Encrypted password string [encryption handled on initial config])

[SYSLOG]
DESTINATION = (The IP address to send the UDP syslog to)
PORT = (The port to send the UDP syslog to)
```

#### **Cognitive Intelligence Incidents API Configuration**
The Cognitive Intelligence Incidents REST API is disabled by default. To enable the API:

* Enable Cognitive Analytics in External Services on your SMC and Flow Collector(s)
* Locate `/lancope/tomcat/webapps/cta-events-collector/WEB-INF/classes/app.properties` file on your SMC system
* Under `#CTA_ENABLED` section set the `cta.api.enabled` option to `true`
* Restart web server on your SMC system: `systemctl restart lc-tomcat`

## Usage
1. Identify the path to your Python 3 executible
    * Depending how Python 3 was installed, this might be as simple as just calling the command `python` or `python3`
2. Run the Python script with the following command:
    * `$ <PYTHON-PATH> cognitive-intelligence-syslog-exporter.py`
    * Example: `$ /usr/bin/python ./cognitive-intelligence-syslog-exporter.py`
3. If running for the first time, enter the request configuration items when prompted
4. This script is designed to be run as a cronjob after the initial run... it caches the previous run's timestamp and only pulls events that are new or have been updated since the last run
    * To schedule a cronjob, run the command `crontab -e` and add a new line containing: `0 0/10 * * * <path-to-python-script>`

## Troubleshooting
A log file will be generated and updated with each run... it will be stored in a `logs` directory in the same directory as the python executable... please reference this log file for troubleshooting

## Known issues
No known issues

## Getting help
Use this project at your own risk (support not provided)... *If you need technical support with Cisco Stealthwatch APIs, do one of the following:*

#### Browse the Forum
Check out our [forum](https://community.cisco.com/t5/custom/page/page-id/customFilteredByMultiLabel?board=j-disc-dev-security&labels=stealthwatch) to pose a question or to see if any questions have already been answered by our community... we monitor these forums on a best effort basis and will periodically post answers

#### Open A Case
* To open a case by web: http://www.cisco.com/c/en/us/support/index.html
* To open a case by email: tac@cisco.com 
* For phone support: 1-800-553-2447 (U.S.)
* For worldwide support numbers: www.cisco.com/en/US/partner/support/tsd_cisco_worldwide_contacts.html
* *If you don't have a Cisco service contract, send an email to swatchc-support@cisco.com describing your problem.*

## Getting involved
Contributions to this code are welcome and appreciated... see [CONTRIBUTING](CONTRIBUTING.md) for details... 

Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) at all times

## Licensing info
This code is licensed under the BSD 3-Clause License... see [LICENSE](LICENSE) for details

