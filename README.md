# Duo API

#### A python script to interact with the Duo Admin API


## Features
- Create alias for admin users in Duo linking their standard and administrator accounts
- Specify an organizational unit as the searchbase instead of all domain users
- Optionally save the integration key, secret key, and api hostname to file using Microsoft's Data Protection API (DPAPI)

## Dependencies
- [Pywin32](https://pypi.org/project/pywin32/) - Python for Window Extensions
- [Pandas](https://pypi.org/project/pandas/) - Powerful data structures for data analysis, time series, and statistics
- [Duo-client](https://pypi.org/project/duo-client/) - Reference client for Duo Security APIs

## Installation
**Download the latest release of python below:**

[![Python Latest](https://img.shields.io/badge/python-latest-blue.svg)](https://www.python.org/downloads/windows/)

**Download and install Pip using the following commands:**
```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```
**Dependencies can be installed using requirements.txt:**
```
pip install -r requirements.txt
```
**Or individually installed via Pip:**
```
pip install pywin32
pip install pandas
pip install duo-client
```

## Usage
To run duo_api.py for the first time:
```
python duo_api.py
```
This will create aliases for administrator accounts in active directory to link them to their standard account in Duo. Will require user interaction.

Arguments can be specified to the script if an automated installation is wanted.

(***-h or --help***) - will display the help screen.

- Examples: ```python duo_api.py -h``` or ```python duo_api.py --help```
(***-i or --ikey***) - the integration key of the Duo Admin API.

- Examples: ```python duo_api.py -i``` or ```python duo_api.py --ikey```
(***-s or --skey***)  - the secret key of the Duo Admin API.

- Examples: ```python duo_api.py -s``` or ```python duo_api.py --skey```
(***-a or --api***) - the api hostname of the Duo tenant.

- Examples: ```python duo_api.py -a``` or ```python duo_api.py --api```
(***-n or --notation***) - the naming convention used to denote an administrator account.

- Examples: ```python duo_api.py -n``` or ```python duo_api.py --notation```
(***-o or --ou***) - the organizational to search for users in Active Directory.

- Examples: ```python duo_api.py -o``` or ```python duo_api.py --ou```


REMINDER - You can use multiple arguments as long as they aren't -h or --help (Those will default to showing the help screen then exiting)

Example run using arguments:
```
python duo_api.py -i DIxxxxxxxx -s I5xxxxxxxxx -a api-xxxxxx.duosecurity.com -n _admin -o Marketing_OU
```

## To Do
- [ ] Add additional functionality to support future processes
