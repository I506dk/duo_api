# Duo API

#### A python script to interact with the Duo Admin API


## Features
- Create alias for admin users in Duo linking their standard and administrator accounts
- Specify an organizational unit as the searchbase instead of all domain users

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

(***-s or --server***)  - the hostname of the SQL server to connect to.

- Examples: ```python ssad.py -s``` or ```python ssad.py --server```

(***-d or --database***) - the name of the database Secret Server should use. ('SecretServer' is generally the default)

- Examples: ```python ssad.py -d``` or ```python ssad.py --database```

(***-u or --username***) - the username of the service account used to connect to the SQL database. Username should be in the format 'domain\username'.

- Examples: ```python ssad.py -u``` or ```python ssad.py --username```

(***-p or --password***) - the password for the service account being used to connect to SQL.

- Examples: ```python ssad.py -p``` or ```python ssad.py --password```

(***-a or --administrator***) - the password for the local administrator account created in Secret Server.

- Examples: ```python ssad.py -a``` or ```python ssad.py --administrator```

REMINDER - You can use multiple arguments as long as they aren't -h or --help (Those will default to showing the help screen then exiting)

Example run using arguments:
```
python ssad.py -s my-sql-server -d SecretServer -u test.domain\service_account -p service_password -a admin_password
```

## To Do
- [ ] Create function to remotely install and configure MS SQL (SQL express, and SQL Dev versions)
