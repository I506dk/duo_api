
# pip install pandas
# pip install pywin32
# pip install duo_client

# USE print(help()) to get all methods for a class or function
# Example: print(help(admin_api.update_user)) 

# These are part of the python standard library
import os
import sys
import argparse
import subprocess

# These need to be install manually
import binascii
import win32crypt
import duo_client
import pandas as pd


# Define a function to run a powershell command via subprocess and return the string output
def parse_command(command):
    command_output = subprocess.check_output(["powershell.exe", command]).decode("utf-8")
    command_output = command_output.replace('\n', '')
    command_output = command_output.replace('\r', '')

    return command_output


# Function to export credentials to xml file and encrypt using windows dpapi
# An exact adaptation of the powershell commandlet Export-Clixml
def export_credentials(username, password, filepath):
    # Encrypt the password using dpapi
    encrypted_password = win32crypt.CryptProtectData(password.encode("utf-16-le"))
    
    # Convert password to secure string format used by powershell
    password_secure_string = binascii.hexlify(encrypted_password).decode()

    # Use the same xml format as for powershells Export-Clixml, just replace values for username and password.
    xml = f"""<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">{username}</S>
      <SS N="Password">{password_secure_string}</SS>
    </Props>
  </Obj>
</Objs>"""
    
    # Write encrypted xml data to file
    try:
        with open(filepath, "w", encoding='utf-16') as export_file:
            export_file.write(xml)
            export_file.close()
            
            # Print ending message
        print("Credentials saved to: {}".format(filepath))
            
    except FileNotFoundError:
        print("Failed to open file: {}".format("filename"))

    return


# Function to import credentials from xml file
# An exact adaptation of the powershell commandlet Import-Clixml
def import_credentials(filename):
    # Import file and get credentials
    try:
        with open(filename, 'r', encoding='utf-16') as import_file:
            xml = import_file.read()
            import_file.close()
            
            if len(xml) > 0:
                # Extract username and password from the XML since thats all we care about.
                username = xml.split('<S N="UserName">')[1].split("</S>")[0]
                password_secure_string = xml.split('<SS N="Password">')[1].split("</SS>")[0]

                # CryptUnprotectData returns two values, description and the password
                _, decrypted_password_string = win32crypt.CryptUnprotectData(binascii.unhexlify(password_secure_string))

                # Decode password string to get rid of unknown characters
                decrypted_password_string = decrypted_password_string.decode("utf-16-le")
                
                return username, decrypted_password_string
            else:
                print("File is empty.")              
                return None, None
        
    except FileNotFoundError:
        print("Failed to open file: {}".format("filename"))
        
        return None


# Define a function to create the duo api connnection
def connect_to_duo(integration_key, secret_key, api_hostname):
    # Connect to the Duo admin api, and return the client
    duo_admin_api = duo_client.Admin(ikey=integration_key, skey=secret_key, host=api_hostname)
    
    return duo_admin_api


# Define a function to add an alias to a Duo user account
def add_alias(duo_user_id, user_alias, duo_api):
    # Get the current user
    current_user = duo_api.get_user_by_id(user_id=duo_user_id)
    
    # Get a list of keys for the current user (duo returns a dictionary)
    key_list = list(current_user.keys())
    # Check the alias keys, and get the first empty one
    for key in key_list:
        if ("alias" in str(key)) and (str(key) != "alias1"):
            if current_user[key] is None:
                # Create new alias that consists of the username plus _admin
                current_user[key] = str(user_alias)
                # Update alias for the specified user
                print("Updating '{}' to '{}' for user: {}".format(key, current_user[key], current_user["username"]))
                duo_api.update_user(duo_user_id, aliases={f"{[key][0]}={current_user[key]}"})
                break

    return


# Define a function to get users from active directory
def get_ad_users(search_base=None):
    # Check if AD tools are installed or not
    ad_tools_check = parse_command("(Get-WindowsFeature -Name 'RSAT-AD-PowerShell').InstallState")
    # If already installed continue, else install tools
    if str(ad_tools_check) == "Installed":
        print("Active Directory tools already installed. Continuing...")
    else:
        print("Installing Active Directory tools...")
        parse_command("Import-Module ServerManager;Add-WindowsFeature -Name 'RSAT-AD-PowerShell' -IncludeAllSubFeature")
        
    # Specify searchbase if necessary
    if search_base is None:
        # Get all SamAccountNames from AD
        ad_users = parse_command("Import-Module ActiveDirectory;Get-ADUser -Filter * | Format-Table SamAccountName -HideTableHeaders")
    else:
        ad_users = parse_command("Import-Module ActiveDirectory;Get-ADUser -Filter * -SearchBase '{}' | Format-Table SamAccountName -HideTableHeaders".format(search_base))
    # Create list of users
    ad_users = ad_users.split(' ')
    ad_users = list(filter(None, ad_users))
    
    return ad_users
    

# Define a function to get the current domain
def get_current_domain():
    # Get the domain of the server using wmi
    current_domain = parse_command("Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Format-Table Domain -HideTableHeaders")
    # Parse the domain into distinguished name format
    current_domain = current_domain.split('.')
    distinguished_name = ""
    j = 0
    while j < len(current_domain):
        if j != (len(current_domain) - 1):
            distinguished_name += ("DC=" + str(current_domain[j]) + ",")
        else:
            distinguished_name += ("DC=" + str(current_domain[j]))
            
        j += 1

    return distinguished_name
    

# Define function to get users from Duo
def get_duo_users(duo_api):
    # Get duo users
    duo_users = duo_api.get_users()
    # Initialize list of duo usernames
    duo_usernames = []
    # Append usernames to duo_usernames list
    for user in duo_users:
        duo_usernames.append([user["username"], user["user_id"]])
    
    return duo_usernames
  

# Define a function to compare the two user bases
def compare_userbase(ad_list, duo_list, duo_api, admin_attribute="_admin"):
    # Create a dataframe for AD and for Duo
    ad_dataframe = pd.DataFrame(ad_list, columns=["samaccountname"])
    # Force all samaccountnames to be lowercase
    ad_dataframe["samaccountname"] = ad_dataframe["samaccountname"].str.lower()
    duo_dataframe = pd.DataFrame(duo_list, columns=["username", "user_id"])
    # Add the naming attribute/string to each of the usernames in duo
    duo_dataframe["alternate"] = duo_dataframe["username"] + admin_attribute
    # Force all lowercase
    duo_dataframe["alternate"] = duo_dataframe["alternate"].str.lower()
    # Once the admin denotation is added, we can search the AD users for matches
    # This returns a new dataframe with True or False if found or not found respectively
    overlap = duo_dataframe["alternate"].isin(ad_dataframe["samaccountname"])
    
    # For each column, check if the user exists or not (True or False
    i = 0
    while i < len(overlap):
        if overlap[i] == True:
            # If true, create the alias for the user
            current_alias = duo_dataframe.iloc[i]["alternate"]
            current_id = duo_dataframe.iloc[i]["user_id"]
            add_alias(current_id, current_alias, duo_api)
        
        i += 1
    
    return


# Define a function to save and retrieve ikey, skey, and api hostname
def save_credentials(ikey=None, skey=None, api=None):
    # Define file paths for each saved items
    ikey_path = os.getcwd() + "\\ikey.xml"
    skey_path = os.getcwd() + "\\skey.xml"
    api_path = os.getcwd() + "\\api.xml"
    # Create list of file paths
    file_paths = [ikey_path, skey_path, api_path]
    
    # If ikey, skey, and api are None, then look for saved files
    if (ikey is None) and (skey is None) and (api is None):
        for path in file_paths:
            if os.path.exists(path) is True:
                # If path is found, import it
                if "ikey" in path:
                    print("Importing integration key...")
                    _, ikey = import_credentials(path)
                elif "skey" in path:
                    print("Importing secret key...")
                    _, skey = import_credentials(path)
                elif "api" in path:
                    print("Importing api hostname...")
                    _, api = import_credentials(path)
                else:
                    print("Found unknown path for: {}".format(path))
            else:
                pass
        return ikey, skey, api
                
    # Else save them to file
    else:
        export_credentials("ikey", ikey, ikey_path)
        export_credentials("skey", skey, skey_path)
        export_credentials("api", api, api_path)
    
        return None


# Define a function that contains the main logic for the script
def main_function(integration_key, secret_key, api_hostname, admin_notation, searchbase):
    # Connect to the Duo admin api
    admin_api = connect_to_duo(integration_key, secret_key, api_hostname)

    if len(searchbase) > 0:
        # Get the domain of the current server
        domain = get_current_domain()
        new_searchbase = "OU=" + str(searchbase) + "," + domain
        # Get a list of all AD users
        all_ad_users = get_ad_users(new_searchbase)
        
    else:
        # Get a list of all AD users
        all_ad_users = get_ad_users()
        
    # Get a list of all Duo users
    all_duo_users = get_duo_users(admin_api)

    # Compare users
    compare_userbase(all_ad_users, all_duo_users, admin_api, admin_notation)
    
    # Print message
    print("\nFinished.")
    
    return


# Define function to parse argument passed via the command line
def parse():
    parser = argparse.ArgumentParser(
        usage="{} [-i 'integration key'] [-s 'secret key'] [-a 'api hostname'] [-n 'naming convention']".format(os.path.basename(__file__)),
        description="Automate the creation of user attributes in Duo. "\
        "Integration Key, Secret Key, and API Hostname can be copied from the the Duo Admin API application. "\
        "More information on the Admin API can be found here: https://duo.com/docs/adminapi"
    )

    # Add argument that contains the integration key
    parser.add_argument("-i", "--ikey", dest="ikey", action="store", type=str, required=False,
        help="The integration key of the Duo Admin API.")
        
    # Add argument that contains the secret key
    parser.add_argument("-s", "--skey", dest="skey", action="store", type=str, required=False,
        help="The secret key of the Duo Admin API.")
        
    # Add argument that contains the api hostname of the duo tenant
    parser.add_argument("-a", "--api", dest="api_host", action="store", type=str, required=False,
        help="The API hostname for the Duo tenant.")
        
    # Add argument that contains the naming convention used to denote administrator accounts
    parser.add_argument("-n", "--notation", dest="notation", action="store", type=str, required=False,
        help="The naming convention or notation for specifying an admin account.")
        
    # Add argument that contains the naming convention used to denote administrator accounts
    parser.add_argument("-o", "--ou", dest="organizational_unit", default="", action="store", type=str, required=False,
        help="The oragnizational unit to pull users from in Active Directory. By default all Active Directory users are searched.")
        
    return parser.parse_args()


# Beginning of main
if __name__ == '__main__':
    # Get command line arguments
    args = parse()
    
    # Check arguments, and if they aren't passed, ask user for them
    # Create a dictionary of the arguments.
    argument_dictionary = vars(args)
    
    # Import credentials if they exists
    # Otherwise they are set to none, and user is prompted for them
    imported_ikey, imported_skey, imported_api = save_credentials()
    # If arguments aren't passed, try to pull them from file(s)
    for key in argument_dictionary.keys():
        if argument_dictionary[key] is None:
            if key == "ikey":
                argument_dictionary[key] = imported_ikey
            if key == "skey":
                argument_dictionary[key] = imported_skey
            if key == "api_host":
                argument_dictionary[key] = imported_api

    # For each of the arguments, check to see if they are equal to None. 
    # If equal to none, prompt user to input a values
    for key in argument_dictionary.keys():
        if argument_dictionary[key] is None:
            if key == "ikey":
                argument_dictionary[key] = input("Please enter the integration key for the Duo admin api: ")
            if key == "skey":
                argument_dictionary[key] = input("Please enter the secret key for the Duo admin api: ")
            if key == "api_host":
                argument_dictionary[key] = input("Please enter api hostname for the Duo tenant: ")
            if key == "notation":
                argument_dictionary[key] = input("Please enter the notation or naming convention used to denote an admin account: ")
            if key == "organizational_unit":
                argument_dictionary[key] = input("Please enter the organizational unit to search for active dirctory users (Leave blank if searching the entire domain): ")
      
    # Initialize variables
    ikey = argument_dictionary["ikey"]
    skey = argument_dictionary["skey"]
    api_host = argument_dictionary["api_host"]
    notation = argument_dictionary["notation"]
    organizational_unit = argument_dictionary["organizational_unit"]
    
    # Ask user if integration_key, secret_key, and api_host should be saved
    if (imported_ikey is None) and (imported_skey is None) and (imported_api is None):
        while True:
            save_info = input("Would you like to save these credentials for future use? (y/n) ").lower()
            if (save_info == 'y') or (save_info == "yes"):
                # Save credentials
                print("Saving to file...")
                save_credentials(ikey, skey, api_host)
                break
            elif (save_info == 'n') or (save_info == "no"):
                print("Continuing...")
                break
            else:
                # Other character entered.
                print("Invalid response entered. Use y/Y for yes, and n/N for no.")
        print("Continuing...")

    # Call main function
    main_function(ikey, skey, api_host, notation, organizational_unit)
