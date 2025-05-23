# Cyber Forge Toolbox by Mason Davis
# Version 0.5.2.5
# Last Updated: 11/17/2023

# Overview:
# This multi-tool suite includes the following tools:
#   1. Port Scanner: Identify vulnerabilities in a target website.
#   2. Password Strength Checker: Evaluate password strength based on common rules.
#   3. File Encryption and Decryption: Securely encrypt or decrypt files.
#   4. Web Application Vulnerability Scanner: Detect SQL Injection and XSS vulnerabilities in web applications.

# Legal Disclaimer:
# This program is for educational purposes only. The author is not liable for misuse or damage caused by this tool.
# Verify the legality of tool usage in your country. Use only on systems you own or have permission to test.
# Remember: Just because you can, doesn't mean you should.

# Usage Guidelines:
# - Web Application Vulnerability Scanner: Legal use on your own web apps or with owner permission.
# - Port Scanner: Legal use on your own network or with owner permission.
# - File Encryption and Decryption: Legal use on your own files or with owner permission.
# - Password Strength Checker: Legal use on your own passwords or with owner permission.

# License:
# This program is licensed under the MIT License. See LICENSE for details.
# You are free to copy, modify, and redistribute under the original author's credit and preserving the original license.
# Provided "as is" with no warranty. The author is not responsible for misuse or damage per the MIT License.

# Contact:
# For questions or concerns, contact: masondav08@gmail.com
# Thank you for using my tool! I hope you find it useful!






#Importing modules for use in program, please install by using pip install -r requirements.txt.
#getpass and re are used for password strength checker.
import getpass
import re
#For json file saving and loading.
import json
#OS module, used for clearing screen.
import os
#Socket module, used for port scanning/anything to due with ports.(IP scanning, SQL injection, etc.)
import socket
import datetime #Used for timestamping files
import time
#crypto modules, used for file encryption and decryption.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#OS module, used for clearing screen.
import os
import base64
import requests
#Below are used for UI, colorama is used for color, and prettytable is used for the menu. Bs4 is used for web scraping.
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from prettytable import PrettyTable
from colorama import Fore, Style



# Function for Vulnerability Scanner
SCAN_RESULTS_DIR = "scan_results"

def create_results_directory():
    if not os.path.exists(SCAN_RESULTS_DIR):
        os.mkdir(SCAN_RESULTS_DIR)

def save_scan_results(target, results):
    timestamp = datetime.datetime.now().strftime("%m-%d %H_%M")
    filename = f"{timestamp}.json"
    results_path = os.path.join(SCAN_RESULTS_DIR, filename)
    with open(results_path, 'w') as file:
        json.dump(results, file)
    print(f"\n{Fore.GREEN}Scan results saved to {results_path}{Style.RESET_ALL}")

def list_saved_results():
    result_files = os.listdir(SCAN_RESULTS_DIR)
    if not result_files:
        print(f"\n{Fore.YELLOW}No saved scan results found.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}Saved scan result files:{Style.RESET_ALL}")
        result_files = sorted(result_files, key=lambda x: os.path.getctime(os.path.join(SCAN_RESULTS_DIR, x)), reverse=True)
        for i, filename in enumerate(result_files):
            print(f"{i + 1}: {filename}")

def retrieve_scan_results():
    list_saved_results()
    print("____________________________")
    selection = input(f"\n{Fore.BLUE}Select a file to display (0 to cancel): {Style.RESET_ALL}")
    if selection == "0":
        return
    try:
        selection = int(selection)
        filename = os.listdir(SCAN_RESULTS_DIR)[selection - 1]
        results_path = os.path.join(SCAN_RESULTS_DIR, filename)
        with open(results_path, 'r') as file:
            results = json.load(file)
            print(f"\n{Fore.YELLOW}Results for {filename}:{Style.RESET_ALL}")
            for target, ports in results.items():
                print(f"\n{Fore.YELLOW}Target: {target}{Style.RESET_ALL}")
                open_ports = [port for port, status in ports.items() if status]
                if open_ports:
                    print(f"{Fore.YELLOW}Open Ports: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}No open ports found.{Style.RESET_ALL}")
    except (ValueError, IndexError):
        print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")

def target_scan(targets):
    results = {}
    for target in targets:
        target = target.strip()
        result = {}
        try:
            ip = socket.gethostbyname(target)
            result["IP"] = ip
            result["Status"] = True
        except socket.gaierror:
            result["IP"] = "N/A"
            result["Status"] = False
        results[target] = result
    return results

def port_scan(targets, ports):
    results = {}
    for target in targets:
        target = target.strip()
        results[target] = {}
        ip = socket.gethostbyname(target)
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                results[target][port] = True
            else:
                results[target][port] = False
    return results

def menu1():
    create_results_directory()
    while True:
        print("____________________________")
        print(f"{Fore.LIGHTCYAN_EX}Port/IP Scanner Menu:{Style.RESET_ALL}")
        print("1. Multi Target Scanning")
        print("2. Port Scanning")
        print("3. Save Scan Results")
        print("4. Retrieve Scan Results")
        print("6. Help")
        print("7. Exit")
        print("____________________________")
        choice = input(f"{Fore.BLUE}Select an option: {Style.RESET_ALL}")

        if choice == "1":
            target_input = input(f"{Fore.BLUE}\nEnter target(s) to scan (comma-separated): {Style.RESET_ALL}").split(',')
            target_results = target_scan(target_input)
            for target, data in target_results.items():
                print(f"\n{Fore.YELLOW}Target: {target}\nIP: {data['IP']}\nStatus: {'Active' if data['Status'] else 'Inactive'}{Style.RESET_ALL}")
        elif choice == "2":
            target_input = input(f"{Fore.BLUE}\nEnter target(s) to scan (comma-separated): {Style.RESET_ALL}").split(',')
            port_input = input(f"{Fore.BLUE}\nEnter port(s) to scan (comma-separated): {Style.RESET_ALL}").split(',')
            try:
                port_input = [int(port.strip()) for port in port_input]
                port_results = port_scan(target_input, port_input)
                for target, data in port_results.items():
                    print(f"\n{Fore.YELLOW}Target: {target}{Style.RESET_ALL}")
                    open_ports = [port for port, status in data.items() if status]
                    if open_ports:
                        print(f"{Fore.YELLOW}Open Ports: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
                        print("____________________________")
                    else:
                        print(f"{Fore.YELLOW}No open ports found.{Style.RESET_ALL}")
                        print("____________________________")
            except ValueError:
                print(f"{Fore.RED}Invalid port input. Please enter a comma-separated list of port numbers.{Style.RESET_ALL}")
        elif choice == "3":
            if 'target_results' not in locals() and 'port_results' not in locals():
                print(f"{Fore.YELLOW}No scan results to save.{Style.RESET_ALL}")
            else:
                if 'target_results' in locals():
                    save_scan_results('target_scan', target_results)
                if 'port_results' in locals():
                    save_scan_results('port_scan', port_results)
        elif choice == "4":
            retrieve_scan_results()
        elif choice == "6":
            print("____________________________")
            print(f"1. Multi Target Scanning: {Fore.GREEN}Scan multiple targets and display their IP and status.{Style.RESET_ALL}")
            print(f"2. Port Scanning: {Fore.GREEN}Scan multiple targets and ports, and display the open ports.{Style.RESET_ALL}")
            print(f"3. Save Scan Results: {Fore.GREEN}Save the results of a scan to a JSON file.{Style.RESET_ALL}")
            print(f"4. Retrieve Scan Results: {Fore.GREEN}Retrieve the results of a scan from a JSON file.{Style.RESET_ALL}")           
            print(f"5. Identify Service Banners: {Fore.GREEN}Identify the service banners of open ports.{Style.RESET_ALL}")
            print(f"7. Exit: {Fore.GREEN}Exit the program.{Style.RESET_ALL}")
            print(f"HELP: {Fore.GREEN}Display the help menu.{Style.RESET_ALL}")
            print("____________________________")
        elif choice == "7":
            main_menu()
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

#calls the vulnerability scanner from the main menu
def vulnerability_scanner():
    print(f"{Fore.GREEN}Running Port/IP Scanner...{Style.RESET_ALL}")
    menu1()

# Function for Password Strength Checker
def is_password_secure(password):
    # Define criteria for a strong password
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    digit_criteria = bool(re.search(r'\d', password))
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    # Check if the password meets all criteria
    if length_criteria and uppercase_criteria and lowercase_criteria and digit_criteria and special_char_criteria:
        return True
    else:
        return False

def check():
    # Get the password from the user
    password = input(f"{Fore.BLUE}Enter your password: {Style.RESET_ALL}")

    # Check the password strength
    if is_password_secure(password):
        print(f"{Fore.GREEN}Password is strong! 👍{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Password is weak. Please make it stronger. 👎{Style.RESET_ALL}")

    # Return to menu() after user input
    input(f"\n{Fore.BLUE}Press Enter to return to the main menu...{Style.RESET_ALL}")
#derive key function, used for file encryption and decryption.
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

#encrypt file function, takes file path and password as input.
def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        salt = os.urandom(16)
        key = derive_key(password, salt)
        iv = os.urandom(16)  # Generate a random IV

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        if not os.path.exists(desktop_path):
            desktop_path = os.path.join(os.path.expanduser("~"), "OneDrive\Desktop")
        base_filename = os.path.splitext(os.path.basename(file_path))[0]  # Strip file extension
        encrypted_file_path = os.path.join(desktop_path, f"{base_filename}.enc")

        with open(encrypted_file_path, 'wb') as file:
            file.write(salt + iv + ciphertext)

        print(f"Encryption successful. Encrypted file: {encrypted_file_path}")
    except FileNotFoundError:
        print("Error: File not found or invalid path.")
        
    except Exception as e:
        print(f"Error: {e}")
#decrypt file function. Same as above, but for decryption.
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        #account for OneDrive desktop folder
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        if not os.path.exists(desktop_path):
            desktop_path = os.path.join(os.path.expanduser("~"), "OneDrive\Desktop")
                
                
                
        base_filename = os.path.splitext(os.path.basename(file_path))[0]  # Strip file extension
        decrypted_file_path = os.path.join(desktop_path, f"{base_filename}.dec")

        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)

        print(f"Decryption successful. Decrypted file: {decrypted_file_path}")
    except FileNotFoundError:
        print("Error: File not found or invalid path.")
    except Exception as e:
        print(f"Error: {e}")
#menu for file encryption and decryption
def main2():
    project_folder = os.path.abspath(os.path.join(os.path.dirname(__file__)))

    file_path = input("Enter the path of the file: ")
    password = input("Enter the password: ")

    encrypt_or_decrypt = input("Do you want to encrypt (e) or decrypt (d) the file? ").lower()

    if encrypt_or_decrypt == 'e':
        encrypt_file(file_path, password)
        print("Current Working Directory:", os.getcwd())
    elif encrypt_or_decrypt == 'd':
        decrypt_file(file_path, password)
    else:
        print("Invalid choice. Please enter 'e' for encryption or 'd' for decryption.")



#return to menu after user input
    input("\nPress Enter to return to the main menu...")
    main_menu()
    # Add your file encryption and decryption logic here

#scan for sql injection, testing payload delivery to see if it is accepted.

def scan_for_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' OR '1'='1' --",
        "1; SELECT * FROM users;",
        "admin'--",
        "1 UNION SELECT password FROM users;",
        "1 AND 1=1 UNION SELECT password FROM users;",
        "1' AND 'a'='a",
    ]

    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        if payload in response.text:
            print(f"*WARNING* SQL INJECTION VULNERABILITY FOUND AT: {test_url}")
            print("Suggested Remediation Steps:")
            print("1. Use parameterized queries or prepared statements to sanitize inputs.")
            print("2. Implement input validation to ensure only expected data is accepted.")
        else:
            print("No SQL Injection vulnerability found.")

def scan_for_xss(url):
    #These payloads were pulled from the OWASP XSS Filter Evasion Cheat Sheet. Do not use these payloads for malicious purposes.
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\"'>",
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83))>",
    ]

    for payload in payloads:
        test_url = f"{url}?input={payload}"
        response = requests.get(test_url)
        if payload in response.text:
            print(f"*WARNING* XSS VULNERABILITY FOUND AT: {test_url}")
            print("Suggested Remediation Steps:")
            print("1. Encode user input when displaying it in HTML (e.g., use HTML entities).")
            print("2. Implement Content Security Policy (CSP) headers to restrict script sources.")
        else:
            print("No XSS (Cross-Site Scripting) vulnerability found.")


def main3():
    target_url = input("Enter the target URL: ")
    
    # Ensure the target URL starts with http:// or https://
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    try:
        response = requests.get(target_url)
        if response.status_code == 200:
            print(f"Scanning {target_url} for vulnerabilities...\n")

            scan_for_sql_injection(target_url)
            scan_for_xss(target_url)

            print("\nVulnerability scanning completed.")
        else:
            print(f"Failed to connect to {target_url}. HTTP Status Code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error: {e}")
    #if http code 403, then it is forbidden, and the program will wait 5 seconds and try again.
    #this may proc, usually does not after testing.
    except requests.exceptions.HTTPError as errh:
        print("Http Error:",errh)
        print("Waiting 5 seconds and trying again.")
        time.sleep(5)
        main3()

    # Return to menu after user input
    input("\nPress Enter to return to the main menu...")
    main_menu()
 
    # Add your web application vulnerability scanning logic here

# Main menu loop


def print_menu():
    # Clear the screen
    os.system('cls' if os.name == 'nt' else 'clear')
    # Print line above header
    print(f"{Fore.YELLOW}{'=' * 49}{Style.RESET_ALL}")

    header = (
        f"{Fore.GREEN}{'=' * 13}⚒️CYBER FORGE TOOLBOX🛠️{'=' * 13}{Style.RESET_ALL}\n"
        f"{' ' * 18}by: {Fore.CYAN}Mason Davis{Style.RESET_ALL}\n"
        f"{' ' * 17}Version:  0.5.2.5{Style.RESET_ALL}\n"
    )
#Pretty table for menu, color coded to make it easier to read.
    menu_table = PrettyTable()

    
    menu_table.field_names = [f"{Fore.YELLOW}#", f"{Fore.YELLOW}Tool Selection{Style.RESET_ALL}"]
    menu_table.add_row(["1", "Port/IP Scanner"])
    menu_table.add_row(["2", "Password Strength Checker"])
    menu_table.add_row(["3", "File Encryption and Decryption"])
    menu_table.add_row(["4", "Web Application Vulnerability Scanner"])
    menu_table.add_row(["5", "License Information"])
    menu_table.add_row(["6", "Help"])
    menu_table.add_row(["0", "Exit"])
    separation_line = f"{Fore.YELLOW}{'=' * 49}{Style.RESET_ALL}"

    print(f"{header}\n{menu_table}\n{separation_line}\n")

def main_menu():
    while True:
        print_menu()
        choice = input(f"{Fore.BLUE}Enter your choice: {Style.RESET_ALL}")

        if choice == '1':
            vulnerability_scanner()
        elif choice == '2':
            check()
        elif choice == '3':
            main2()
        elif choice == '4':
            main3()
        elif choice == '5':
            display_license_information()
        elif choice == "6":
             print_help_menu()
        elif choice == '0':
            print(f"{Fore.RED}Exiting the Cybersecurity Tool Suite. Goodbye!{Style.RESET_ALL}")
            time.sleep(2)
            exit()
        else:
            print(f"{Fore.RED}Invalid choice. Please enter a valid option.{Style.RESET_ALL}")
#Handy Dandy help menu, color coded to make it easier to read.
def print_help_menu():
    #color the help menu to make it easier to read as \nHelp Menu
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Help Menu{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    print("This is a multi-tool suite that contains the following tools:")
    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
   
    print("\n\033[91m1. Port Scanner:\033[0m Scan for vulnerabilities in a target website by scanning")
    print("   for open ports and displaying the IP address and status of the target.")
    print("\n\033[92m2. Password Strength Checker:\033[0m Check the strength of a password based on common password rules.")
    print("   - Passwords must be at least 8 characters long.")
    print("   - Must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
    print("\n\033[93m3. File Encryption and Decryption:\033[0m Encrypt or decrypt a file.")
    print("   - The encrypted and decrypted files will be saved to your desktop.")
    print("   - To decrypt a file or encrypt, please place the file in the same directory as the program.")
    print("   - Then type the name of the file when prompted. (e.g., info.txt)")
    print("\n\033[94m4. Web Application Vulnerability Scanner:\033[0m Scan web applications for SQL Injection and XSS vulnerabilities.")
    print("\n\033[96m5. License Information:\033[0m Display the license information for this program.")
    print("\n\033[95m6. Help:\033[0m Display this help menu!")
    print("\n\033[96m0. Exit:\033[0m Exit the Cybersecurity Tool Suite.")
    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    # Wait for user input before going back to the main menu
    input("\nPress Enter to return to the main menu...")
    main_menu()

def display_license_information():
    # Clear the screen
    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'=' * 15} LICENSE INFORMATION {'=' * 15}{Style.RESET_ALL}\n")
    print("This program is licensed under the MIT License.")
    print("For detailed information, please visit:")
    print(f"{Fore.BLUE}https://opensource.org/licenses/MIT{Style.RESET_ALL}\n")
    print("MIT License\n")
    print("MIT License Text:\n")
    print("Permission is hereby granted, free of charge, to any person obtaining a copy")
    print("of this software and associated documentation files (the \"Software\"), to deal")
    print("in the Software without restriction, including without limitation the rights")
    print("to use, copy, modify, merge, publish, distribute, sublicense, and/or sell")
    print("copies of the Software, and to permit persons to whom the Software is")
    print("furnished to do so, subject to the following conditions:\n")
    print("The above copyright notice and this permission notice shall be included in all")
    print("copies or substantial portions of the Software.\n")
    print("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR")
    print("IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,")
    print("FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE")
    print("AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER")
    print("LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,")
    print("OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE")
    print("SOFTWARE.\n")
    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")

    #wait for user input to return to menu
    input("\nPress Enter to return to the main menu...")
    main_menu()


if __name__ == "__main__":
    main_menu()



