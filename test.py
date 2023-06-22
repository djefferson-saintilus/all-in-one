import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)  # Initialize colorama

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

search_gtfobins()
