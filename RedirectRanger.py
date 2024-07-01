import re
import sys
import subprocess
import signal
import getopt
import os
from urllib.parse import urlparse

def print_ascii_art():
    art = """
    \033[91m
\033[91m    ____           ___                __  ____
\033[91m   / __ \___  ____/ (_)_______  _____/ /_/ __ \____ _____  ____ ____  _____
\033[93m  / /_/ / _ \/ __  / / ___/ _ \/ ___/ __/ /_/ / __ `/ __ \/ __ `/ _ \/ ___/
\033[92m / _, _/  __/ /_/ / / /  /  __/ /__/ /_/ _, _/ /_/ / / / / /_/ /  __/ /
\033[94m/_/ |_|\___/\__,_/_/_/   \___/\___/\__/_/ |_|\__,_/_/ /_/\__, /\___/_/
                                                        /____/
    \033[95mv1.0 by QuackTheCode\033[0m
    """
    print(art)

def print_help():
    help_text = """
    \033[91m
\033[91m    ____           ___                __  ____
\033[91m   / __ \___  ____/ (_)_______  _____/ /_/ __ \____ _____  ____ ____  _____
\033[93m  / /_/ / _ \/ __  / / ___/ _ \/ ___/ __/ /_/ / __ `/ __ \/ __ `/ _ \/ ___/
\033[92m / _, _/  __/ /_/ / / /  /  __/ /__/ /_/ _, _/ /_/ / / / / /_/ /  __/ /
\033[94m/_/ |_|\___/\__,_/_/_/   \___/\___/\__/_/ |_|\__,_/_/ /_/\__, /\___/_/
                                                        /____/
    \033[95mv1.0 by QuackTheCode\033[0m

\033[93mDescription:\033[0m
\033[92mRedirectRanger is a tool designed to check the redirection of URLs from HTTP to HTTPS.
It extracts URLs from a specified file, performs cURL requests to check redirection,
and logs the results.\033[0m

\033[93mUsage:\033[0m
\033[92mpython RedirectRanger.py -l <input_file>\033[0m

\033[93mOptions:\033[0m
\033[92m-h, --help          Show this help message and exit
-l, --file          Specify the input file containing the URLs\033[0m

\033[93mExample:\033[0m
\033[92mpython RedirectRanger.py -l your_file.txt\033[0m
    """
    print(help_text)

def extract_urls_from_file(file_path):
    urls = set()  # Use a set to store URLs and remove duplicates
    with open(file_path, 'r') as file:
        for line in file:
            # Use a regular expression to find content within square brackets
            matches = re.findall(r'\[(https?://[^\]]+)\]', line)
            urls.update(matches)  # Add matches to the set
    return list(urls)  # Convert the set back to a list

def get_base_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def check_redirection(url):
    command = ['curl', '-I', url]
    try:
        response = subprocess.run(command, capture_output=True, text=True, timeout=10)
        headers = response.stdout
        # Extract status code
        status_code = re.search(r'HTTP\/\d\.\d (\d+)', headers)
        status_code = status_code.group(1) if status_code else 'N/A'
        # Check for redirection
        location = re.search(r'Location: (https?://[^\r\n]+)', headers)
        if location:
            redirect_url = location.group(1)
            if status_code == '301':
                return True, status_code, redirect_url, headers
        if status_code == '200':
            return False, status_code, None, headers
        return False, status_code, location.group(1) if location else None, headers
    except subprocess.TimeoutExpired:
        return False, 'Timeout', None, 'Timeout'

def save_urls_to_file(urls, output_dir, log_file_path):
    successful_redirects = []
    no_redirects = []
    other_responses = []
    
    os.makedirs(output_dir, exist_ok=True)
    master_file_path = os.path.join(output_dir, 'results.txt')
    success_file_path = os.path.join(output_dir, 'successful_redirects.txt')
    no_redirect_file_path = os.path.join(output_dir, 'no_redirects.txt')
    other_responses_file_path = os.path.join(output_dir, 'other_responses.txt')

    with open(master_file_path, 'w') as master_file, \
         open(log_file_path, 'w') as log_file:
        for url in urls:
            # Replace "https" with "http"
            modified_url = url.replace("https", "http")
            success, status_code, redirect_url, headers = check_redirection(modified_url)
            # Log the cURL command and response
            log_file.write(f"\033[94mCommand: curl -I \"{modified_url}\"\033[0m\n")
            log_file.write(f"Response:\n{headers}\n")
            if success:
                message = f"\033[92mSuccessfully redirected to HTTPS ({status_code})\033[0m"
                successful_redirects.append(f"\033[94m{modified_url}\033[0m - {message}")
            elif status_code == '200' and not redirect_url:
                message = f"\033[91mDid not redirect (200 OK)\033[0m"
                no_redirects.append(f"\033[94m{modified_url}\033[0m - {message}")
            else:
                message = f"\033[93mUnexpected status ({status_code})\033[0m"
                other_responses.append(f"\033[94m{modified_url}\033[0m - {message}")
            print(f"\033[94m{modified_url}\033[0m - {message}")
            master_file.write(f"\033[94m{modified_url}\033[0m - {message}\n")

    # Write specific files if there are entries
    if successful_redirects:
        with open(success_file_path, 'w') as success_file:
            for entry in successful_redirects:
                success_file.write(entry + '\n')

    if no_redirects:
        with open(no_redirect_file_path, 'w') as no_redirect_file:
            for entry in no_redirects:
                no_redirect_file.write(entry + '\n')

    if other_responses:
        with open(other_responses_file_path, 'w') as other_responses_file:
            for entry in other_responses:
                other_responses_file.write(entry + '\n')

    return len(urls), len(successful_redirects), len(no_redirects), len(other_responses), master_file_path, success_file_path, no_redirect_file_path, other_responses_file_path

def signal_handler(sig, frame):
    print("\n\033[93mExecution interrupted. Exiting gracefully...\033[0m")
    sys.exit(0)

def main(argv):
    input_file_path = ''
    try:
        opts, args = getopt.getopt(argv, "hl:", ["help", "file="])
    except getopt.GetoptError:
        print_help()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_help()
            sys.exit()
        elif opt in ("-l", "--file"):
            input_file_path = arg
    
    if not input_file_path:
        print("\033[91mInput file is required.\033[0m")
        print_help()
        sys.exit(2)

    signal.signal(signal.SIGINT, signal_handler)

    print_ascii_art()
    
    urls = extract_urls_from_file(input_file_path)
    if not urls:
        print("\033[91mNo URLs found in the input file.\033[0m")
        sys.exit(2)
    
    base_url = get_base_url(urls[0])
    output_dir = base_url  # Directory to save the results
    log_file_path = os.path.join(output_dir, 'curl_commands.txt')  # The file to log the cURL requests and responses

    total_urls, successful_redirects, no_redirects, other_responses, master_file_path, success_file_path, no_redirect_file_path, other_responses_file_path = save_urls_to_file(
        urls,
        output_dir,
        log_file_path
    )
    
    print("\n\033[93mTotal number of URLs tested: {}\033[0m - written to {}".format(total_urls, master_file_path))
    print("\033[0m-----------------------------------------------------------------------")
    print("\033[92mSuccessful redirections: {}\033[0m - written to {}".format(successful_redirects, success_file_path if successful_redirects > 0 else 'N/A'))
    print("\033[91mDid not redirect: {}\033[0m - written to {}".format(no_redirects, no_redirect_file_path if no_redirects > 0 else 'N/A'))
    print("\033[93mOther responses: {}\033[0m - written to {}".format(other_responses, other_responses_file_path if other_responses > 0 else 'N/A'))
    print("\033[0m-----------------------------------------------------------------------")
    print("\033[95mcURL logs have been saved to {}\033[95m".format(log_file_path))

if __name__ == "__main__":
    main(sys.argv[1:])
