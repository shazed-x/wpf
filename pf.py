import requests
import argparse
import concurrent.futures
from urllib.parse import urljoin, urlparse
import os
import signal
import sys
import threading
from colorama import Fore, Style, init

# Initialize colorama for cross-platform support
init(autoreset=True)

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Global counters
total_paths_scanned = 0
failed_requests = 0  # 404 responses
passed_requests = 0  # 200 responses
other_responses = 0  # Non-200, non-404 responses
wordlist_lines = 0
found_urls = []  # Store successful URLs
executor = None  # ThreadPoolExecutor reference
stop_event = threading.Event()  # Event to stop requests immediately

def save_results(output_file):
    """Save found URLs to the output file."""
    if found_urls:
        with open(output_file, "w") as f:
            f.write("\n".join(found_urls) + "\n")
        print(Fore.YELLOW + f"\n[INFO] Results saved to {output_file}")

def print_summary():
    """Print the Scan Summary before exiting."""
    print(Fore.CYAN + "\n=== Scan Summary ===")
    print(f"Total lines in wordlist: {wordlist_lines}")
    print(f"Total paths checked: {total_paths_scanned}")
    print(Fore.GREEN + f"Passed requests (Status 200): {passed_requests}")
    print(Fore.GREEN + f"Other passed requests (Non-200, Non-404): {other_responses}")
    print(Fore.RED + f"Failed requests (Status 404 + errors): {failed_requests}")
    print(Fore.YELLOW + f"Results saved to {output_file}")

def handle_exit(signal_received, frame):
    """Handle CTRL+C (KeyboardInterrupt) and stop scanning immediately."""
    global executor
    print(Fore.RED + "\n[EXIT] CTRL+C detected! Stopping scan immediately...")

    stop_event.set()  # Stop all running requests

    if executor:
        executor.shutdown(wait=False, cancel_futures=True)  # Kill all threads instantly

    save_results(output_file)  # Save found results
    print_summary()  # Show Scan Summary
    sys.exit(0)  # Exit program immediately

# Attach signal handler for CTRL+C
signal.signal(signal.SIGINT, handle_exit)

def check_path(url, path):
    """Checks if a path exists on the target domain."""
    global failed_requests, passed_requests, other_responses, total_paths_scanned

    # Stop if CTRL+C was pressed
    if stop_event.is_set():
        return  

    full_url = urljoin(url, path.strip())

    try:
        response = requests.get(full_url, timeout=5, verify=False)

        # Stop immediately if CTRL+C was pressed during the request
        if stop_event.is_set():
            return  

        total_paths_scanned += 1  # Count each request attempt

        if response.status_code == 200:
            print(Fore.GREEN + "[PASS]  " + Fore.RESET + full_url)  # Green for [PASS], URL in white
            passed_requests += 1
            found_urls.append(full_url)  # Store found URL
        elif response.status_code == 404:
            print(Fore.RED + "[FAILED] " + Fore.RESET + full_url)  # Red for [FAILED], URL in white
            failed_requests += 1
        else:
            print(Fore.GREEN + "[PASSED] " + Fore.RESET + full_url + f" (Status: {response.status_code})")  
            other_responses += 1
    except requests.exceptions.RequestException:
        if not stop_event.is_set():  # Avoid printing after CTRL+C
            print(Fore.RED + "[FAILED] " + Fore.RESET + full_url)  # Red for [FAILED], URL in white
        failed_requests += 1

def scan_paths(url, wordlist):
    """Scans paths from a wordlist and checks if they exist."""
    global wordlist_lines, output_file, executor
    domain = urlparse(url).netloc
    output_file = f"{domain}_results.txt"

    print(Fore.YELLOW + f"Scanning {url} with wordlist: {wordlist}")

    try:
        with open(wordlist, "r") as f:
            paths = f.readlines()
    except FileNotFoundError:
        print(Fore.RED + f"Error: Wordlist file '{wordlist}' not found!")
        return

    wordlist_lines = len(paths)  # Count total lines in wordlist

    # Use ThreadPoolExecutor for faster scanning
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

    try:
        futures = [executor.submit(check_path, url, path) for path in paths]
        concurrent.futures.wait(futures)
    except KeyboardInterrupt:
        handle_exit(None, None)  # Force handle CTRL+C

    # Save results after scan
    save_results(output_file)

    # Print final summary
    print_summary()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Path Finder")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    args = parser.parse_args()

    scan_paths(args.url, args.wordlist)
