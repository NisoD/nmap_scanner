import pandas as pd
import subprocess  # For nmap execution
import click

from multiprocessing import process
from multiprocessing import Pool
nmap_cmd = [
        r'C:\Users\RedmiBook\OneDrive\Documents\GitHub\Ethical_Hacking\Nmap\nmap.exe', '-sS', '-O', '-Pn', 0]
def read_ips_from_csv(csv_file):
    """Reads IP addresses from a CSV file.

    Args:
        csv_file (str): Path to the CSV file containing IP addresses.

    Returns:
        list: List of IP addresses extracted from the CSV file.
    """

    try:
        df = pd.read_csv(csv_file)
        return df['IP/subnet'].tolist()  # Assuming 'IP/subnet' is the header
    except FileNotFoundError:
        print(f"Error: CSV file '{csv_file}' not found.")
        return []
    except pd.errors.ParserError:
        print(
            f"Error: Could not parse the CSV file '{csv_file}'. Ensure proper formatting.")
        return []


def scan_ip_with_nmap(ip):

    # Use SYN scan (-sS) and OS detection (-O)
    nmap_cmd[-1] = ip
    try:
        output = subprocess.check_output(
            nmap_cmd, stderr=subprocess.STDOUT).decode()
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error scanning {ip}: {e}")
        return "Scan failed"


def write_results_to_csv(ips, results, output_csv):
    """Writes scan results to a CSV file.

    Args:
        ips (list): List of scanned IP addresses.
        results (list): List of corresponding scan results (output from nmap_scan).
        output_csv (str): Path to the output CSV file.
    """

    data = {'IP/subnet': ips, 'Result': results}
    df = pd.DataFrame(data)
    df.to_csv(output_csv, index=False)  # Avoid index column

def get_input_by_click():
    input_csv = 'data.csv'
    output_csv = 'scan_results.csv'
    input_csv_user = click.prompt(
        'Enter the input CSV file path', default=input_csv)
    output_csv_user = click.prompt(
        'Enter the output CSV file path', default=output_csv)
    prcoess_amount = click.prompt('Enter the amount of processes', default=4)
    return input_csv_user, output_csv_user,prcoess_amount
def parallel_nmap_scan(ips, processes):
    with Pool(processes) as pool:
        results = pool.map(scan_ip_with_nmap, ips)
    return results


   
def main():
    """Main function to handle program execution."""

    # Get input and output CSV file paths
    input_csv, output_csv,prcoess_amount = get_input_by_click()

    # Read IP addresses from the input CSV file
    ips = read_ips_from_csv(input_csv)

    # Perform parallel nmap scans on the IP addresses
    results = parallel_nmap_scan(ips,prcoess_amount)

    # Write the scan results to an output CSV file
    write_results_to_csv(ips, results, output_csv)

if __name__ == "__main__":
    main()
