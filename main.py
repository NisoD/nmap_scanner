import pandas as pd
import subprocess  # For nmap execution
import click

from multiprocessing import Pool

nmap_cmd = [
    r'C:\Users\RedmiBook\OneDrive\Documents\GitHub\Ethical_Hacking\Nmap\nmap.exe', '-sS', '-O', '-Pn', 0]


def read_ips_from_csv(csv_file):
    """Reads IP addresses from a CSV file."""
    try:
        df = pd.read_csv(csv_file)
        return df['IP/subnet'].tolist()  # Assuming 'IP/subnet' is the header
    except FileNotFoundError:
        print(f"Error: CSV file '{csv_file}' not found.")
        return []
    except pd.errors.ParserError:
        print(f"Error: Could not parse the CSV file '{csv_file}'. Ensure proper formatting.")
        return []


def scan_ip_with_nmap(ip):
    """Scans an IP address with nmap."""
    nmap_cmd[-1] = ip
    try:
        output = subprocess.check_output(nmap_cmd, stderr=subprocess.STDOUT).decode()
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error scanning {ip}: {e}")
        return "Scan failed"


def write_results_to_csv(ips, results, output_csv):
    """Writes scan results to a CSV file."""
    data = {'IP/subnet': ips, 'Result': results}
    df = pd.DataFrame(data)
    df.to_csv(output_csv, index=False)  # Avoid index column


@click.command()
@click.option('--input_csv', default='data.csv', help='Path to the input CSV file')
@click.option('--output_csv', default='scan_results.csv', help='Path to the output CSV file')
@click.option('--processes', default=4, help='Number of processes to run in parallel')
def main(input_csv, output_csv, processes):
    """Main function to handle program execution."""
    # Read IP addresses from the input CSV file
    ips = read_ips_from_csv(input_csv)

    # Perform parallel nmap scans on the IP addresses
    results = parallel_nmap_scan(ips, processes)

    # Write the scan results to an output CSV file
    write_results_to_csv(ips, results, output_csv)


def parallel_nmap_scan(ips, processes):
    """Performs parallel nmap scans on the IP addresses."""
    with Pool(processes) as pool:
        results = pool.map(scan_ip_with_nmap, ips)
    return results


if __name__ == "__main__":
    main()
