"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""

import sys
import re
import pandas as pd
import log_analysis_lib as la

def main():
    log_file_path = la.get_file_path_from_cmd_line(1)
    
    # Determine how much traffic is on each port
    port_traffic_counts = tally_port_traffic(log_file_path)

    # Generate reports for ports that have 100 or more records
    for port, count in port_traffic_counts.items():
        if count >= 100:
            generate_port_traffic_report(log_file_path, port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report(log_file_path)

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log(log_file_path, '220.195.35.40')

def tally_port_traffic(log_file_path):
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value).

    Args:
        log_file_path (str): Path to the log file.

    Returns:
        dict: Dictionary of destination port number counts.
    """
    dpt_matches = la.filter_log_by_regex(log_file_path, r"DPT=(.*?) ")[1]
    
    port_traffic_counts = {}
    for match in dpt_matches:
        port = match[0]
        port_traffic_counts[port] = port_traffic_counts.get(port, 0) + 1
        
    return port_traffic_counts

def generate_port_traffic_report(log_file_path, port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        log_file_path (str): Path to the log file.
        port_number (str or int): Destination port number.
    """
    regex = r"^(.*[0-9]+)\s+(.*)\s+myth kernel.*SRC=(.*?)\s+.*DST=(.*?)\s+.*SPT=(.*?)\s+.*DPT=" + f"({port_number})"
    port_traffic_data = la.filter_log_by_regex(log_file_path, regex)[1]
    
    # Generate the CSV report
    column_names = ["Date", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port"]
    port_traffic_df = pd.DataFrame(port_traffic_data, columns=column_names)
    report_filename = f'destination_port_{port_number}_report.csv'
    port_traffic_df.to_csv(report_filename, header=column_names, index=False)

def generate_invalid_user_report(log_file_path):
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.

    Args:
        log_file_path (str): Path to the log file.
    """
    regex = r"(\w{3} \d{2}) (\d{2}:\d{2}:\d{2}).*Invalid user (\w+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    invalid_user_data = la.filter_log_by_regex(log_file_path, regex)[1]
    
    # Generate the CSV report
    column_names = ["Date", "Time", "Username", "IP Address"]
    invalid_user_df = pd.DataFrame(invalid_user_data, columns=column_names)
    invalid_user_df.to_csv('invalid_users_report.csv', header=column_names, index=False)

def generate_source_ip_log(log_file_path, ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        log_file_path (str): Path to the log file.
        ip_address (str): Source IP address.
    """
    regex = rf'SRC={ip_address}\s'
    source_ip_matches = la.filter_log_by_regex(log_file_path, regex)[0]
    log_filename = f'source_ip_{ip_address.replace(".", "_")}_log.txt'
    with open(log_filename, 'w') as log_file:
        for log_entry in source_ip_matches:
            log_file.write(log_entry + '\n')

if __name__ == '__main__':
    main()
