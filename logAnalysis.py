import re
import csv
from collections import Counter


LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

# Configurable threshold
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def extract_ip_requests(log_lines):
    ip_requests = Counter()
    for line in log_lines:
        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip_requests[match.group(1)] += 1
    return ip_requests

def extract_endpoints(log_lines):
    endpoints = Counter()
    for line in log_lines:
        match = re.search(r'\"(?:GET|POST|PUT|DELETE) (/\S*) HTTP/1.\d\"', line)
        if match:
            endpoints[match.group(1)] += 1
    return endpoints

def detect_suspicious_activity(log_lines):
    failed_attempts = Counter()
    for line in log_lines:
        if "401" in line or "Invalid credentials" in line:
            match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                failed_attempts[match.group(1)] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity):
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # IP Requests
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests.items())
        
        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        
        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity.items())

def main():
    log_lines = parse_log_file(LOG_FILE)
    
    # Count requests per IP
    ip_requests = extract_ip_requests(log_lines)
    sorted_ip_requests = dict(ip_requests.most_common())
    
    # most accessed endpoint
    endpoints = extract_endpoints(log_lines)
    most_accessed_endpoint = endpoints.most_common(1)[0]
    
    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(log_lines)
    
    # Display results
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests.items():
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:20} {count}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_activity)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
