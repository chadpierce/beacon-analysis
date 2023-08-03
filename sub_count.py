# prints out # of subdomains associated with each domain

from collections import defaultdict
import csv
import sys

def count_subdomains(file_path, keywords):
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        lines = [row[2] for row in reader]
    domains = defaultdict(set)
    for line in lines:
        line = line.strip()
        # Check for duplicated domain names and remove them
        if len(line) % 2 == 0 and line[:len(line)//2] == line[len(line)//2:]:
            line = line[:len(line)//2]
        # Check if the domain name contains any of the keywords and ignore it if it does
        if any(keyword in line for keyword in keywords):
            continue
        parts = line.split('.')
        if len(parts) > 2:
            root_domain = '.'.join(parts[-2:])
            subdomain = parts[0]
            domains[root_domain].add(subdomain)
    for domain, subdomains in domains.items():
        print(f'{len(subdomains)} {domain}')

if __name__ == '__main__':
    file_path = sys.argv[1]
    ignore_list = ['word1', 'word2']
    count_subdomains(file_path, ignore_list)
