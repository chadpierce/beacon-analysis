import random
from datetime import datetime, timedelta

def generate_dummy_log_data(num_sources=200):
    start_time = datetime(2023, 3, 2, 20, 58, 27)
    end_time = start_time + timedelta(hours=8)
    current_time = start_time
    time_increment = timedelta(seconds=1)
    beacon_time = start_time
    beacon_increment = timedelta(minutes=1)

    sources = [f"172.30.0.{i}" for i in range(1, num_sources + 1)]
    usernames = [f"user{i}" for i in range(1, num_sources + 1)]
    source_username_pairs = list(zip(sources, usernames))
    dest_ips = [f"99.11.99.{i}" for i in range(1, 21)]
    categories = ['"category"']
    methods = ["POST"]
    ports = [443]
    domains = [f"domain{i}.com" for i in range(1, 101)]
    uris = ["/index.html"]
    filetypes = [0]
    agents = ['"Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_(KHTML,_like_Gecko)_Chrome/109.0.0.0_Safari/537.36"']
    
    beacon_source_username_pair = random.choice(source_username_pairs)
    beacon_dest_ip = random.choice(dest_ips)
    
    while current_time < end_time:
        source_username_pair = random.choice(source_username_pairs + [("-", "-")])
        source = source_username_pair[0]
        username = source_username_pair[1]
        dest_ip = random.choice(dest_ips + ["-"])
        category = random.choice(categories)
        method = random.choice(methods)
        port = random.choice(ports)
        domain = random.choice(domains)
        uri = random.choice(uris)
        filetype = random.choice(filetypes)
        agent = random.choice(agents)
        bytes_received = random.randint(100, 1000)
        bytes_sent = random.randint(1000, 10000)

        if current_time >= beacon_time:
            jitter = timedelta(seconds=random.randint(-10, 10))
            #jitter = timedelta(0)  ## uncomment to remove jitter
            beacon_time += beacon_increment + jitter
            sent_bytes = 300 # + random.randint(-400, 400)  # uncomment to add randomness
            rec_bytes = 400 # + random.randint(-400, 400)  # uncomment to add randomness
            print(f"{current_time.strftime('%Y-%m-%d-%H:%M:%S')},{beacon_source_username_pair[0]},{beacon_source_username_pair[1]},{beacon_dest_ip},{category},{method},{port},itsabeacon.com,{uri},{filetype},{agent},{rec_bytes},{sent_bytes}")

        print(f"{current_time.strftime('%Y-%m-%d-%H:%M:%S')},{source},{username},{dest_ip},{category},{method},{port},{domain},{uri},{filetype},{agent},{bytes_received},{bytes_sent}")
        
        current_time += time_increment

generate_dummy_log_data()