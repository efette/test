import socket
import json
import hashlib
import struct
import time
import threading
import time

pool_address = "stratum+tcp://btc.zsolo.bid"
pool_port = 6057
username = "34hYPbBwqM3N4FgXBSrh3euchZeZrKq7av.nonce-guesser"
password = "x"
num_threads = 12

# Do not edit below this if you don't know what you are doing. 
threads = []
hash_count = 0
start_time = time.time()
run_start_time = time.time()
stop_mining_event = threading.Event()
rejected = 0
accepted = 0

def sha256d(data):
    return hashlib.sha256(data).digest()

def connect_to_pool(pool_address, pool_port, timeout=30, retries=5):
    for attempt in range(retries):
        try:
            print(f"Attempting to connect to pool (Attempt {attempt + 1}/{retries})...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((pool_address, pool_port))
            print("Connected to pool!")
            return sock
        except socket.gaierror as e:
            print(f"Address-related error connecting to server: {e}")
        except socket.timeout as e:
            print(f"Connection timed out: {e}")
        except socket.error as e:
            print(f"Socket error: {e}")

        print(f"Retrying in 5 seconds...")
        time.sleep(5)
    
    raise Exception("Failed to connect to the pool after multiple attempts")

def send_message(sock, message):
    # print(f"Sending message: {message}")
    sock.sendall(json.dumps(message).encode('utf-8') + b'\n')

def receive_messages(sock, timeout=60):
    buffer = b''
    sock.settimeout(timeout)
    while True:
        try:
            chunk = sock.recv(2048)
            if not chunk:
                break
            buffer += chunk
            while b'\n' in buffer: 
                line, buffer = buffer.split(b'\n', 1)
                try:
                    decoded_line = line.decode('utf-8')
                    # print(f"Received message: {decoded_line}")
                    yield json.loads(decoded_line)
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}. Buffer state: {buffer}")
                    continue 
                except UnicodeDecodeError as e:
                    print(f"Error decoding UTF-8: {e}. Skipping invalid chunk.")
                    continue 
        except socket.timeout:
            print("Receive operation timed out. Retrying...")
            continue

def subscribe(sock):
    message = {
        "id": 1,
        "method": "mining.subscribe",
        "params": []
    }
    send_message(sock, message)
    for response in receive_messages(sock):
        if response['id'] == 1:
            print(f"Subscribed for jobs")
            return response['result']

def authorize(sock, username, password):
    message = {
        "id": 2,
        "method": "mining.authorize",
        "params": [username, password]
    }
    send_message(sock, message)
    for response in receive_messages(sock):
        if response['id'] == 2:
            return response['result']

def handle_connection_error(sock):
    print("Connection lost, attempting to reconnect...")
    sock.close()
    return connect_to_pool(pool_address, pool_port)

def submit_solution(sock, job_id, extranonce2, ntime, nonce):
    message = {
        "id": 4,
        "method": "mining.submit",
        "params": [username, job_id, extranonce2.hex(), ntime, struct.pack('<I', nonce).hex()]
    }
    try:
        send_message(sock, message)
        for response in receive_messages(sock):
            if response['id'] == 4:
                print("Submission response:", response)
                if response['result'] is None:
                    error_code = response.get('error', {})[0]
                    error_message = response.get('error', {})[1]
                    if error_code == 23: 
                        print(f"Low difficulty share: {error_message}")
                        return "low_diff"
                    else:
                        print(f"Submission error: {error_message} (code {error_code})")
                        return "error"
                return "accepted"
    except (socket.error, BrokenPipeError) as e:
        print(f"Error in submission: {e}. Reconnecting...")
        sock = handle_connection_error(sock)

def mine(sock, job, difficulty, extranonce1, extranonce2_size, nonce_start, nonce_end):
    global stop_mining_event, hash_count, start_time, rejected, accepted
    stop_mining_event.clear()
    job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs = job

    extranonce2_size = int(extranonce2_size)
    extranonce2 = struct.pack('<Q', 0)[:extranonce2_size]
    
    coinbase = (coinb1 + extranonce1 + extranonce2.hex() + coinb2).encode('utf-8')
    coinbase_hash_bin = sha256d(sha256d(coinbase))
    
    merkle_root = coinbase_hash_bin
    for branch in merkle_branch:
        merkle_root = sha256d(sha256d(merkle_root + bytes.fromhex(branch)))
    block_header = (version + prevhash + merkle_root[::-1].hex() + ntime + nbits).encode('utf-8')
    nonce = nonce_start

    while nonce < nonce_end:
        if stop_mining_event.is_set():
            return
        nonce_bin = struct.pack('<I', nonce)
        hash_result = sha256d(block_header + nonce_bin)
        hash_int = int.from_bytes(hash_result, byteorder='big')
        target_int = target_from_difficulty(difficulty)
        hash_count += 1
        if hash_int <= target_int:
            print(f"Nonce found: {nonce}")
            print(f"Hash: {hash_result[::-1].hex()}")
            result = submit_solution(sock, job_id, extranonce2, ntime, nonce)
            if result == "accepted":
                print("Solution accepted!")
                accepted += 1
                return
            elif result != "accepted":
                print("Solution rejected! Continue")
                rejected += 1
            elif result == "error":
                print("Encountered error during submission. Stopping mining for this job.")
                rejected += 1
                return
        nonce += 1

def target_from_difficulty(difficulty):
    max_target = 0xFFFF000000000000000000000000000000000000000000000000000000000000
    target = max_target // difficulty
    return target

def nbits_to_target(nbits_str):
    nbits = int(nbits_str, 16)
    exponent = nbits >> 24
    mantissa = nbits & 0xFFFFFF
    target = mantissa * (256 ** (exponent - 3))
    return target

def difficulty_from_target(target):
    max_target = 0xFFFF000000000000000000000000000000000000000000000000000000000000
    difficulty = max_target // target
    return difficulty

def start_mining_thread(sock, job, difficulty, extranonce1, extranonce2_size, nonce_start, nonce_end):
    global stop_mining_event
    mining_thread = threading.Thread(
        target=mine,
        args=(sock, job, difficulty, extranonce1, extranonce2_size, nonce_start, nonce_end)
    )
    mining_thread.start()
    return mining_thread

def start_mining(sock, job, difficulty, extranonce1, extranonce2_size, nonce_division):
    global threads, stop_mining_event
    stop_mining_event.set()  # Signal all threads to stop

    # Gracefully join threads
    for thread in threads:
        thread.join()
    threads = []  # Reset threads list

    # Start new mining threads
    for i in range(num_threads):  # Split into 4 threads
        nonce_start = i * nonce_division
        nonce_end = (i + 1) * nonce_division
        thread = start_mining_thread(
            sock, job, difficulty, extranonce1, extranonce2_size, nonce_start, nonce_end
        )
        threads.append(thread)


def notify():
    global hash_count, start_time, rejected, accepted
    while True:
        elapsed_time = time.time() - start_time
        if elapsed_time >= 1:  
            hashes_per_second = hash_count / elapsed_time
            mhashes_per_second = hashes_per_second / 1000
            print(f"Hashes per second: {mhashes_per_second:.2f} Mh/s")
            if rejected > 0:
                print(f"Rejected hashes: {rejected}")
            if accepted > 0:
                print(f"Accepted hashes: {accepted}")
            start_time = time.time()
            hash_count = 0

def start_notifications_thread():
    print("Starting notifications")
    notify_thread = threading.Thread(
        target=notify,
        args=()
    )
    notify_thread.start()
    return notify_thread


if __name__ == "__main__":
    if pool_address.startswith("stratum+tcp://"):
        pool_address = pool_address[len("stratum+tcp://"):]
    
    difficulty = None
    nonce_division = 2**32 // num_threads  # Example: Split the nonce range into 4 parts  # Keep track of threads
    started_mining = False
    while True:
        try:
            sock = connect_to_pool(pool_address, pool_port)
            
            extranonce = subscribe(sock)
            extranonce1, extranonce2_size = extranonce[1], extranonce[2]
            authorize(sock, username, password)
            notifications_thread = start_notifications_thread()
            while True:
                for response in receive_messages(sock):
                    if response['method'] == 'mining.set_difficulty':
                        difficulty = response['params'][0]
                        print(f"New Difficulty {response['params'][0]}")
                    if response['method'] == 'mining.notify':
                        try:
                            job = response['params']
                            if difficulty == None:
                                target = nbits_to_target(job[6])
                                difficulty = difficulty_from_target(target)
                                print(f"New Difficulty {difficulty}")
                            if difficulty != None:
                                if job[8] is False and not started_mining:
                                    started_mining = True
                                    start_mining(sock, job, difficulty, extranonce1, extranonce2_size, nonce_division)
                                elif job[8] is True and started_mining:
                                    start_mining(sock, job, difficulty, extranonce1, extranonce2_size, nonce_division)
                        except Exception as e:
                            print(f"Error while mining: {e}. Restarting job...")
                
                         
        except Exception as e:
            print(f"An error occurred: {e}. Reconnecting...")
            time.sleep(5)
