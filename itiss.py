import socket
import threading
import sys
import time

connected_clients = []
UDP_PORT = 5556 
TCP_PORT = 5555 

def scramble_text(message, key="docx_key_99"):
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(message))

def host_discovery(room_id):
    """Runs on the Host: Listens for people looking for this Room ID and replies."""
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(('0.0.0.0', UDP_PORT))
    
    while True:
        try:
            data, addr = udp_sock.recvfrom(1024)
            request = data.decode('utf-8')
            if request == f"FIND_ROOM:{room_id}":
                udp_sock.sendto(b"ROOM_FOUND", addr)
        except:
            pass

def find_room_ip(room_id):
    """Runs on the Client: Shouts across the network to find the Host's IP."""
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_sock.settimeout(3.0) 
    
    broadcast_msg = f"FIND_ROOM:{room_id}".encode('utf-8')
    try:
        udp_sock.sendto(broadcast_msg, ('255.255.255.255', UDP_PORT))
    except Exception as e:
        print(f"[!] Broadcast error. Network might restrict UDP.")
        return None

    try:
        data, addr = udp_sock.recvfrom(1024)
        if data.decode('utf-8') == "ROOM_FOUND":
            return addr[0]
    except socket.timeout:
        return None
    return None
def broadcast_message(message, sender_socket):
    for client in connected_clients:
        if client != sender_socket:
            try:
                client.send(message)
            except:
                client.close()
                if client in connected_clients:
                    connected_clients.remove(client)

def handle_client(conn):
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            broadcast_message(data, conn)
        except:
            break
    conn.close()
    if conn in connected_clients:
        connected_clients.remove(conn)

def server_switchboard():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', TCP_PORT))
    s.listen(20)
    while True:
        conn, addr = s.accept()
        connected_clients.append(conn)
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

def receive_messages(sock, my_name):
    while True:
        try:
            data = sock.recv(1024).decode('utf-8')
            if not data:
                break
            decrypted_msg = scramble_text(data)
            sys.stdout.write('\r\033[K') 
            print(f"\n{decrypted_msg}")
            sys.stdout.write(f"[{my_name}] -> ")
            sys.stdout.flush()
        except:
            print("\n[!] Connection lost.")
            break

# --- MAIN TERMINAL UI ---
def start_terminal():
    print("===Group Network===")
    print("1. Host a Room")
    print("2. Join a Room")
    choice = input("Select operation mode (1/2): ")
    my_name = input("Enter your display name: ")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if choice == '1':
        room_id = input("Create a 4-digit Room ID (e.g., 7777): ")
        
        # 1. Start the Chat Server
        threading.Thread(target=server_switchboard, daemon=True).start()
        
        # 2. Start the Discovery Engine so others can find the room
        threading.Thread(target=host_discovery, args=(room_id,), daemon=True).start()
        
        time.sleep(0.5)
        s.connect(('127.0.0.1', TCP_PORT))
        print(f"[*] Room {room_id} is live! Waiting for others to join...")
        
    elif choice == '2':
        room_id = input("Enter the 4-digit Room ID: ")
        print("[*] Scanning local network for room...")
        
        # Use the Discovery Engine to automatically find the Host's IP
        host_ip = find_room_ip(room_id)
        
        if host_ip:
            try:
                s.connect((host_ip, TCP_PORT))
                print(f"[*] Found room at {host_ip}! Connected.")
            except:
                print("[!] Found the room, but TCP connection was blocked.")
                return
        else:
            print(f"[!] Could not find Room {room_id}. Ensure the Host is running.")
            return
    else:
        print("Invalid input.")
        return

    threading.Thread(target=receive_messages, args=(s, my_name), daemon=True).start()
    time.sleep(0.5)
    print("\n(Chat room active. All messages are encrypted.)")
    
    while True:
        try:
            msg = input(f"[{my_name}] -> ")
            if msg.lower() in ['exit', 'quit']:
                print("[*] Leaving room...")
                s.close()
                break
            formatted_msg = f"[{my_name}]: {msg}"
            encrypted_msg = scramble_text(formatted_msg)
            s.send(encrypted_msg.encode('utf-8'))
        except KeyboardInterrupt:
            print("\n[*] Emergency shutdown initiated...")
            s.close()
            break

if __name__ == "__main__":
    if sys.platform.startswith('win'):
        import os
        os.system('cls')
    start_terminal()
