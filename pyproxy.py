import sys
import socket 
import threading

HEX_FILTER = ''.join(
        [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

def hexdump(src, length=16, show=True):
    if isintance(src, bytes): #if it is in bytes format, we want to decode it
        src = src.decode()
    results = list()
    for i in range(0, len(src), length):
        word = str(src[i:i+length])
        printable = word.translate(HEX_FILTER) #translate method based on the HEX filter, so will export printable alphabets
        hexa = ''.join([f'{ord(c):02X}' for c in word]) #to get the hexadecimal showed earlier in the hex/text format
        hexwidth = length*3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    if show:
        for line in results:
            print(line)
        else:
            return results

def receive_from(connection):
    buffer = b""
    connection.settimeout(20)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break

            buffer += data
    except Exception as e:
        print('error', e)
        pass

    return buffer

def request_handler(buffer): #perform packet modifications , finding creds
        return buffer

def response_handler(buffer): #perform packet modifications
        return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))
    
    if receive_first: #this is for protocoles that first will send you a banner before any communications like FTP
        remote_buffer = receive_first(remote_socket)
        if len(remote_buffer):
            print("[<==] Recived %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[==>] Sent to local.")

    While True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print("[<==] Recived %d bytes from local." % len(local_buffer))
            hexdump(local_buffer)

            local_buffer = response_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[==>] Sent to local.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] no more data. Closing the conneciton.")
            break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print("[!!] Failed to listen on $s:%d" % (local_host, local_port))
        print("[!!] Check for other listerning sockets or conttect permissions.")
        print(e)
        sys.exit(0)

    print("[*] listening on %s:%d" % (local_host, local_port))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        print("> Received incoming connection from %s:%d" % (addr[0], addr[1]))

        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first)
                )
        proxy_thread.start()

def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport]", end="")
        print("[remotehost] [remoteport] [reveivefirst]")
        print("Example: ./pyproxy.py 127.0.0.1 9000 10.12.132.1 9000 True")

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()
        
