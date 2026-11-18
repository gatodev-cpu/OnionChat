import socket

class Cliente():
    def __init__(self):
        self.ip = "127.0.0.1"
        self.port = 5000
    
    def conectar(self):
     with socket.create_connection((self.ip, self.port)) as c:
       while True:
        c.sendall(input("> ").encode('utf-8'))
        print("[Server]:", c.recv(1024).decode('utf-8'))

if __name__ == '__main__':
    Cliente().conectar()
    