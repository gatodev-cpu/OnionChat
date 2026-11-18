import socket


class Servidor:
    def __init__(self, ip='127.0.0.1', puerto=5000):
        self.ip_servidor = ip
        self.puerto = puerto
    
    def portada(self):
        print(r"""
                            ~
                           /~
                     \  \ /**
                      \ ////
                      // //
                     // //
                   ///&//
                  / & /\ \
                /  & .,,  \
              /& %  :       \
            /&  %   :  ;     `\
           /&' &..%   !..    `.\
          /&' : &''" !  ``. : `.\
         /#' % :  "" * .   : : `.\
        I# :& :  !"  *  `.  : ::  I
        I &% : : !%.` '. . : : :  I
        I && :%: .&.   . . : :  : I
        I %&&&%%: WW. .%. : :     I
         \&&&##%%%`W! & '  :   ,'/
          \####ITO%% W &..'  #,'/
            \W&&##%%&&&&### %./
              \###j[\##//##}/
                 ++///~~\//_
                  \\ \ \ \  \_
                  /  /    \ 
                       _             
                      (_)            
            ___  _ __  _  ___  _ __  
           / _ \| '_ \| |/ _ \| '_ \ 
          | (_) | | | | | (_) | | | |
           \___/|_| |_|_|\___/|_| |_|
                           
""")
    def iniciar(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
            servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            servidor.bind((self.ip_servidor, self.puerto))
            servidor.listen(1)

            print(f"[+] Servidor iniciado en {self.ip_servidor}:{self.puerto}")
            print("[+] Esperando conexiones...")

            try:
                conexion, direccion = servidor.accept()
                with conexion:
                    print(f"[+] Cliente conectado: {direccion}")
                    while True:
                        mensaje = conexion.recv(1024).decode('utf-8')
                        if not mensaje:
                            print("\n[*] El cliente se desconectó.")
                            break
                        print(f"\n[Mensaje recibido]: {mensaje}")

                        respuesta = input("> ")
                        conexion.sendall(respuesta.encode('utf-8'))
            except (KeyboardInterrupt, ConnectionResetError):
                print("\n[*] Cerrando servidor...")


if __name__ == '__main__':
    Servidor().portada()
    Servidor().iniciar()