# 🧅 OnionChat

**Chat de terminal con cifrado de extremo a extremo, servidor de reenvío ciego y soporte nativo para servicios ocultos de Tor.**

![Python 3](https://img.shields.io/badge/Python-3-3776AB?logo=python&logoColor=white)
![Cifrado](https://img.shields.io/badge/Cifrado-AES--256--GCM-2ea44f)
![Tor](https://img.shields.io/badge/Tor-Hidden%20Service-7D4698?logo=torproject&logoColor=white)
![Licencia](https://img.shields.io/badge/Licencia-por%20definir-lightgrey)

---

## Tabla de contenidos

- [Descripción general](#descripción-general)
- [Arquitectura](#arquitectura)
- [Características principales](#características-principales)
- [Instalación](#instalación)
- [Guía de uso](#guía-de-uso)
  - [Servidor](#servidor)
  - [Exponer el servidor como servicio oculto de Tor](#exponer-el-servidor-como-servicio-oculto-de-tor)
  - [Cliente](#cliente)
- [Comandos del chat](#comandos-del-chat)
- [Transferencia de archivos](#transferencia-de-archivos)
- [Modelo de seguridad y advertencias](#modelo-de-seguridad-y-advertencias)
- [Archivos generados](#archivos-generados)
- [Solución de problemas](#solución-de-problemas)

---

## Descripción general

OnionChat se compone de dos programas:

- **`server.py`**: un *blind relay* (relé ciego). Recibe líneas de texto en Base64 de un cliente y las reenvía al resto de clientes conectados. **No conoce las claves y no puede leer el contenido**: solo ve bloques cifrados.
- **`client.py`**: un cliente con interfaz de terminal (TUI) construida con [`rich`](https://github.com/Textualize/rich). Cifra y descifra los mensajes localmente, gestiona el historial cifrado, envía y recibe archivos, y se conecta directamente o a través de Tor.

La clave de cifrado se deriva de una **contraseña de sala** que comparten los participantes. Esa contraseña nunca se envía al servidor.

## Arquitectura

```
 ┌────────────┐   texto cifrado    ┌──────────────┐   texto cifrado    ┌────────────┐
 │  Cliente A │ ─────────────────► │  server.py   │ ─────────────────► │  Cliente B │
 │ (cifra y   │  (AES-256-GCM,     │ (relé ciego: │  (AES-256-GCM,     │ (descifra  │
 │  descifra) │   en Base64)       │  sin claves) │   en Base64)       │  y cifra)  │
 └────────────┘                    └──────────────┘                    └────────────┘
        │                                 ▲
        └── opcional: SOCKS5 → Tor ───────┘  (servicio oculto .onion)
```

Puntos clave del diseño:

- El servidor escucha por defecto solo en `127.0.0.1`. Para acceso remoto se expone mediante un servicio oculto de Tor (ver [más abajo](#exponer-el-servidor-como-servicio-oculto-de-tor)).
- Cada mensaje es un objeto JSON cifrado con AES-256-GCM y codificado en Base64; viaja como una línea terminada en salto de línea.
- El nombre de usuario y el tipo de mensaje van **dentro** del contenido cifrado, por lo que el servidor tampoco los ve.
- El servidor solo reenvía líneas que sean Base64 válido, lo que impide que un cliente inyecte líneas de control a los demás.
- Cada cliente tiene su propia cola y su propio hilo de escritura en el servidor, de modo que un cliente lento no bloquea a los demás.

## Características principales

- 🔒 **Cifrado de extremo a extremo** con AES-256-GCM (confidencialidad e integridad). La clave se obtiene de la contraseña de sala con **scrypt** (`n=2^15, r=8, p=1`).
- 🙈 **Servidor ciego**: solo reenvía datos cifrados; no tiene acceso a claves ni a texto en claro.
- 🧅 **Soporte automático para Tor**: las direcciones `.onion` usan Tor sin configuración extra. El cliente detecta el proxy SOCKS5 probando el puerto `9050` (demonio de Tor) y después `9150` (Tor Browser). La resolución de nombres también pasa por Tor.
- 🗄️ **Historial local cifrado** en SQLite: cada mensaje se guarda cifrado con AES-256-GCM usando una contraseña maestra (derivada con scrypt y una sal aleatoria por base de datos). El historial se organiza por servidor.
- 📁 **Transferencia de archivos fragmentada (*chunked*)**: bloques de 64 KB, varios archivos por comando, verificación de integridad **SHA-256** y escritura directa a disco (los archivos grandes no se cargan en memoria).
- 🖥️ **Interfaz TUI** con `rich`: panel de chat con colores por remitente, caja de entrada, barra de estado (estado de conexión, latencia, progreso de transferencias).
- 🔀 **Cambio de servidor en caliente** con `/connect`, sin cerrar el programa ni editar código.
- 📋 **Registro (*logging*)** con marcas de tiempo y niveles, tanto en servidor como en cliente.
- 🧹 **Saneamiento de entradas de red**: se eliminan caracteres de control y secuencias de escape ANSI de lo que llega por la red.

## Instalación

**Requisitos:** Python 3, `pip`, y (para usar Tor) un proxy Tor en ejecución en el cliente.

Dependencias (`requirements.txt`):

```text
cryptography
rich
PySocks
```

### Opción A: scripts de instalación automática

<!-- TODO: verificar y completar con el comportamiento real de setup_server.sh / setup_client.sh
     (qué instalan, si requieren sudo, si aceptan argumentos). Solo se documenta la invocación básica. -->

```bash
# En la máquina del servidor
chmod +x setup_server.sh
./setup_server.sh

# En la máquina del cliente
chmod +x setup_client.sh
./setup_client.sh
```

### Opción B: instalación manual

```bash
git clone <URL-DE-TU-REPOSITORIO> onionchat
cd onionchat

python3 -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate

pip install -r requirements.txt
```

Para conectarte a servidores `.onion` en el cliente, instala también Tor:

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install tor
sudo systemctl enable --now tor
```

## Guía de uso

### Servidor

Levantar el servidor en local (escucha en `127.0.0.1:5000`):

```bash
python3 server.py
```

Opciones disponibles:

| Flag | Por defecto | Descripción |
|---|---|---|
| `--ip` | `127.0.0.1` | IP en la que escuchar. **No uses `0.0.0.0` junto con Tor.** |
| `--port` | `5000` | Puerto TCP. |
| `--max-clients` | `50` | Número máximo de clientes simultáneos. |
| `--log` | `onionchat.log` | Archivo de log. |
| `--verbose` | desactivado | Registra también el reenvío de cada fragmento de archivo. |

Ejemplo con otro puerto y log:

```bash
python3 server.py --port 6000 --log /var/log/onionchat.log
```

El servidor es un relé: **no tiene consola de chat**. Para hablar desde la misma máquina, abre un cliente aparte. Se detiene con `Ctrl+C`.

### Exponer el servidor como servicio oculto de Tor

1. Instala Tor en la máquina del servidor:

   ```bash
   sudo apt update && sudo apt install tor
   ```

2. Añade el servicio oculto al final de `/etc/tor/torrc`:

   ```text
   HiddenServiceDir /var/lib/tor/onionchat/
   HiddenServicePort 5000 127.0.0.1:5000
   ```

   El segundo número (`127.0.0.1:5000`) debe coincidir con la IP y el puerto en los que escucha `server.py`.

3. Reinicia Tor y lee tu dirección `.onion`:

   ```bash
   sudo systemctl restart tor
   sudo cat /var/lib/tor/onionchat/hostname
   ```

4. Arranca el servidor (sigue escuchando solo en `127.0.0.1`):

   ```bash
   python3 server.py
   ```

5. Comparte con los participantes la dirección `.onion` **y** la contraseña de sala, cada una por un canal adecuado (ver [advertencias](#modelo-de-seguridad-y-advertencias)).

> ⚠️ Guarda el contenido de `HiddenServiceDir` (en especial las claves): quien lo tenga puede suplantar tu dirección `.onion`.

### Cliente

Iniciar el cliente (te pregunta a qué servidor conectarte):

```bash
python3 client.py
```

Conectar directamente a un servidor indicado como argumento:

```bash
# Servidor normal
python3 client.py ejemplo.com:5000

# Servidor local
python3 client.py 127.0.0.1:5000

# Servicio oculto de Tor: las direcciones .onion usan Tor automáticamente
python3 client.py abcdefghijklmnop.onion:5000
```

Si no indicas puerto, se usa `5000`.

Al arrancar, el cliente pide por orden:

1. **Tu nombre** (hasta 20 caracteres).
2. **Contraseña maestra del historial local** (vacía = sin historial).
3. **Servidor** (si no lo pasaste como argumento; por defecto `127.0.0.1:5000`).
4. **Contraseña de la sala** de ese servidor (entrada oculta).

Opciones disponibles:

| Flag | Por defecto | Descripción |
|---|---|---|
| `server` (posicional) | se pregunta | `host[:puerto]` al que unirse. |
| `--tor` | desactivado | Fuerza el uso de Tor (SOCKS5) para cualquier host. Los `.onion` lo usan siempre. |
| `--tor-host` | `127.0.0.1` | Dirección del proxy SOCKS5 de Tor. |
| `--tor-port` | autodetección | Puerto SOCKS de Tor. Si no se indica, prueba `9050` y luego `9150`. |
| `--db` | `onionchat_history.db` | Archivo del historial cifrado. |
| `--max-file-mb` | `25` | Tamaño máximo (MB) de los archivos que envías o aceptas. |
| `--downloads` | `downloads` | Carpeta donde se guardan los archivos recibidos. |
| `--log` | `onionchat-client.log` | Archivo de log del cliente. |

Ejemplos:

```bash
# Forzar Tor hacia un host normal, con Tor Browser (puerto 9150)
python3 client.py ejemplo.com:5000 --tor --tor-port 9150

# Dos identidades en la misma carpeta, con historiales separados
python3 client.py 127.0.0.1:5000 --db alice.db --downloads descargas_alice

# Aceptar y enviar archivos de hasta 100 MB
python3 client.py abcdefghijklmnop.onion --max-file-mb 100
```

## Comandos del chat

Todo lo que escribas sin `/` se envía como mensaje a la sala.

| Comando | Descripción |
|---|---|
| `/help` | Muestra la lista de comandos. |
| `/status` | Muestra el estado de la conexión, el servidor, la ruta (directa o por Tor), la latencia, el tráfico, las transferencias activas, el cifrado y el historial. |
| `/clear` | Limpia la pantalla. No borra el historial guardado. |
| `/file <ruta> [ruta ...]` | Envía uno o varios archivos. Admite varias rutas, comillas, comodines (`*.png`) y carpetas (solo los archivos del primer nivel). Máximo 50 archivos por comando. |
| `/connect [host[:puerto]]` | Cambia a otro servidor sin cerrar el programa. Pide la contraseña de sala (entrada oculta) si no la conoce aún en esta sesión. Sin argumentos, reconecta al servidor actual. Si falla, mantiene la conexión actual. |
| `/password` | Cambia la contraseña de sala del servidor actual (entrada oculta). Útil si los mensajes salen como no descifrables. |
| `/exit` (o `/quit`) | Cierra el cliente. `Ctrl+C` también funciona. |

## Transferencia de archivos

- Los archivos se dividen en fragmentos de **64 KB**, cada uno cifrado igual que un mensaje.
- Tamaño máximo por defecto: **25 MB** por archivo (`--max-file-mb`). Los archivos vacíos se omiten.
- El receptor escribe los fragmentos a disco en un archivo temporal `.part` y, al terminar, verifica el **SHA-256**. Si no coincide, descarta el archivo.
- Los archivos se guardan en `downloads/` (o la carpeta de `--downloads`). **Nunca se sobrescribe un archivo existente**: si el nombre ya existe se guarda como `nombre_1.ext`, `nombre_2.ext`, etc. Los nombres se sanean antes de escribirlos.
- Se aceptan hasta 4 transferencias entrantes simultáneas; una transferencia sin datos durante 120 segundos se cancela.
- Si la conexión se interrumpe, la transferencia se cancela (no hay reanudación).
- El progreso aparece en la barra de estado (`TX` = enviando, `RX` = recibiendo).
- Quien recibe aplica **su propio** límite de tamaño: si es menor que el del emisor, rechaza el archivo y lo avisa.

## Modelo de seguridad y advertencias

### Qué protege OnionChat

| Propiedad | Cómo |
|---|---|
| **Confidencialidad del contenido** | Mensajes y archivos se cifran en el cliente con AES-256-GCM; el servidor solo ve texto cifrado. |
| **Integridad del contenido** | AES-GCM detecta cualquier modificación; los archivos además se verifican con SHA-256. |
| **Ocultamiento de la IP** | Con Tor, el servidor no conoce la IP real de los clientes y los clientes no conocen la del servidor. |
| **Historial en reposo** | El historial local está cifrado con tu contraseña maestra. |
| **Contraseña de sala fuera del servidor** | Se usa solo localmente para derivar la clave; nunca se transmite. |

### Qué debes tener en cuenta

- **Comparte la contraseña de sala por un canal seguro fuera de banda** (en persona, o por otro medio cifrado), nunca por el propio chat ni junto a la dirección del servidor por un canal inseguro. Quien la conozca puede leer y escribir en la sala.
- **Usa una contraseña larga y única.** Toda la seguridad depende de ella: una contraseña débil puede ser adivinada por fuerza bruta.
- **Sin secreto hacia adelante (*forward secrecy*)**: la clave de sala es fija. Si alguien obtiene la contraseña, puede descifrar también el tráfico que haya guardado antes.
- **Sin protección contra repetición (*replay*)**: un atacante con acceso al tráfico podría reenviar mensajes cifrados capturados.
- **Los nombres no están autenticados**: cualquiera con la contraseña de sala puede usar el nombre que quiera, incluido el tuyo.
- **Sal fija para la clave de sala**: la misma contraseña produce la misma clave en cualquier servidor. No reutilices la contraseña de sala en otros sitios ni entre salas.
- **Metadatos visibles**: el servidor ve cuándo se conecta cada cliente, el tamaño y la frecuencia de los mensajes y las direcciones de origen (con Tor, la del propio proceso de Tor). La medición de latencia (`PING`/`PONG`) viaja sin cifrar.
- **Archivos recibidos**: se guardan automáticamente en la carpeta de descargas. Nunca se ejecutan, pero **no abras archivos de personas que no conozcas**.
- **Logs**: el servidor y el cliente registran metadatos (conexiones, tamaños, nombres de remitentes y de archivos, marcas de tiempo), **no el contenido de los mensajes**. Protege esos archivos si el anonimato es importante.
- **No expongas el servidor en `0.0.0.0` con Tor**: déjalo en `127.0.0.1` para que solo sea accesible a través del servicio oculto.
- **Es un proyecto sin auditoría externa.** No lo uses como única defensa en situaciones de riesgo real.
- Probado en Linux. El cliente incluye soporte para el teclado de Windows, pero no ha sido probado allí.

## Archivos generados

| Archivo | Generado por | Contenido |
|---|---|---|
| `onionchat.log` | servidor | Conexiones, desconexiones, errores y tamaños de reenvío (sin contenido). |
| `onionchat-client.log` | cliente | Eventos de conexión, errores y metadatos de mensajes y archivos (sin contenido). |
| `onionchat_history.db` | cliente | Historial SQLite con cada mensaje cifrado. |
| `downloads/` | cliente | Archivos recibidos. |

## Solución de problemas

| Síntoma | Causa probable / solución |
|---|---|
| `Missing dependencies` al arrancar el cliente | Ejecuta `pip install -r requirements.txt`. |
| `connection refused` | El servidor no está en marcha o el puerto no coincide. |
| `no Tor proxy found` | Tor no está en ejecución. Inícialo (`sudo systemctl start tor`) o abre Tor Browser, o indica el puerto con `--tor-port`. |
| `PySocks is required for Tor` | `pip install PySocks`. |
| Aviso de mensajes que no se pueden descifrar | Alguien usa otra contraseña de sala. Usa `/password` o acuerda la contraseña correcta. |
| `wrong master password for this history file` | La contraseña maestra no corresponde a ese `--db`. Usa otro archivo con `--db`, bórralo, o deja la contraseña vacía. |
| `Address already in use` al iniciar el servidor | Otro proceso usa el puerto; cambia `--port` o ciérralo. |
