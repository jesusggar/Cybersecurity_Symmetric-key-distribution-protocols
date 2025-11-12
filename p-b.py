

from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("B->T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################

# (A realizar por el alumno/a...)
cifrado_TB = socket.recibir()
cifrado_mac_TB = socket.recibir()
cifrado_nonce_TB = socket.recibir()

datos_descifrado_TB = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce_TB, cifrado_TB, cifrado_mac_TB)

# Decodifica el contenido
json_TB = datos_descifrado_TB.decode("utf-8" ,"ignore")
print("T->B (descifrado): " + json_TB)
msg_TB = json.loads(json_TB)

# Extraigo el contenido
t_K1, t_K2, t_nb = msg_TB
t_K1 = bytearray.fromhex(t_K1)
t_K2 = bytearray.fromhex(t_K2)
t_nb = bytearray.fromhex(t_nb)

if t_nb != t_n_origen:
    print("Error: El nonce recibido de T con coincide con el de Bob")
    socket.cerrar()
    sys.exit()

print("Nonce de Bob verificado.")

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# (A realizar por el alumno/a...)
# Crear el socket de escucha de Alice (5552)
print("Esperando a Alice...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.escuchar()

cifrado_AB = socket.recibir()
nonce_A = socket.recibir()
hmac_A = socket.recibir()

#Comprobamos que el MAC coincide con el recibido
h_A = HMAC.new(t_K2, digestmod=SHA256)
h_A.update(cifrado_AB)
try:
    h_A.verify(hmac_A)
    print("HMAC del nombre verificado")
except ValueError:
    print("Error: HMAC del nombre no coincide con el de Alice")
    socket.cerrar()
    sys.exit()

aes_descifrado_AB = funciones_aes.iniciarAES_CTR_descifrado(t_K1, nonce_A)
datos_descifrado_AB = funciones_aes.descifrarAES_CTR(aes_descifrado_AB, cifrado_AB)

json_AB = datos_descifrado_AB.decode("utf-8" ,"ignore")
print("A->B (descifrado): " + json_AB)
msg_AB = json.loads(json_AB)

nombre = msg_AB

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)
aes_cifrado_BA, nonce_B = funciones_aes.iniciarAES_CTR_cifrado(t_K1)

msg_BA = []
msg_BA.append("Garcia")
msg_BA_json = json.dumps(msg_BA)
print("B -> A (descifrado): " + msg_BA_json)

cifrado_BA = funciones_aes.cifrarAES_CTR(aes_cifrado_BA, msg_BA_json.encode("utf-8"))

h_B = HMAC.new(t_K2, digestmod=SHA256)
h_B.update(cifrado_BA)
hmac_B = h_B.digest()

socket.enviar(cifrado_BA)
socket.enviar(nonce_B)
socket.enviar(hmac_B)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)
cifrado_AB_end = socket.recibir()
nonce_A_end = socket.recibir()
hmac_A_end = socket.recibir()

#Comprobamos que el MAC coincide con el recibido
h_A_end = HMAC.new(t_K2, digestmod=SHA256)
h_A_end.update(cifrado_AB_end)
try:
    h_A_end.verify(hmac_A_end)
    print("HMAC del nombre verificado")
except ValueError:
    print("Error: HMAC del nombre no coincide con el de Alice")
    socket.cerrar()
    sys.exit()

aes_descifrado_AB_end = funciones_aes.iniciarAES_CTR_descifrado(t_K1, nonce_A_end)
datos_descifrado_AB_end = funciones_aes.descifrarAES_CTR(aes_descifrado_AB_end, cifrado_AB_end)

json_AB_end = datos_descifrado_AB_end.decode("utf-8" ,"ignore")
print("A->B (descifrado): " + json_AB_end)
msg_AB_end = json.loads(json_AB_end)

end = msg_AB_end

if end[0] == "END":
    print("Recibido END. Cerrando conexion con Alice.")
    socket.cerrar()
else:
    print("Error: Se esperaba END pero se recibio otra cosa.")
    socket.cerrar()
    sys.exit()