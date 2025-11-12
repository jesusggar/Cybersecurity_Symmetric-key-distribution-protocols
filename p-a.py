
from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# (A realizar por el alumno/a...)
# Lee clave KAT
KAT = open("KAT.bin", "rb").read()

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

# (A realizar por el alumno/a...)
# Crear el socket de conexion con T (5550)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5550)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Alice")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("A -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

# (A realizar por el alumno/a...)
cifrado_TA = socket.recibir()
cifrado_mac_TA = socket.recibir()
cifrado_nonce_TA = socket.recibir()

datos_descifrado_TA = funciones_aes.descifrarAES_GCM(KAT, cifrado_nonce_TA, cifrado_TA, cifrado_mac_TA)

# Decodifica el contenido
json_TA = datos_descifrado_TA.decode("utf-8" ,"ignore")
print("T->A (descifrado): " + json_TA)
msg_TA = json.loads(json_TA)

# Extraigo el contenido
t_K1, t_K2, t_na = msg_TA
t_K1 = bytearray.fromhex(t_K1)
t_K2 = bytearray.fromhex(t_K2)
t_na = bytearray.fromhex(t_na)

if t_na != t_n_origen:
    print("Error: El nonce recibido de T con coincide con el de Alice")
    socket.cerrar()
    sys.exit()

print("Nonce de Alice verificado.")

# Cerramos el socket entre A y T, no lo utilizaremos mas
socket.cerrar() 

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# (A realizar por el alumno/a...)
# Crear el socket de conexion con B (5552)
print("Creando conexion con B...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.conectar()

aes_cifrado_AB, nonce_A = funciones_aes.iniciarAES_CTR_cifrado(t_K1)

msg_AB = []
msg_AB.append("Jesus")
msg_AB_json = json.dumps(msg_AB)
print("A -> B (descifrado): " + msg_AB_json)

cifrado_AB = funciones_aes.cifrarAES_CTR(aes_cifrado_AB, msg_AB_json.encode("utf-8"))

h_A = HMAC.new(t_K2, digestmod=SHA256)
h_A.update(cifrado_AB)
hmac_A = h_A.digest()

socket.enviar(cifrado_AB)
socket.enviar(nonce_A)
socket.enviar(hmac_A)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)
cifrado_BA = socket.recibir()
nonce_B = socket.recibir()
hmac_B = socket.recibir()

#Comprobamos que el MAC coincide con el recibido
h_B = HMAC.new(t_K2, digestmod=SHA256)
h_B.update(cifrado_BA)
try:
    h_B.verify(hmac_B)
    print("HMAC del apellido verificado")
except ValueError:
    print("Error: HMAC del apellido no coincide con el de Bob")
    socket.cerrar()
    sys.exit()

aes_descifrado_BA = funciones_aes.iniciarAES_CTR_descifrado(t_K1, nonce_B)
datos_descifrado_BA = funciones_aes.descifrarAES_CTR(aes_descifrado_BA, cifrado_BA)

json_BA = datos_descifrado_BA.decode("utf-8" ,"ignore")
print("B->A (descifrado): " + json_BA)
msg_BA = json.loads(json_BA)

apellido = msg_AB


# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)
aes_cifrado_AB_end, nonce_A_end = funciones_aes.iniciarAES_CTR_cifrado(t_K1)

msg_AB_end = []
msg_AB_end.append("END")
msg_AB_end_json = json.dumps(msg_AB_end)
print("A -> B (descifrado): " + msg_AB_end_json)

cifrado_AB_end = funciones_aes.cifrarAES_CTR(aes_cifrado_AB_end, msg_AB_end_json.encode("utf-8"))

h_A_end = HMAC.new(t_K2, digestmod=SHA256)
h_A_end.update(cifrado_AB_end)
hmac_A_end = h_A_end.digest()

socket.enviar(cifrado_AB_end)
socket.enviar(nonce_A_end)
socket.enviar(hmac_A_end)

socket.cerrar()
