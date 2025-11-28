︠48db5505-e870-4b8d-b454-74300134518a︠

︡40126165-7d78-478d-93eb-72ff6d0e8cb5︡{"stdout":"你妈妈很胖\n"}︡{"done":true}
︠e9e0e6aa-6dd7-4599-9050-225400c516e6︠

# Objetivo: Implementar un sistema de autenticación funcional basado en HMAC, integrando múltiples funciones hash (MD5, SHA-256 y SHA-3) y comparando su rendimiento y nivel de seguridad, acompañado de una interfaz de usuario que permita visualizar el proceso de autenticación y la verificación de integridad y autenticidad del mensaje.

import hmac
import hashlib
import secrets
import time
import json
︡3fca5ae4-ca7d-44e4-a316-36303c1fc4aa︡{"done":true}
︠23f1a519-e09d-475d-b674-71255840b9eb︠
# 1) Algoritmos de hash soportados

ALGORITHMS = {
    "MD5": hashlib.md5,
    "SHA256": hashlib.sha256,
    "SHA3_256": hashlib.sha3_256,
    # "WHIRLPOOL": ...  # para Whirlpool necesitarías una librería externa (p.ej. pycryptodome)
}


# Obtiene la función de hash de hashlib dada una etiqueta. Si el nombre no está en el diccionario ALGORITHMS, no lo acepta.
def get_hash_func(name: str):
    if name not in ALGORITHMS:                  # Para los algoritmos de hash que no existen en ALGORITHMS
        raise ValueError(f"Algoritmo no soportado: {name}")
    return ALGORITHMS[name]
︡7d8dd334-81a2-430b-8cf1-bdcf13da8873︡{"done":true}
︠f22338b4-ced1-49ac-8700-15274b825aec︠
#2) Helpers para formatos

# Helper para canonizar el payload. Payload canonico: JSON del payload pasado a una forma fija y única en bytes
# Para que el payload tenga una única representación. Si el mismo mensaje puede tener dos strings distintos, el hash (y el HMAC) cambiarían aunque el contenido sea “igual”.
def canon_payload(payload):
    # Es un diccionario vacio si no tiene datos.
    if payload is None:
        payload = {}
    # convierte el dict a un string JSON. y que no ponga espacios despues de , y :. Con claves ordenadas alfabéticamente (para evitar que HMAC cambie porque los formatos están en orden distinto) y el utf-8 convierte el String a bytes, que es lo que consume las funciones de Hash y HMAC
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


# Construye la cadena canónica: username|ts|nonce|op|HASH(payload_min)

# op = Operation (LOGIN, TRANSFER)


# Retorna una String canonica en bytes
def make_request_string(username, ts, nonce, op, payload, hash_func):
    payload_bytes = canon_payload(payload)
    payload_hash = hash_func(payload_bytes).hexdigest()
    s = f"{username}|{ts}|{nonce}|{op}|{payload_hash}"
    return s.encode("utf-8")


#  Calcula HMAC(key, message) con el hash indicado. Se crea un objeto con la key, mensaje y la función hash. Con hexdigest() devuelve el HMAC en string hexadecimal.
def compute_hmac(key: bytes, message: bytes, hash_func):
    return hmac.new(key, message, hash_func).hexdigest()
︡74288797-0583-47db-acdd-ea06bc2401a4︡{"done":true}
︠00064dcf-56bd-47c3-bd51-e7c686b82074︠
# 3) “Base de datos” de usuarios (demo) el cual es un diccionario

USERS = {
    # En un sistema real, K_user (clave secreta simetrica) se generaría y almacenaría en un lugar seguro. Lo comparte el usuario y el servidor.
    # genera 32 bytes criptográficamente aleatorios
    "alice": secrets.token_bytes(32),
    "bob": secrets.token_bytes(32),
}

USED_NONCES = set()  # pares (username, nonce) ya usados. Para evitar replay attacks.
WINDOW = 60          # ventana temporal en segundos que se acepta para el Timestamp
︡3f92b8cc-c63c-492e-b736-37940afb8d17︡{"done":true}
︠77dd9659-78b6-45c6-8a7b-ddc32ac61d33︠
# 4) Cliente: construye AuthRequest


#Construye un mensaje de autenticación:
#{
#   username, ts, nonce, op, payload, alg, mac
#}

# retorna un request autenticada del cliente.
def build_auth_request(username: str, alg_name: str, payload=None):
    if username not in USERS:            # Para los usuarios que no existen en la DB USERS.
        raise ValueError("Usuario desconocido en este demo (USERS)")

    key = USERS[username]                  # Recupera la clave asociada al usuario
    hash_func = get_hash_func(alg_name)    # Usa la función hash

    ts = int(time.time())          # Empieza el timestamp en entero para enviarlo más simple (facil de comparar).
    nonce = secrets.token_hex(16)  # 16 bytes -> 32 hex chars
    op = "AUTH"

    msg = make_request_string(username, ts, nonce, op, payload, hash_func)         # String canonica en bytes
    mac = compute_hmac(key, msg, hash_func)                                        # El HMAC de esa string canonica. El cual sirve para verificar. Si se cambia el contenido del mensaje, no calzaria el HASH.

    request = {
        "username": username,
        "ts": ts,                          # Timestamp, la hora en que se creó el mensaje.
        "nonce": nonce,
        "op": op,
        "payload": payload or {},
        "alg": alg_name,
        "mac": mac,
    }
    return request
︡dc36ae9c-7012-4b48-8479-3c6f1d828441︡{"done":true}
︠ca0e0609-8618-4036-af05-6875195b85a8︠
# 5) Servidor: verifica AuthRequest y responde AuthResponse

#Verifica el HMAC y las condiciones básicas.
#Retorna un dict tipo AuthResponse:
#  { status, server_ts, nonce, alg, mac_resp, err? }

def verify_auth_request(request: dict):
    username = request.get("username")
    ts = request.get("ts")
    nonce = request.get("nonce")
    op = request.get("op")
    payload = request.get("payload")
    alg_name = request.get("alg")
    mac_cli = request.get("mac")

    now = int(time.time())                                        # Fija la hora actual

    # 1) Usuario
    if username not in USERS:
        return {"status": "FAIL", "err": "ERR_USER_UNKNOWN"}

    key = USERS[username]

    # 2) Algoritmo
    try:
        hash_func = get_hash_func(alg_name)
    except ValueError:
        return {"status": "FAIL", "err": "ERR_ALG_UNSUPPORTED"}

    # 3) Ventana temporal
    if abs(now - ts) > WINDOW:                                     # Rechaza si el mensaje es muy viejo o muy adelantado (ts > now) si esa diferencia es mayor que 60 segundos, con ayuda del valor absoluto para diferencias negativas.
        return {"status": "FAIL", "err": "ERR_TIME_SKEW"}

    # 4) Replay (nonce)
    if (username, nonce) in USED_NONCES:                           # Falla si ese Nonce se usó.
        return {"status": "FAIL", "err": "ERR_NONCE_REPLAY"}

    # 5) Verificar HMAC
    msg = make_request_string(username, ts, nonce, op, payload, hash_func)
    mac_srv = compute_hmac(key, msg, hash_func)

    if not hmac.compare_digest(mac_cli, mac_srv):                   # si el HMAC que mandó el cliente es distinto al HMAC recien calculado,
        return {"status": "FAIL", "err": "ERR_MAC_INVALID"}

    # Si todo OK, registrar nonce y responder
    USED_NONCES.add((username, nonce))
    server_ts = now                                            # Timestamp del servidor para la respuesta
    resp_str = f"OK|{server_ts}|{nonce}".encode("utf-8")
    mac_resp = compute_hmac(key, resp_str, hash_func)

    # No se envia el resp_str porque el usuario puede armar el mismo formato de resp_str con las componentes que vienen de la respuesta y hacer el HMAC para comparar.
    response = {
        "status": "OK",
        "server_ts": server_ts,
        "nonce": nonce,
        "alg": alg_name,
        "mac_resp": mac_resp,
    }
    return response
︡0b0de76d-59f2-428e-84f9-8379b2c033f8︡{"done":true}
︠67f755f1-1c42-4832-96b4-3700ee69c24as︠
# 6) Demo rápida del prototipo

# Probar con distintos algoritmos
for alg in ["MD5", "SHA256", "SHA3_256"]:
    print(f"\n=== Prueba de autenticación con {alg} ===")
    req = build_auth_request("alice", alg, {"note": "hola mundo"})
    print("Request:", req)

    resp = verify_auth_request(req)
    print("Response:", resp)

    # Intentar replay (mismo mensaje)
    resp2 = verify_auth_request(req)
    print("Replay attempt:", resp2)
︡1a4209f8-7770-409a-ab36-f8be3dc25e33︡{"stdout":"\n=== Prueba de autenticación con MD5 ===\nRequest: {'username': 'alice', 'ts': 1763340075, 'nonce': 'd51e00f42ab92594fb2a8ea962a6e009', 'op': 'AUTH', 'payload': {'note': 'hola mundo'}, 'alg': 'MD5', 'mac': 'c3fc1f838121367a4971a8ea9eb9f592'}\nResponse: {'status': 'OK', 'server_ts': 1763340075, 'nonce': 'd51e00f42ab92594fb2a8ea962a6e009', 'alg': 'MD5', 'mac_resp': '1e62e9633f45ffb89be89c255f37fb09'}\nReplay attempt: {'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}\n\n=== Prueba de autenticación con SHA256 ===\nRequest: {'username': 'alice', 'ts': 1763340075, 'nonce': 'b0454ad96fbb3b18970d2b44d7bac48e', 'op': 'AUTH', 'payload': {'note': 'hola mundo'}, 'alg': 'SHA256', 'mac': '5a27666cc9cfb740a9f288c23dc92f2dc784f7bf0ad8c68901f241eaeecf6e4c'}\nResponse: {'status': 'OK', 'server_ts': 1763340075, 'nonce': 'b0454ad96fbb3b18970d2b44d7bac48e', 'alg': 'SHA256', 'mac_resp': '493351369c147c049dfa1888664577ff6dd3339ea1d33098971817c26c985f5b'}\nReplay attempt: {'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}\n\n=== Prueba de autenticación con SHA3_256 ===\nRequest: {'username': 'alice', 'ts': 1763340075, 'nonce': '51d1c4b48bfae5ab551c0baf915cdd32', 'op': 'AUTH', 'payload': {'note': 'hola mundo'}, 'alg': 'SHA3_256', 'mac': '15f54d133f457fbf28c9e3b9a4abc4af27a997d147b7c4b9ac803f662d331cd3'}\nResponse: {'status': 'OK', 'server_ts': 1763340075, 'nonce': '51d1c4b48bfae5ab551c0baf915cdd32', 'alg': 'SHA3_256', 'mac_resp': '7f9b7c0eab35313616a725e03d7f89b71df2ca8b644cf0e4f23a9d556aaf46a1'}\nReplay attempt: {'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}\n"}︡{"done":true}
︠a2c461c9-3e42-4624-949e-0c9fbf539459︠
# Pruebas de caso de validación

def test_ok():
    req = build_auth_request("alice", "SHA256", {"note": "hola"})
    resp = verify_auth_request(req)
    return "OK", req, resp

def test_replay():
    req = build_auth_request("alice", "SHA256", {"note": "hola"})
    resp1 = verify_auth_request(req)
    resp2 = verify_auth_request(req)
    return "REPLAY", req, resp1, resp2

def test_unknown_user():
    req = {
        "username": "mallory",
        "ts": int(time.time()),
        "nonce": "123",
        "op": "AUTH",
        "payload": {},
        "alg": "SHA256",
        "mac": "00" * 32,
    }
    resp = verify_auth_request(req)
    return "UNKNOWN_USER", req, resp

def test_bad_alg():
    req = build_auth_request("alice", "SHA256", {"note": "hola"})
    req["alg"] = "WHATEVER"
    resp = verify_auth_request(req)
    return "BAD_ALG", req, resp

def test_old_timestamp():
    req = build_auth_request("alice", "SHA256", {"note": "hola"})
    req["ts"] -= 1000   # viejo
    resp = verify_auth_request(req)
    return "OLD_TS", req, resp

def test_tampered_payload():
    req = build_auth_request("alice", "SHA256", {"note": "hola"})
    req["payload"]["note"] = "ataque"
    resp = verify_auth_request(req)
    return "TAMPERED", req, resp


# lista de funciones
tests = [
    test_ok,
    test_replay,
    test_unknown_user,
    test_bad_alg,
    test_old_timestamp,
    test_tampered_payload,
]

for t in tests:
    # El primer elemento de la tupla (Label) y *rest es el resto de los valores que los mete en una lista por el *S (req y resp). Es un desempaquetamiento.
    name, *rest = t()            # Una función t() que devuelve una tupla.
    print("\n==", name, "==")
    for r in rest:
        print(r)
︡2bc7be8d-8e82-43a9-9839-1898d2e65b0c︡{"stdout":"\n== OK ==\n{'username': 'alice', 'ts': 1763340085, 'nonce': '45861ed71481bdca63b2b2b1b896ea57', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': 'e04010e775c3b320fdc7dc523c3d0ab34c1941f1fe0b11f6213a075031b70486'}\n{'status': 'OK', 'server_ts': 1763340085, 'nonce': '45861ed71481bdca63b2b2b1b896ea57', 'alg': 'SHA256', 'mac_resp': 'd8f68c85a1c64d6c9d82108d2df140820694805a23e7833c631363712999f62e'}\n\n== REPLAY ==\n{'username': 'alice', 'ts': 1763340085, 'nonce': '2d58581331b36c623acea6da5f39611a', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': '15995cecca0a372d09f2f677007577c138c6c55610f0cff3911216008f4e2af4'}\n{'status': 'OK', 'server_ts': 1763340085, 'nonce': '2d58581331b36c623acea6da5f39611a', 'alg': 'SHA256', 'mac_resp': 'a4de7e6928492d7ee2580f4a1133462ccd2c0cfb94faf0e94554ec7e6da26781'}\n{'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}\n\n== UNKNOWN_USER ==\n{'username': 'mallory', 'ts': 1763340085, 'nonce': '123', 'op': 'AUTH', 'payload': {}, 'alg': 'SHA256', 'mac': '0000000000000000000000000000000000000000000000000000000000000000'}\n{'status': 'FAIL', 'err': 'ERR_USER_UNKNOWN'}\n\n== BAD_ALG ==\n{'username': 'alice', 'ts': 1763340085, 'nonce': '76cdb7a3e540c9be43a39ad3fb797967', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'WHATEVER', 'mac': '6dd5f4db4211f99e6ea1452e5943c0acaaf9540ad68e59dcf8815a9aafd84a02'}\n{'status': 'FAIL', 'err': 'ERR_ALG_UNSUPPORTED'}\n\n== OLD_TS ==\n{'username': 'alice', 'ts': 1763339085, 'nonce': '5b59ed6bd459dfbbcd3da55dd6f30abc', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': 'b90a0b732e18fef1757d8cd7001be0e1804214928b019d221e1cc82611b7f80b'}\n{'status': 'FAIL', 'err': 'ERR_TIME_SKEW'}\n\n== TAMPERED ==\n{'username': 'alice', 'ts': 1763340085, 'nonce': '763a6607b3c381a8cf910d649d21897a', 'op': 'AUTH', 'payload': {'note': 'ataque'}, 'alg': 'SHA256', 'mac': '77d488fba0b464dd29f4d976c5cd5782000df11d489a01f57bc1f526b989a38c'}\n{'status': 'FAIL', 'err': 'ERR_MAC_INVALID'}\n"}︡{"done":true}
︠a2b497c6-391d-43a7-9052-f0ac374af831︠









