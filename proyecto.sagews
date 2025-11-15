︠48db5505-e870-4b8d-b454-74300134518as︠
#QUE PASA CHAVALEEEES
print("你妈妈很胖")
︡496d758c-acee-4de7-a059-d6801ff58782︡{"stdout":"你妈妈很胖\n"}︡{"done":true}
︠e9e0e6aa-6dd7-4599-9050-225400c516e6s︠

# Objetivo: Implementar un sistema de autenticación funcional basado en HMAC, integrando múltiples funciones hash (MD5, Whirlpool, SHA-256 y SHA-3) y comparando su rendimiento y nivel de seguridad, acompañado de una interfaz de usuario que permita visualizar el proceso de autenticación y la verificación de integridad y autenticidad del mensaje.

import hmac
import hashlib
import secrets
import time
import json
︡79668749-303b-4ec6-b9ac-9addf14cae64︡{"done":true}
︠23f1a519-e09d-475d-b674-71255840b9ebs︠
# 1) Algoritmos de hash soportados

ALGORITHMS = {
    "MD5": hashlib.md5,
    "SHA256": hashlib.sha256,
    "SHA3_256": hashlib.sha3_256,
    # "WHIRLPOOL": ...  # para Whirlpool necesitarías una librería externa (p.ej. pycryptodome)
}


def get_hash_func(name: str):
    """Obtiene la función de hash de hashlib dada una etiqueta."""
    if name not in ALGORITHMS:
        raise ValueError(f"Algoritmo no soportado: {name}")
    return ALGORITHMS[name]
︡b89508e5-d2af-4182-9e3a-774914abad4b︡{"done":true}
︠f22338b4-ced1-49ac-8700-15274b825aecs︠
#2) Helpers para formatos

def canon_payload(payload):
    """JSON compacto y con claves ordenadas, en bytes."""
    if payload is None:
        payload = {}
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def make_request_string(username, ts, nonce, op, payload, hash_func):
    """
    Construye la cadena canónica:
    username|ts|nonce|op|HASH(payload_min)
    """
    payload_bytes = canon_payload(payload)
    payload_hash = hash_func(payload_bytes).hexdigest()
    s = f"{username}|{ts}|{nonce}|{op}|{payload_hash}"
    return s.encode("utf-8")


def compute_hmac(key: bytes, message: bytes, hash_func):
    """Calcula HMAC(key, message) con el hash indicado."""
    return hmac.new(key, message, hash_func).hexdigest()
︡5d28e638-ce65-4b4b-8aad-d9903df36ec1︡{"done":true}
︠00064dcf-56bd-47c3-bd51-e7c686b82074s︠
# 3) “Base de datos” de usuarios (demo)

USERS = {
    # En un sistema real, K_user se generaría y almacenaría en un lugar seguro
    "alice": secrets.token_bytes(32),
    "bob": secrets.token_bytes(32),
}

USED_NONCES = set()  # pares (username, nonce) ya usados
WINDOW = 60          # ventana temporal en segundos
︡aec46f94-6b9d-49ef-a8ba-521167a2c339︡{"done":true}
︠77dd9659-78b6-45c6-8a7b-ddc32ac61d33s︠
# 4) Cliente: construye AuthRequest


#Construye un mensaje de autenticación:
#{
#   username, ts, nonce, op, payload, alg, mac
#}


def build_auth_request(username: str, alg_name: str, payload=None):
    if username not in USERS:
        raise ValueError("Usuario desconocido en este demo (USERS)")

    key = USERS[username]
    hash_func = get_hash_func(alg_name)

    ts = int(time.time())
    nonce = secrets.token_hex(16)  # 16 bytes -> 32 hex chars
    op = "AUTH"

    msg = make_request_string(username, ts, nonce, op, payload, hash_func)
    mac = compute_hmac(key, msg, hash_func)

    request = {
        "username": username,
        "ts": ts,
        "nonce": nonce,
        "op": op,
        "payload": payload or {},
        "alg": alg_name,
        "mac": mac,
    }
    return request
︡a5f005e0-f57d-40f2-87a2-e0d4f974055a︡{"done":true}
︠ca0e0609-8618-4036-af05-6875195b85a8s︠
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

    now = int(time.time())

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
    if abs(now - ts) > WINDOW:
        return {"status": "FAIL", "err": "ERR_TIME_SKEW"}

    # 4) Replay (nonce)
    if (username, nonce) in USED_NONCES:
        return {"status": "FAIL", "err": "ERR_NONCE_REPLAY"}

    # 5) Verificar HMAC
    msg = make_request_string(username, ts, nonce, op, payload, hash_func)
    mac_srv = compute_hmac(key, msg, hash_func)

    if not hmac.compare_digest(mac_cli, mac_srv):
        return {"status": "FAIL", "err": "ERR_MAC_INVALID"}

    # Si todo OK, registrar nonce y responder
    USED_NONCES.add((username, nonce))
    server_ts = now
    resp_str = f"OK|{server_ts}|{nonce}".encode("utf-8")
    mac_resp = compute_hmac(key, resp_str, hash_func)

    response = {
        "status": "OK",
        "server_ts": server_ts,
        "nonce": nonce,
        "alg": alg_name,
        "mac_resp": mac_resp,
    }
    return response
︡6b8e884b-d033-4b07-9bda-fb742dbdd5c4︡{"done":true}
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
︡68948485-d470-4461-b410-41a852b3b023︡{"stdout":"\n=== Prueba de autenticación con MD5 ===\nRequest: {'username': 'alice', 'ts': 1763161815, 'nonce': 'af3059c695f36e834f7fe2c006b2379f', 'op': 'AUTH', 'payload': {'note': 'hola mundo'}, 'alg': 'MD5', 'mac': '1c68b6f689bcbb0026c072c8aa9c69a2'}\nResponse: {'status': 'OK', 'server_ts': 1763161815, 'nonce': 'af3059c695f36e834f7fe2c006b2379f', 'alg': 'MD5', 'mac_resp': '2f32605de6abb9e9491b78af878a0e82'}\nReplay attempt: {'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}\n\n=== Prueba de autenticación con SHA256 ===\nRequest: {'username': 'alice', 'ts': 1763161815, 'nonce': '7b4c2d0f5a048fe00f0cbae03170fde0', 'op': 'AUTH', 'payload': {'note': 'hola mundo'}, 'alg': 'SHA256', 'mac': 'ca4bb3835779898f2549248421310b6a5ec0c32169ccd2d3c1595715e213a1a6'}\nResponse: {'status': 'OK', 'server_ts': 1763161815, 'nonce': '7b4c2d0f5a048fe00f0cbae03170fde0', 'alg': 'SHA256', 'mac_resp': '689d2c4902ad9201578012917774bbe84d4fd50b3371e6b7a3db3a423b914b32'}\nReplay attempt: {'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}\n\n=== Prueba de autenticación con SHA3_256 ===\nRequest: {'username': 'alice', 'ts': 1763161815, 'nonce': '8d362a8422eab7ba7de4645564c8b1c2', 'op': 'AUTH', 'payload': {'note': 'hola mundo'}, 'alg': 'SHA3_256', 'mac': 'a6be9eb3a358b09201812bcf8c0568871e0c3c1a6df97fac12720de76686c949'}\nResponse: {'status': 'OK', 'server_ts': 1763161815, 'nonce': '8d362a8422eab7ba7de4645564c8b1c2', 'alg': 'SHA3_256', 'mac_resp': 'a8af30d454cb356a1818dabfe3900c21e0b0bbda424905fd03d0996c59e8fd35'}\nReplay attempt: {'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}\n"}︡{"done":true}
︠a2c461c9-3e42-4624-949e-0c9fbf539459︠









