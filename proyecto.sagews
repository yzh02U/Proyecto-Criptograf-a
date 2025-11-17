︠48db5505-e870-4b8d-b454-74300134518as︠
#QUE PASA CHAVALEEEES
print("你妈妈很胖")
︡40126165-7d78-478d-93eb-72ff6d0e8cb5︡{"stdout":"你妈妈很胖\n"}︡{"done":true}
︠e9e0e6aa-6dd7-4599-9050-225400c516e6s︠

# Objetivo: Implementar un sistema de autenticación funcional basado en HMAC, integrando múltiples funciones hash (MD5, Whirlpool, SHA-256 y SHA-3) y comparando su rendimiento y nivel de seguridad, acompañado de una interfaz de usuario que permita visualizar el proceso de autenticación y la verificación de integridad y autenticidad del mensaje.

import hmac
import hashlib
import secrets
import time
import json
︡3fca5ae4-ca7d-44e4-a316-36303c1fc4aa︡{"done":true}
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
︡7d8dd334-81a2-430b-8cf1-bdcf13da8873︡{"done":true}
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
︡74288797-0583-47db-acdd-ea06bc2401a4︡{"done":true}
︠00064dcf-56bd-47c3-bd51-e7c686b82074s︠
# 3) “Base de datos” de usuarios (demo)

USERS = {
    # En un sistema real, K_user se generaría y almacenaría en un lugar seguro
    "alice": secrets.token_bytes(32),
    "bob": secrets.token_bytes(32),
}

USED_NONCES = set()  # pares (username, nonce) ya usados
WINDOW = 60          # ventana temporal en segundos
︡3f92b8cc-c63c-492e-b736-37940afb8d17︡{"done":true}
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
︡dc36ae9c-7012-4b48-8479-3c6f1d828441︡{"done":true}
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
︠a2c461c9-3e42-4624-949e-0c9fbf539459s︠
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

tests = [
    test_ok,
    test_replay,
    test_unknown_user,
    test_bad_alg,
    test_old_timestamp,
    test_tampered_payload,
]

for t in tests:
    name, *rest = t()
    print("\n==", name, "==")
    for r in rest:
        print(r)
︡2bc7be8d-8e82-43a9-9839-1898d2e65b0c︡{"stdout":"\n== OK ==\n{'username': 'alice', 'ts': 1763340085, 'nonce': '45861ed71481bdca63b2b2b1b896ea57', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': 'e04010e775c3b320fdc7dc523c3d0ab34c1941f1fe0b11f6213a075031b70486'}\n{'status': 'OK', 'server_ts': 1763340085, 'nonce': '45861ed71481bdca63b2b2b1b896ea57', 'alg': 'SHA256', 'mac_resp': 'd8f68c85a1c64d6c9d82108d2df140820694805a23e7833c631363712999f62e'}\n\n== REPLAY ==\n{'username': 'alice', 'ts': 1763340085, 'nonce': '2d58581331b36c623acea6da5f39611a', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': '15995cecca0a372d09f2f677007577c138c6c55610f0cff3911216008f4e2af4'}\n{'status': 'OK', 'server_ts': 1763340085, 'nonce': '2d58581331b36c623acea6da5f39611a', 'alg': 'SHA256', 'mac_resp': 'a4de7e6928492d7ee2580f4a1133462ccd2c0cfb94faf0e94554ec7e6da26781'}\n{'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}\n\n== UNKNOWN_USER ==\n{'username': 'mallory', 'ts': 1763340085, 'nonce': '123', 'op': 'AUTH', 'payload': {}, 'alg': 'SHA256', 'mac': '0000000000000000000000000000000000000000000000000000000000000000'}\n{'status': 'FAIL', 'err': 'ERR_USER_UNKNOWN'}\n\n== BAD_ALG ==\n{'username': 'alice', 'ts': 1763340085, 'nonce': '76cdb7a3e540c9be43a39ad3fb797967', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'WHATEVER', 'mac': '6dd5f4db4211f99e6ea1452e5943c0acaaf9540ad68e59dcf8815a9aafd84a02'}\n{'status': 'FAIL', 'err': 'ERR_ALG_UNSUPPORTED'}\n\n== OLD_TS ==\n{'username': 'alice', 'ts': 1763339085, 'nonce': '5b59ed6bd459dfbbcd3da55dd6f30abc', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': 'b90a0b732e18fef1757d8cd7001be0e1804214928b019d221e1cc82611b7f80b'}\n{'status': 'FAIL', 'err': 'ERR_TIME_SKEW'}\n\n== TAMPERED ==\n{'username': 'alice', 'ts': 1763340085, 'nonce': '763a6607b3c381a8cf910d649d21897a', 'op': 'AUTH', 'payload': {'note': 'ataque'}, 'alg': 'SHA256', 'mac': '77d488fba0b464dd29f4d976c5cd5782000df11d489a01f57bc1f526b989a38c'}\n{'status': 'FAIL', 'err': 'ERR_MAC_INVALID'}\n"}︡{"done":true}
︠a2b497c6-391d-43a7-9052-f0ac374af831︠









