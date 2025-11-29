# Sistema de autenticación con HMAC y validación de usuarios 

Autores: 
Nicolás Vallejos, Álvaro Tello, Gustavo Romero, Tomás González, Yu Zhou  

Asignatura: TEL252 – Criptografía y Seguridad de la Información 

Profesor: Luis Lizama  

# Definición del problema:

Los sistemas de autenticación tradicionales que transmiten contraseñas o tokens en texto claro presentan vulnerabilidades frente a ataques de interceptación y modificación de datos. 

En entornos donde múltiples usuarios deben autenticarse ante un servidor, es esencial garantizar la integridad del mensaje y la autenticidad del emisor, evitando que un atacante pueda alterar el contenido sin ser detectado. 

El proyecto busca resolver esta necesidad mediante el uso del algoritmo HMAC (Hash-based Message Authentication Code), que combina una función hash criptográfica con una clave secreta compartida entre cliente y servidor para validar la identidad y el contenido de cada mensaje. 


# Nuestro objetivo:

Diseñar e implementar un sistema de autenticación de usuarios basado en HMAC, que permita verificar la integridad y autenticidad de las credenciales transmitidas entre un cliente y un servidor, utilizando funciones hash seguras. 

# Motivación

En el contexto de la criptografía, la integridad es una propiedad fundamental de la seguridad de la información que asegura que la información transmitida no han sido modificados, alterados, destruidos o perdidos de manera no autorizada, ya sea por ejemplo, por un tercero (intencional o accidental) durante el almacenamiento o transmisión. La información debe ser consistente por el lado del remitente como también en el receptor. La utilización de algoritmos de Hashing son una buena herramienta que otorgan integridad en la data, pero si no se combinan con otras mecánicas, pueden perder efectividad, logrando así, que a pesar de los esfuerzos en la seguridad, que de todas maneras un atacante logre inyectar un mensaje al receptor sin que este se dé cuenta. Para ilustrar lo anterior, vea el siguiente diagrama:


<img width="766" height="390" alt="image" src="https://github.com/user-attachments/assets/c470c8e3-7e7f-43fd-bfab-04450c79417c" />


Suponga usted el escenario compuesto por un emisor A, receptor B y un atacante C:

- A calcula el digest del mensaje a transmitir.
- A envía un mensaje con su digest asociado.
- B calcula el digest a partir del mensaje.
- B compara el digest que ha calculado y lo compara con el recibido.
- Si los dos digest son iguales es que el mensaje no ha sido modificado.

<img width="761" height="557" alt="image" src="https://github.com/user-attachments/assets/e8d9ca80-6c17-46a5-a34e-08b272f2d30e" />


- A decide repetir el mismo paso anterior, calcula el digest y lo envía junto al mensaje.
- Aparece el actor C e intercepta el mensaje.
- C crea un nuevo mensaje y calcula su digest.
- C envía el mensaje junto al digest.
- B recibe el digest y el mensaje de C.

En esta situación la integridad se vió comprometida. En ese caso, ¿Qué elemento se puede agregar para reforzar la seguridad?:

<img width="1570" height="1115" alt="image" src="https://github.com/user-attachments/assets/27913630-e33f-43ff-b191-bec398f5a67c" />

- A y B deciden una clave compartida inicial enviada por un canal seguro.
- A combina una forma de utilizar la clave y el mensaje para crear el digest.
- B recibe el mensaje y replica el mismo procedimiento que A para calcular el digest.
- B verifica la integridad del mensaje comparando el digest calculado con el recibido por A.

Si bien C ha podido interceptar el mensaje y ver el contenido, no puede deducir la clave para replicar el mismo esquema de obtención del digest y lograr que el receptor B no descarte el mensaje. Por lo tanto, el esquema mostrado cumple no solo la propiedad de integrida sino también la autenticación dado que solamente personal selecto que tengan la clave secreta pueden generar el mismo mensaje de autentitación y demostrar quién dice ser. A este mensaje de autenticación se le conoce como **Message Authentication control (MAC)**. Sin embargo, dependiendo del procedimiento y método empleado mediante una combinación de la misma clave secreta y mensaje pueden generar distintos digest (Para este caso, MAC), y por lo mismo existen algoritmos estandarizados que pueden implementarse, de tal modo que A y B estén en sincronía. Pues, en este proyecto se estudiará *Hash-Based Message Authentication control (HMAC)*, un algoritmo que combina una clave secreta compartida y funciones hash como el SHA-256 que cumple las dos propiedades de autenticación e integridad. 

# Algoritmo HMAC

Para propósitos del estudio del proyecto se utilizará el algoritmo HMAC estandarizado por el NIST *FIPS (Federal information processing data standard) PUB 198-1*, que proporciona el detalle técnico formal y los pasos de cálculos.

En primera instancia, El algoritmo HMAC se utiliza para calcular un Código de Autenticación de Mensajes (MAC) sobre los datos $${\color{Yellow}(Mensaje)}$$ usando una clave secreta $${\color{Red}K}$$ y una función hash aprobada $${\color{Green}H}$$ (SHA-2, SHA-3, MD4, MD5... ); en nuestro caso se utilizará SHA-256. 

El algoritmo central es el siguiete:

```math
\mathrm{MAC}(\text{text}) = \mathrm{HMAC}(K,\text{text})
= H\Big((K_0 \oplus \text{opad}) \,\|\, H\big((K_0 \oplus \text{ipad}) \,\|\, \text{text}\big)\Big)

```
Donde:


## Variables y Parámetros del Algoritmo HMAC (FIPS 198-1)

| Símbolo | Definición | Descripción |
| :---: | :--- | :--- |
| **$H$** | Función Hash Aprobada | La función hash criptográfica utilizada (ej. SHA-256 o SHA-3). |
| **$K$** | Clave Secreta | La clave secreta compartida entre el originador y el receptor. |
| **$K_0$** | Clave Preprocesada | La clave $K$ después de cualquier ajuste de longitud para formar una clave de $B$ bytes. |
| **$B$** | Tamaño del Bloque | La longitud (en bytes) del bloque de entrada de la función hash (ej. 64 bytes para SHA-1/SHA-256). |
| **$L$** | Tamaño de Salida | La longitud (en bytes) de la salida de la función hash (ej. 32 bytes para SHA-256). |
| **text** | Datos del Mensaje | Los datos sobre los que se calcula el HMAC.  |
| **ipad** | Inner Pad (Relleno Interno) | El byte $x'36'$ repetido $B$ veces. Se utiliza para el hash interno. |
| **opad** | Outer Pad (Relleno Externo) | El byte $x'5c'$ repetido $B$ veces. Se utiliza para el hash externo. |
| **$\oplus$** | Operación XOR | Operación **Exclusive-Or**. Se utiliza para combinar la clave con ipad/opad. |
| **$\|\|$** | Concatenación | Operación para unir dos cadenas de bytes. |

---

Los pasos del algoritmo se muestran en la siguiente tabla:


| Paso | Descripción del paso |
| :---: | :--- |
| **Paso 1** | Si la longitud de `K` = `B`: Entonces `K_0 = K`. Ir al paso 4. |
| **Paso 2** | Si la longitud de `K > B`: Aplicar hash a `K` para obtener una cadena de `L` bytes. Luego concatenar `(B-L)` ceros para crear una cadena de `B` bytes y `K_0` (i.e., `K_0 = H(K) || 0x00...00`). Ir al paso 4. |
| **Paso 3** | Si la longitud de `K < B`: Agregar ceros al final de `K` para crear una cadena de `B`-bytes y `K_0` (Ej: Si `K` tiene 20 bytes y `B=64`, se agregan 44 ceros `0x00`). |
| **Paso 4** | Aplicar **XOR** a `K_0` y `ipad` para generar una cadena de `B`-bytes: `K_0 XOR ipad`. |
| **Paso 5** | **Concatenar** '`text`' a la cadena resultante del paso 4: `(K_0 XOR ipad) || text`. |
| **Paso 6** | Aplicar la función `H` (hash) a la cadena generada en el paso 5: `H((K_0 XOR ipad) || text)`. |
| **Paso 7** | Aplicar **XOR** a `K_0` y `opad`: `K_0 XOR opad`. |
| **Paso 8** | **Concatenar** el resultado del paso 6 al paso 7: `(K_0 XOR opad) || H((K_0 XOR ipad) || text)`. |
| **Paso 9** | Aplicar la función `H` (hash) al resultado del paso 8: `H((K_0 XOR opad) || H((K_0 XOR ipad) || text))`. |


El diagrama es el siguiente:

<img width="591" height="793" alt="image" src="https://github.com/user-attachments/assets/fcaed2cf-2161-43de-83e4-6740eeeb1cc2" />




Entendido el funcionamiento del propio algoritmo, se diseña el protocolo para asegurar su correcto funcionamiento.

# Protocolo:

El proceso se dividirá en cuatro etapas fundamentales: *Preparación, firma, envío y verificación*. Para ser más específico, el contexto de la implementación será llevado en un modelo cliente-servidor para consultas de API bajo el modelo REST, pudiendo así, el usuario consultar recursos al servidor mediante los verbos GET, PUT, POST, etc.   

## Preparación:
El cliente recopila los datos necesarios para la autenticación y la integridad:

1). El cliente se registra en una plataforma a la cual desea consultar recursos. Al momento del registro solicita una API Key o Token al servidor, de manera que el cliente pueda consultar recursos y el servidor le permitar autenticar el usuario. El Token debe ser enviado al cliente mediante un canal seguro distinto al convencional, en donde se realizarían las consultas. Existen protocolos que lo implementan como TLS, una versión mejorada del SSL.

2). El cliente genera su $${\color{Red}ID}$$ de identificador en la plataforma.

3). El cliente genera un time stamp $${\color{Blue}Ts}$$.

4). El cliente define el método `HTTP` (GET, POST, PUT, etc) con su respectiva `URI`.


## Firma:
Se genera el firmado del código MAC del cliente:

1). Se construye la cadena concatenada a firmar: `ID||Ts||URL`.

2). Se utiliza el algoritmo HMAC pasando como parámetro la llave compartida API KEY y la cadena a firmar para obtener el MAC final; esto es `HMAC(API KEY, ID||Ts||URL)`. 

## Envío:

El cliente envía la solicitud HTTP con los metadatos necesarios en el header:

1). El cliente envía la solicitud HTTP, por ejemplo, `GET /data/profile`.

2). Se incluye en los headers del envío la $${\color{Red}ID}$$, $${\color{Blue}Ts}$$ y $${\color{Yellow}MAC}$$.

## Verificación:

El servidor valida la autenticidad del mensaje:

1). El servidor recibe la consulta del cliente y los headers.

2). El servidor primero valida que el timestamp esté dentro de la ventana del tiempo.

3). El servidor construye la cadena el cuál utilizó el cliente para el firmado en base a los parámetros del header.

4). El servidor busca la API Key del cliente.

5). Calcula el MAC usando el algoritmo HMAC.

6). Finalmente compara las firmas, y en base al resultado envía un código $${\color{Green}200}$$ con la respuesta esperada, $${\color{Red}208}$$ correspondiente a un Time out o $${\color{Red}401}$$ MAC invalido. 

# Prototipo inicial

Para la primera etapa del proyecto se implementó un prototipo básico del sistema de autenticación basado en HMAC.  
Este prototipo permite validar las funciones principales del flujo de autenticación antes de desarrollar la versión completa cliente-servidor.

El objetivo del prototipo es demostrar:

- La construcción correcta de un mensaje de autenticación por parte del cliente (username, timestamp, nonce, operación y payload).
- La generación del MAC utilizando distintas funciones hash (MD5, SHA-256 y SHA3-256).
- La verificación en el servidor, incluyendo validación de:
  - Usuario válido.
  - Algoritmo de hash soportado.
  - Ventana de tiempo.
  - Protección contra replay mediante nonces usados.
  - Integridad del MAC.

A continuación se presentan las funciones principales implementadas:

---

### **1. Construcción del mensaje por parte del cliente**

```python
req = build_auth_request("alice", "SHA256", {"note": "hola mundo"})
print(req)
```

### Ejemplo de salida:

```json
{
  "username": "alice",
  "ts": 1763340075,
  "nonce": "b0454ad96fbb3b18970d2b44d7bac48e",
  "op": "AUTH",
  "payload": {"note": "hola mundo"},
  "alg": "SHA256",
  "mac": "5a27666cc9cfb740a9f288c23dc92f2dc784f7bf0ad8c68901f241eaeecf6e4"
}
```


### **2. Verificación en el servidor**

resp = verify_auth_request(req)
print(resp)

### Ejemplo

```json
{
  "status": "ok",
  "server_ts": 1763340075,
  "nonce": "b0454ad96fbb3b18970d2b44d7bac48e",
  "alg": "SHA256",
  "mac_resp": "493351369c147c049dfa1888664577ff6dd3339ea1d33098971817c26c985f5"
}
```

# Validación preliminar

Para verificar que las primitivas criptográficas y las reglas del protocolo funcionan correctamente, se implementaron pruebas unitarias que evalúan distintos escenarios de autenticación.  
Estas pruebas permiten validar comportamiento esperado tanto en casos correctos como en ataques comunes.

Los casos considerados fueron:

- **Caso OK:** mensaje válido y MAC correcto.
- **Replay attack:** reutilización del mismo nonce.
- **Usuario desconocido:** el servidor no reconoce al emisor.
- **Algoritmo no soportado:** el cliente solicita un hash inválido.
- **Timestamp antiguo:** ataque de desincronización temporal.
- **Mensaje modificado:** integridad comprometida (MAC inválido).

A continuación se presentan salidas reales generadas por el prototipo:

### **Salida de las pruebas:**

```bash
== OK ==
{'username': 'alice', 'ts': 1763340085, 'nonce': '45861ed71481bdca63b2b2b1b896ea57', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': 'e04010e775c3b320fdc7dc523c3d0ab34c1941f1fe0b11f6213a075031b70486'}
{'status': 'OK', 'server_ts': 1763340085, 'nonce': '45861ed71481bdca63b2b2b1b896ea57', 'alg': 'SHA256', 'mac_resp': 'd8f68c85a1c64d6c9d82108d2df140820694805a23e7833c631363712999f62e'}

== REPLAY ==
{'username': 'alice', 'ts': 1763340085, 'nonce': '2d58581331b36c623acea6da5f39611a', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': '15995cecca0a372d09f2f677007577c138c6c55610f0cff3911216008f4e2af4'}
{'status': 'OK', 'server_ts': 1763340085, 'nonce': '2d58581331b36c623acea6da5f39611a', 'alg': 'SHA256', 'mac_resp': 'a4de7e6928492d7ee2580f4a1133462ccd2c0cfb94faf0e94554ec7e6da26781'}
{'status': 'FAIL', 'err': 'ERR_NONCE_REPLAY'}

== UNKNOWN_USER ==
{'username': 'mallory', 'ts': 1763340085, 'nonce': '123', 'op': 'AUTH', 'payload': {}, 'alg': 'SHA256', 'mac': '0000000000000000000000000000000000000000000000000000000000000000'}
{'status': 'FAIL', 'err': 'ERR_USER_UNKNOWN'}

== BAD_ALG ==
{'username': 'alice', 'ts': 1763340085, 'nonce': '76cdb7a3e540c9be43a39ad3fb797967', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'WHATEVER', 'mac': '6dd5f4db4211f99e6ea1452e5943c0acaaf9540ad68e59dcf8815a9aafd84a02'}
{'status': 'FAIL', 'err': 'ERR_ALG_UNSUPPORTED'}

== OLD_TS ==
{'username': 'alice', 'ts': 1763339085, 'nonce': '5b59ed6bd459dfbbcd3da55dd6f30abc', 'op': 'AUTH', 'payload': {'note': 'hola'}, 'alg': 'SHA256', 'mac': 'b90a0b732e18fef1757d8cd7001be0e1804214928b019d221e1cc82611b7f80b'}
{'status': 'FAIL', 'err': 'ERR_TIME_SKEW'}

== TAMPERED ==
{'username': 'alice', 'ts': 1763340085, 'nonce': '763a6607b3c381a8cf910d649d21897a', 'op': 'AUTH', 'payload': {'note': 'ataque'}, 'alg': 'SHA256', 'mac': '77d488fba0b464dd29f4d976c5cd5782000df11d489a01f57bc1f526b989a38c'}
{'status': 'FAIL', 'err': 'ERR_MAC_INVALID'}
```


# Resultados 

En esta sección se adjunta una comparación de los distintos algoritmos hashes incorporados en Hmac. Observe los siguientes resultados:


<img width="873" height="552" alt="image" src="https://github.com/user-attachments/assets/2a221a38-16e1-4093-aac4-0c249fc7baa9" />

<img width="855" height="552" alt="image" src="https://github.com/user-attachments/assets/56807f5e-4fe3-4e90-8930-e8118aa51508" />

### Ranking de Rendimiento

Resultados promedio tras ejecutar **50,000,000 iteraciones** por algoritmo.

| Ranking | Algoritmo | Tiempo (ms) | Tiempo ($\mu s$) | Observación |
| :---: | :--- | :--- | :--- | :--- |
| 1 | **SHA1** | `0.00263` | **2.63 µs** | El más veloz (pero inseguro). |
| 2 | **SHA256** | `0.00269` | **2.69 µs** | Muy optimizado, casi igual a SHA1. |
| 3 | **MD5** | `0.00279` | **2.79 µs** | Ligeramente más lento que SHA256 en esta prueba. |
| 4 | **SHA_512** | `0.00340` | **3.40 µs** | Eficiente en arquitecturas de 64 bits. |
| 5 | **SHA3_512** | `0.00396` | **3.96 µs** | Menor overhead inicial que su versión de 256. |
| 6 | **SHA3_256** | `0.00412` | **4.12 µs** | Mayor costo computacional por iteración. |
| 7 | **WHIRLPOOL** | `0.00616` | **6.16 µs** | El más lento (algoritmo pesado de 512 bits). |

### Comparación de Tamaño de Salida

| Algoritmo | Caracteres | Bits |
| :--- | :---: | :---: |
| **MD5** | 32 | 128 |
| **SHA1** | 40 | 160 |
| **SHA256** | 64 | 256 |
| **SHA3_256** | 64 | 256 |
| **SHA3_512** | 128 | 512 |
| **SHA_512** | 128 | 512 |
| **WHIRLPOOL** | 128 | 512 |

Las pruebas han revelado resultados inesperados influenciado por la arquitectura y complejidad de su algoritmo. Note que los algoritmos SHA1-SHA256 son los más rápidos, a pesar de tener arquitecturas diferentes entre unos 0.0026-0.0028 milisegundos. Su motivo principal es el diseño interno a nivel lógico, dado que utilizan operaciones básicas (AND, OR, XOR, rotaciones de bits y sumas modulares), por lo que su estructura es diseñado para ser rápido en ejecución.

La famila del SHA3 son más lentos en general y no se debe a la optimización en sí, sino a su diseño. Es que el SHA-3 realiza permutaciones sobre una matriz de estado de 1600 bits, por lo que mover una matriz muy grande requiere más ciclos lógicos que las variables de estado más pequeños de SHA-2. Lo anterior sacrifica algo de rendimiento por robustez. Note un detalle importante, el SHA3 512 es más rápido que el SHA3 256 y radica en la arquitectura esponja en sí. Recuerde que la función esponja depende de dos parámetos correspondientes al ratio o velocidad de procesamiento `r`  y capacidad `c` donde se inicializa un vector nulo para asegurar la seguridad en el sistema. Según el estándar FIPS-PUB 202 del NIST el tamaño de la capacidad se define como:

```math
c = 2 \cdot Tamaño\_salida

```

Luego los bloques internos:

| Algoritmo | c | Bits restantes bloque |
| :--- | :---: | :---: |
| **SHA3-256** | 512 | 1088 (136 bytes)|
| **SHA3-512** | 1024 | 576 (72 bytes)|


Por lo tanto los bloques a procesar del SHA3 512 procesa bloques mucho más pequeño y por ende es más eficiente. Por último la función Whirpool fue el más lento en sus pruebas porque utiliza una arquitectura basado en el cifrado AESrepetida en 10 rondas de una matriz de 512 bits.

En términos de seguidad,la paradoja del cumpleaños indica que es posible encontrar una colisión hash de n bits solamente se necesita probar $2^{n/2}$ combinaciones. Por lo tanto, los sistemas más robustos se encuentran los hashes cuyas salidas contienen la mayor cantidad de bits, por ejemplo, SHA3 512 o Whirpool; mientras que aquellos con menor cantidad de bits de salida se pueden romper con mayor facilidad, por lo que MD5 y SHA-1 son triviales para los ataques modernos.

A pesar de todo lo anteior, todos los algoritmos demuestran una fiabilidad en el efecto avalancha. Esto ayuda a ocultar patrones y romper cualquier esquema lógico evidente del mensaje oiginal en donde un cambio mínimo en un bit produce un resultado muy diferente.  



# Referencias:
- https://csrc.nist.gov/pubs/fips/198-1/final
- https://www.rfc-editor.org/rfc/rfc2104.html
- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf
