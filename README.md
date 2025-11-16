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

En el contexto de la criptografía, la integridad es una propiedad fundamental de la seguridad de la información que asegura que la información transmitida no han sido modificados, alterados, destruidos o perdidos de manera no autorizada, ya sea por ejemplo, por un tercero (intencional o accidental) durante el almacenamiento o transmisión. La información debe ser consistente por el lado del remitente como también en el receptor. La utilización de algoritmos de Hashing son una buena herramienta que otorgan integridad en la data, pero si no se combiann con otras mecánicas, pueden perder efectividad, logrando así, que a pesar de los esfuerzos en la seguridad, que de todas maneras un atacante logre inyectar un mensaje al receptor sin que este se dé cuenta. Para ilustrar lo anterior, vea el siguiente diagrama:


<img width="1582" height="672" alt="image" src="https://github.com/user-attachments/assets/452d62f4-466e-4c11-bfd4-f7af33396287" />

Suponga usted el escenario compuesto por un emisor A, receptor B y un atacante C:

- A calcula el digest del mensaje a transmitir.
- A envía un mensaje con su digest asociado.
- B calcula el digest a partir del mensaje.
- B compara el digest que ha calculado y lo compara con el recibido.
- Si los dos digest son iguales es que el mensaje no ha sido modificado.

  <img width="1677" height="840" alt="image" src="https://github.com/user-attachments/assets/e3a64f51-1bdd-47d3-b1af-1dd9fe8cb02e" />

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

Si bien C ha podido interceptar el mensaje y ver el contenido, no puede deducir la clave para replicar el mismo esquema de obtención del digest y lograr que el receptor B no descarte el mensaje. Por lo tanto, el esquema mostrado cumple no solo la propiedad de integrida sino también la autenticación dado que solamente personal selecto que tengan la clave secreta pueden generar el mismo mensaje de autentitación y demostrar quién dice ser. A este mensaje de autenticación se le **Message Authentication control (MAC)**. Sin embargo, dependiendo del procedimiento y método empleado mediante una combinación de la misma clave secreta y mensaje pueden generar distintos digest (Para este caso, MAC), y por lo mismo existen algoritmos estandarizados que pueden implementarse, de tal modo que A y B estén en sincronía. Pues, en este proyecto se estudiará *Hash-Based Message Authentication control (HMAC)*, un algoritmo que combina una clave secreta compartida y funciones hash como el SHA-256 que cumple las dos propiedades de autenticación e integridad. 

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

<img width="1250" height="1590" alt="image" src="https://github.com/user-attachments/assets/cea24de2-f42b-4e95-80a8-da8b65b586ee" />


Entendido el funcionamiento del propio algoritmo, se diseña el protocolo para asegurar su correcto funcionamiento.

# Protocólo:

El proceso se dividirá en cuatro etapas fundamentales: *Preparación, firma, envío y verificación*. Para ser más específico, el contexto de la implementación será llevado en un modelo cliente-servidor para consultas de API bajo el modelo REST, pudiendo así, el usuario consultar recursos al servidor mediante los verbos GET, PUT, POST, etc.   

## Preparación:
El cliente recopila los datos necesarios para la autenticación y la integridad:

1). El cliente se registra en una plataforma al cual desea consultar recursos. Al momento del registro solicita una API Key o Token al servidor, de manera que el cliente pueda consultar recursos y el servidor le permitar autenticar el usuario. El Token debe ser enviado al cliente mediante un canal seguro distinto al convencional, en donde se realizarían las consultas. Existen protocolos que lo implementan como TLS, una versión mejorada del SSL.

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

2). Se incluye en los headers del envío la $${\color{Red}ID}$$, $${\color{Blue}Ts}$$ y $${\color{Yellos}MAC}$$.

## Verificación:

El servidor valida la autenticidad del mensaje:

1). El servidor recibe la consulta del cliente y los headers.

2). El servidor primero valida que el timestamp esté dentro de la ventana del tiempo.

3). El servidor construye la cadena el cuál utilizó el cliente para el firmado en base a los parámetros del header.

4). El servidor busca la API Key del cliente.

5). Calcula el MAC usando el algoritmo HMAC.

6). Finalmente compara las firmas, y en base al resultado envía un código $${\color{Green}200}$$ con la respuesta esperada, $${\color{Red}208}$$ correspondiente a un Time out o $${\color{Red}401}$$ MAC invalido. 





# Referencias:
- https://csrc.nist.gov/pubs/fips/198-1/final 
