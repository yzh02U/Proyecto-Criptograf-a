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

 
