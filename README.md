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


