# Ejecución experimental 
El proyecto es elaborado con MERN con versión de Node v22.13.1. Dentro del proyecto encontrará la siguiente distribución de carpetas:

```
-Proyecto_Cripto:
  -Backend:
    -.....
    -.env
  -Frontend
```

Usted deberá ejecutar dos terminales para ambas carpetas. Esto es para levantar el servidor y la aplicación web por separado. El primer paso es dirigirse al archivo con extensión .env, el cual debe modificar. Este muestra lo siguiente:

```
MONGO_URI=mongodb+srv://(usuario):(contraseña)@cripto.ds1atv1.mongodb.net/?appName=Cripto
PORT=3001
```

Remplace el parámetro MONGO_URI con la dirección de conexión con su base datos. Luego edite el "usuario" y "contraseña" de acceso.

<img width="1851" height="913" alt="image" src="https://github.com/user-attachments/assets/9332f212-e7c4-438c-a5ee-89794da03207" />

Para hallar el enlace, valla a "Clusters" y presione Connect->Drivers. Seleccione Node.js con versión 6.7. En las dos secciones posteriores se detallan las instrucciones para ejecutar las dos terminales. 

## Backend

Inicie una terminal y diríjase a la ruta:
```
C:\.....\Proyecto_Cripto\Backend
```

y ejecute el siguiente comando: 
```
node index.js
```
le deberá mostrar el siguiete resultado que indica el levantamiento correcto del servidor:

<img width="1105" height="620" alt="image" src="https://github.com/user-attachments/assets/c124bae5-10c7-492b-bf72-8d3566b3ac31" />


## FrontEnd

Inicie una segunda terminal y diríjase a la ruta:
```
C:\.....\Proyecto_Cripto\Frontend
```

y ejecute el siguiente comando: 

```
npm run dev
```

deberá visualizar el siguiente resultado del levantamiento correcto: 

<img width="1100" height="618" alt="image" src="https://github.com/user-attachments/assets/b08f1d2b-7a84-4506-9f42-896f40c94cfe" />

Posteriormente debe abrir un navegador web de preferencia e ingrese la siguiente url en la barra de navegación:

```
 http://localhost:5173/
```

Si le muestra la interfaz, es que ha completado todos los pasos con éxito:

<img width="1830" height="984" alt="image" src="https://github.com/user-attachments/assets/9deca32e-8493-4086-90d0-16f840bf9b98" />


# Demostración experrimental

Para ver una demostración del experimento, vea el archivo "Demostración experimental.mp4".

