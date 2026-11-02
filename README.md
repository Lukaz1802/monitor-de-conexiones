# Monitor de conexiones de red

Programa gratuito para Windows 10 y 11 que te muestra qué programas de tu PC se conectan a Internet, te avisa de lo sospechoso y te deja bloquearlo con un clic.

Creado por **Lucas Lopez** · [lucaslopez.com.ar](https://lucaslopez.com.ar)

> No sustituye al antivirus: úsalo junto a Seguridad de Windows.

## Qué hace

- **Muestra cada conexión** con el programa que la abre, quién lo firmó y a qué servidor va, con su nombre.
- **Detecta señales típicas de virus** y explica en palabras sencillas por qué conviene revisar cada una.
- **Ve lo que dura una fracción de segundo.** Abierto como administrador, Windows le avisa al instante de cada conexión, cada consulta DNS y cada lectura de archivos de contraseñas, aunque un programa se abra, envíe algo y se cierre entre dos revisiones.
- **Guarda las alertas en disco** y avisa con una notificación, aunque no estés mirando.
- **Frena lo sospechoso** con el Firewall de Windows: bloquea un programa o una IP, o corta Internet en una emergencia.
- **Se queda vigilando** desde la bandeja y puede iniciarse con Windows.

## Cómo conseguirlo

Lo recomendado es compilarlo tú mismo. Tarda unos segundos y no hay que instalar nada, porque usa el compilador de C# que ya viene con Windows (.NET Framework 4).

1. Pulsa el botón verde **Code → Download ZIP** y descomprime el archivo.
2. Entra en la carpeta `codigo` y haz doble clic en `compilar.bat`.
3. Cuando diga «Listo», tendrás `MonitorConexiones.exe` en la carpeta principal.

`compilar.bat` es un archivo de texto de pocas líneas. Si Windows te pide confirmación porque viene de Internet, puedes abrirlo antes con el Bloc de notas y comprobar que solo llama al compilador.

## Primeros pasos

1. Haz clic derecho en `MonitorConexiones.exe` → **Ejecutar como administrador**. Sin esos permisos también funciona, pero solo ve las conexiones que siguen abiertas cada vez que revisa.
2. Déjalo abierto. Durante los **primeros 10 minutos aprende** qué programas usas y no avisa de ellos como nuevos.
3. Activa **Opciones → Iniciar con Windows** para que se abra solo junto al reloj al iniciar sesión, ya como administrador y sin preguntar.
4. Revisa de vez en cuando la pestaña **Alertas guardadas**: ahí queda todo lo sospechoso, aunque haya pasado mientras no mirabas.

Haz clic derecho sobre cualquier fila para investigarla en VirusTotal, AbuseIPDB o Google, o para bloquearla.

Para conocer cada parte de la ventana y qué hacer ante una alerta, lee la [guía de uso en PDF](Gu%C3%ADa%20del%20Monitor%20de%20conexiones.pdf).

## Qué detecta

Ninguna señal prueba por sí sola que algo sea un virus, pero cada una es una pista que vale la pena mirar.

| Señal | Riesgo | Necesita administrador |
|---|---|---|
| Un programa lee contraseñas, cookies o tarjetas del navegador, carteras de criptomonedas o la sesión de Discord, Telegram o Steam sin ser su dueño | Alto sin firma, Medio con firma | Sí |
| Conexión a un bot de Telegram, a webhooks de Discord, a sitios de subida anónima o a túneles | Alto sin firma, Medio con firma | Sí |
| Servidor o dominio de una lista negra | Alto o Medio según la lista | No |
| Programa que se conecta por primera vez | Medio, una sola vez | No |
| Cambió el archivo de un programa sin firma | Medio | No |
| Programa sin firma digital | Medio | No |
| Programa sin firma en Descargas o en una carpeta temporal | Alto | No |
| Programa con el nombre de uno de Windows, pero fuera de la carpeta de Windows | Alto | No |
| PowerShell, cmd u otras herramientas de Windows conectándose a Internet | Medio | No |
| Puertos de troyanos, de Tor o de minería de criptomonedas | Medio | No |
| El archivo del programa se borró después de conectarse | Medio | Sí |
| Conexiones que duran una fracción de segundo | Se evalúan como las demás | Sí |

Los programas de Windows y de Microsoft no generan avisos de «programa nuevo», y el propio navegador no genera avisos por leer sus contraseñas.

## Qué se conecta, qué guarda y qué cambia

- **No envía tus datos a ningún sitio.** Solo descarga una vez al día estas listas negras públicas:
  - [Feodo Tracker](https://feodotracker.abuse.ch/) (abuse.ch)
  - [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), IPv4 e IPv6
  - [URLhaus](https://urlhaus.abuse.ch/), a través de [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter)
  - [Emerging Threats](https://rules.emergingthreats.net/), dos listas
- **Pregunta a tu servidor DNS el nombre de cada IP** que aparece, para mostrarte a qué servidor va cada conexión.
- **VirusTotal, AbuseIPDB y Google solo se abren en tu navegador** cuando tú los eliges. A VirusTotal solo le llega la huella SHA-256 del archivo, nunca el archivo.
- **Guarda** las alertas, los programas conocidos, los ajustes y las listas en `%LOCALAPPDATA%\MonitorConexiones`.
- **Solo cambia Windows si tú lo eliges:** crea reglas del Firewall en el grupo «Monitor de conexiones» al bloquear algo o cortar Internet, y la tarea programada «MonitorConexiones» al activar Iniciar con Windows.

## Por qué un antivirus puede marcarlo como virus

Para reconocer a los programas que roban datos, el monitor tiene que saber qué buscan y adónde lo envían. Por eso su código incluye:

- los nombres de los archivos de contraseñas y cookies de los navegadores, de las carteras de criptomonedas y de las sesiones de Telegram, Discord y Steam ([Proteccion.cs](codigo/Proteccion.cs#L501-L625));
- los sitios a los que esos virus suelen enviar lo robado: la API de bots de Telegram, Discord, servicios de subida anónima y túneles ([Proteccion.cs](codigo/Proteccion.cs#L673-L710)).

Son reglas de detección, no objetivos. El monitor nunca abre, copia ni envía esos archivos: Windows solo le dice qué programa los abrió. Pero un análisis automático ve las mismas palabras que en un virus que roba datos, y Microsoft Defender marcó copias descargadas del programa como `Trojan:Win32/Wacatac.C!ml`. El «!ml» indica que lo decidió un modelo de aprendizaje automático, no una firma de virus concreta.

Un programa que compilas tú no llega marcado como descargado de Internet, que es cuando más se aplica ese análisis, y además te deja revisar cada línea antes. Si tu antivirus lo marca igualmente, no lo desactives ni añadas exclusiones: puedes enviarlo a Microsoft como falso positivo en [microsoft.com/wdsi/filesubmission](https://www.microsoft.com/wdsi/filesubmission).

## Desinstalar

1. Desactiva **Opciones → Iniciar con Windows**.
2. Usa **Protección → Quitar todos los bloqueos del monitor**.
3. Cierra el monitor con **Archivo → Salir del todo**.
4. Borra la carpeta del programa y la carpeta `%LOCALAPPDATA%\MonitorConexiones`.

## El código

Está escrito en C# con Windows Forms y no usa bibliotecas externas.

| Archivo | Qué contiene |
|---|---|
| [MonitorConexiones.cs](codigo/MonitorConexiones.cs) | Inicio del programa y evaluación del riesgo de cada conexión |
| [Ventana.cs](codigo/Ventana.cs) | La ventana, los menús y el icono de la bandeja |
| [CapturaTiempoReal.cs](codigo/CapturaTiempoReal.cs) | Captura en tiempo real con ETW: red, procesos, archivos y DNS |
| [Proteccion.cs](codigo/Proteccion.cs) | Firewall, inicio con Windows, listas negras y detector de robo de datos |
| [Registros.cs](codigo/Registros.cs) | Alertas guardadas, programas conocidos y ajustes |
| [Nativo.cs](codigo/Nativo.cs) | Llamadas a Windows: tabla de conexiones, firmas digitales y DNS inverso |
| [compilar.bat](codigo/compilar.bat) | Compila el programa |

## Autor

**Lucas Lopez** · [lucaslopez.com.ar](https://lucaslopez.com.ar)
