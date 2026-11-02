// Monitor de conexiones de red para Windows.
// Muestra en tiempo real qué programas se conectan a la red, marca lo que conviene revisar y ayuda a frenar el robo de datos.
// El código está repartido en varios archivos de esta carpeta; compilar.bat los compila todos juntos:
//   MonitorConexiones.cs  arranque, datos de cada conexión y evaluación del riesgo
//   Ventana.cs            la ventana, la bandeja del sistema y las acciones
//   CapturaTiempoReal.cs  los avisos del núcleo de Windows (conexiones, programas, archivos y DNS)
//   Proteccion.cs         firewall, inicio con Windows, listas negras y reglas contra el robo de datos
//   Registros.cs          lo que se guarda en disco: ajustes, alertas y programas conocidos
//   Nativo.cs             llamadas directas a Windows

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Monitor de conexiones de red")]
[assembly: AssemblyProduct("Monitor de conexiones de red")]
[assembly: AssemblyCompany(MonitorConexiones.Autoria.Nombre)]
[assembly: AssemblyCopyright("© 2026 " + MonitorConexiones.Autoria.Nombre + " · " + MonitorConexiones.Autoria.Web)]
[assembly: AssemblyVersion("1.2.0.0")]
[assembly: AssemblyFileVersion("1.2.0.0")]

namespace MonitorConexiones
{
    static class Autoria
    {
        public const string Nombre = "Lucas Lopez";
        public const string Web = "lucaslopez.com.ar";
        public const string Version = "1.2";
    }

    static class Programa
    {
        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        [STAThread]
        static void Main(string[] args)
        {
            // Modo de prueba sin ventana: guarda las conexiones actuales en un archivo de texto.
            if (args.Length >= 2 && args[0] == "--volcar")
            {
                var lineas = new List<string>();
                foreach (var c in new Recolector(null, null, null).Capturar())
                    lineas.Add(string.Join("\t", NivelRiesgo.Nombre(c.Riesgo), c.Proceso, c.Pid, c.Direccion, c.Estado, c.TextoRemoto, c.TextoLocal, c.Firmante, c.Ruta, c.Motivo));
                File.WriteAllLines(args[1], lineas, Encoding.UTF8);
                return;
            }

            // Al compilar con el monitor abierto, la versión anterior se renombra; aquí se borra cuando ya no está en uso.
            try { File.Delete(Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "MonitorConexiones.old.exe")); } catch { }

            // Modo de prueba: la ventana se dibuja fuera de la pantalla, guarda imágenes y se cierra, con sus datos aparte.
            bool captura = args.Length >= 2 && args[0] == "--captura";
            if (captura) Datos.Carpeta = Path.Combine(Path.GetDirectoryName(args[1]), Path.GetFileNameWithoutExtension(args[1]) + "_datos");

            // Tras «Abrir como administrador», la copia nueva espera a que se cierre la anterior.
            int pos = Array.IndexOf(args, "--esperar-pid");
            int pidAnterior;
            if (pos >= 0 && pos + 1 < args.Length && int.TryParse(args[pos + 1], out pidAnterior))
            {
                try { using (var anterior = Process.GetProcessById(pidAnterior)) anterior.WaitForExit(15000); }
                catch (ArgumentException) { } // ya se había cerrado
            }

            Mutex unico = null;
            if (!captura)
            {
                bool esLaPrimera;
                try { unico = new Mutex(true, "Local\\MonitorConexiones-Unico", out esLaPrimera); }
                catch (UnauthorizedAccessException) { esLaPrimera = false; } // la abrió una copia como administrador
                if (!esLaPrimera)
                {
                    // Ya hay un monitor abierto (quizá en la bandeja): se le pide que muestre su ventana.
                    InstanciaUnica.AvisarALaOtra();
                    return;
                }
            }

            try { SetProcessDPIAware(); } catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var ventana = new VentanaPrincipal();
            ventana.IniciarEnBandeja = args.Contains("--bandeja");
            if (captura)
            {
                ventana.RutaCaptura = args[1];
                ventana.StartPosition = FormStartPosition.Manual;
                ventana.Location = new Point(-30000, -30000);
                ventana.ShowInTaskbar = false;
            }
            Application.Run(ventana);
            GC.KeepAlive(unico);
        }
    }

    // Si ya hay un monitor abierto (por ejemplo en la bandeja), abrirlo otra vez muestra esa ventana en lugar de duplicarlo.
    static class InstanciaUnica
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern int RegisterWindowMessage(string nombre);

        [DllImport("user32.dll")]
        static extern bool PostMessage(IntPtr ventana, int mensaje, IntPtr w, IntPtr l);

        [DllImport("user32.dll")]
        static extern bool ChangeWindowMessageFilterEx(IntPtr ventana, int mensaje, int accion, IntPtr cambio);

        public static readonly int MensajeMostrar = RegisterWindowMessage("MonitorConexiones-Mostrar");

        public static void AvisarALaOtra()
        {
            PostMessage(new IntPtr(0xFFFF), MensajeMostrar, IntPtr.Zero, IntPtr.Zero); // a todas las ventanas
        }

        // Una copia abierta como administrador tiene que aceptar el aviso de una copia normal (Windows lo bloquea por defecto).
        public static void PermitirAviso(IntPtr ventana)
        {
            try { ChangeWindowMessageFilterEx(ventana, MensajeMostrar, 1, IntPtr.Zero); }
            catch (EntryPointNotFoundException) { }
        }
    }

    static class NivelRiesgo
    {
        public const int Ninguno = 0, Bajo = 1, Medio = 2, Alto = 3;

        public static readonly Color ColorAlto = Color.FromArgb(255, 199, 199);
        public static readonly Color ColorMedio = Color.FromArgb(255, 224, 178);
        public static readonly Color ColorBajo = Color.FromArgb(255, 246, 196);
        public static readonly Color ColorNueva = Color.FromArgb(212, 243, 212);

        public static string Nombre(int nivel)
        {
            switch (nivel)
            {
                case Alto: return "Alto";
                case Medio: return "Medio";
                case Bajo: return "Bajo";
                default: return "—";
            }
        }

        public static Color Fondo(int nivel, bool nueva)
        {
            if (nivel == Alto) return ColorAlto;
            if (nivel == Medio) return ColorMedio;
            if (nivel == Bajo) return ColorBajo;
            return nueva ? ColorNueva : Color.Empty;
        }
    }

    static class Tcp
    {
        public const int Cerrada = 1, Escuchando = 2, EsperaCierre = 11, Eliminandose = 12;

        public static string Nombre(int estado)
        {
            switch (estado)
            {
                case 1: return "Cerrada";
                case 2: return "En escucha";
                case 3:
                case 4: return "Conectando";
                case 5: return "Establecida";
                case 8: return "Cierre pendiente";
                case 11: return "Cerrada hace poco";
                case 12: return "Cerrada";
                default: return "Cerrándose";
            }
        }
    }

    static class Red
    {
        static readonly Dictionary<int, string> servicios = new Dictionary<int, string>
        {
            { 20, "FTP" }, { 21, "FTP" }, { 22, "SSH" }, { 23, "Telnet" }, { 25, "Correo (SMTP)" }, { 53, "DNS" },
            { 80, "Web (HTTP)" }, { 110, "Correo (POP3)" }, { 123, "Hora (NTP)" }, { 135, "RPC de Windows" },
            { 139, "Archivos compartidos" }, { 143, "Correo (IMAP)" }, { 443, "Web segura (HTTPS)" },
            { 445, "Archivos compartidos (SMB)" }, { 465, "Correo (SMTPS)" }, { 587, "Correo (SMTP)" }, { 853, "DNS cifrado" },
            { 993, "Correo (IMAPS)" }, { 995, "Correo (POP3S)" }, { 1433, "SQL Server" }, { 1883, "MQTT" },
            { 3306, "MySQL" }, { 3389, "Escritorio remoto" }, { 3478, "Llamadas (STUN)" }, { 5222, "Mensajería (XMPP)" },
            { 5228, "Notificaciones de Google" }, { 5353, "mDNS" }, { 5432, "PostgreSQL" }, { 5900, "VNC (control remoto)" },
            { 7680, "Optimización de distribución" }, { 8009, "Chromecast / Google Cast" }, { 8080, "Web alternativa" },
            { 8443, "Web segura alternativa" }, { 27017, "MongoDB" }
        };

        public static string Servicio(int puerto)
        {
            string s;
            return servicios.TryGetValue(puerto, out s) ? s : "";
        }

        public static string Formato(IPAddress ip)
        {
            if (ip == null) return "—";
            return ip.AddressFamily == AddressFamily.InterNetworkV6 ? "[" + ip + "]" : ip.ToString();
        }

        public static bool EsNula(IPAddress ip)
        {
            return ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any);
        }

        public static bool EsPrivada(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return true;
            byte[] b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)
                    || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC;
        }

        // Multidifusión y difusión: anuncios de la red local (mDNS, SSDP...), no conexiones con un equipo concreto.
        public static bool EsDifusion(IPAddress ip)
        {
            if (ip.AddressFamily == AddressFamily.InterNetworkV6) return ip.IsIPv6Multicast;
            return ip.GetAddressBytes()[0] >= 224;
        }
    }

    class Firma
    {
        public bool Valida, SinFirma, Alterada, Caducada, Desconocida, Borrado;
        public string Firmante;
    }

    // Datos comunes a una conexión, una entrada del historial, una alerta guardada y un programa conocido.
    class Entrada
    {
        public string Clave;
        public string Proceso;
        public string Ruta;
        public string Firmante;
        public int Riesgo;
        public string Motivo;
        public int Pid;
        public IPAddress IpRemota;
        public int PuertoRemoto;
        public string Dominio; // el nombre que pidió el programa al DNS (con la captura en tiempo real)
    }

    class Conexion : Entrada
    {
        public string ClaveHistorial;
        public string Protocolo;
        public IPAddress IpLocal;
        public int PuertoLocal;
        public int EstadoTcp;
        public string Estado;
        public string Direccion;
        public bool EsLocal;
        public DateTime Desde;

        public bool EnEscucha { get { return EstadoTcp == Tcp.Escuchando; } }
        public bool YaCerrada { get { return Pid == 0 || EstadoTcp == Tcp.Cerrada || EstadoTcp == Tcp.EsperaCierre || EstadoTcp == Tcp.Eliminandose; } }
        public string TextoLocal { get { return Red.Formato(IpLocal) + ":" + PuertoLocal; } }
        public string TextoRemoto { get { return EnEscucha ? "(en escucha)" : (Dominio ?? Red.Formato(IpRemota)) + ":" + PuertoRemoto; } }
    }

    class Visto : Entrada
    {
        public int Veces;
        public DateTime Primera, Ultima;
    }

    class Alerta : Entrada
    {
        public int Veces;
        public DateTime Primera, Ultima;
        public string Protocolo;
        public string Origen;
        public string Tipo;    // "Conexión" o "Archivo"
        public string Detalle; // en las de tipo archivo, qué archivo se leyó
    }

    // Una conexión avisada por Windows en el momento en que ocurre (captura en tiempo real).
    class EventoRed
    {
        public DateTime Hora;
        public int Pid;
        public string Protocolo;
        public bool Entrante;
        public IPAddress IpLocal, IpRemota;
        public int PuertoLocal, PuertoRemoto;
        public string Ruta;
    }

    // Un programa abrió un archivo de los que suelen robar los virus (contraseñas, cookies, carteras...).
    class EventoArchivo
    {
        public DateTime Hora;
        public int Pid;
        public string RutaProceso, Archivo, Categoria;
    }

    class LecturaSospechosa : Entrada
    {
        public DateTime Hora;
        public string Archivo, Categoria;
    }

    // Lee la tabla de conexiones TCP de Windows y evalúa cada conexión: su programa, su firma digital, su destino y su riesgo.
    class Recolector
    {
        class InfoProceso { public string Nombre, Ruta; }

        static readonly HashSet<string> nombresDeWindows = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "services.exe", "winlogon.exe", "wininit.exe", "explorer.exe",
            "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe", "dwm.exe", "sihost.exe",
            "runtimebroker.exe", "searchhost.exe", "lsm.exe", "taskmgr.exe", "ctfmon.exe"
        };

        // Programas legítimos de Windows que el malware usa a menudo para descargar o enviar datos.
        static readonly HashSet<string> herramientasAbusadas = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe",
            "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe",
            "cmstp.exe", "hh.exe", "msxsl.exe", "odbcconf.exe", "curl.exe"
        };

        static readonly Dictionary<int, string> puertosSospechosos = new Dictionary<int, string>
        {
            { 4444, "puerto típico de Metasploit y troyanos de acceso remoto" },
            { 1337, "puerto típico de herramientas de hacking" },
            { 31337, "puerto típico de puertas traseras" },
            { 5555, "puerto usado por algunos troyanos (y por ADB de Android)" },
            { 6666, "puerto de IRC, muy usado por botnets" },
            { 6667, "puerto de IRC, muy usado por botnets" },
            { 6697, "puerto de IRC, muy usado por botnets" },
            { 9001, "puerto de la red Tor" }, { 9030, "puerto de la red Tor" },
            { 9050, "puerto de la red Tor" }, { 9150, "puerto de la red Tor" },
            { 3333, "puerto típico de minería de criptomonedas" }, { 14433, "puerto típico de minería de criptomonedas" },
            { 14444, "puerto típico de minería de criptomonedas" }, { 45700, "puerto típico de minería de criptomonedas" }
        };

        readonly ListasNegras listas;
        readonly ProgramasConocidos conocidos;
        readonly Func<int, IPAddress, string> dominioDe; // dominio que pidió ese proceso para esa IP (captura en tiempo real)
        readonly Dictionary<int, InfoProceso> procesos = new Dictionary<int, InfoProceso>();
        readonly Dictionary<string, Firma> firmas = new Dictionary<string, Firma>(StringComparer.OrdinalIgnoreCase);
        readonly string carpetaWindows = Carpeta(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        readonly string carpetaProgramData = Carpeta(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        readonly string carpetaStore = Carpeta(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps"));
        readonly string rutaPropia = Application.ExecutablePath;
        readonly int pidPropio = Process.GetCurrentProcess().Id;

        public Recolector(ListasNegras listas, ProgramasConocidos conocidos, Func<int, IPAddress, string> dominioDe)
        {
            this.listas = listas;
            this.conocidos = conocidos;
            this.dominioDe = dominioDe;
        }

        static string Carpeta(string ruta)
        {
            return ruta.TrimEnd('\\').ToLowerInvariant() + "\\";
        }

        static string NombreVisible(int pid, string nombre)
        {
            return pid > 4 && !nombre.StartsWith("(") ? nombre + ".exe" : nombre;
        }

        static string ClaveHistorial(Conexion c)
        {
            return (c.Proceso + "|" + c.IpRemota + "|" + c.PuertoRemoto).ToLowerInvariant();
        }

        public static bool EsMicrosoft(string firmante)
        {
            return firmante != null && firmante.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        string Dominio(int pid, IPAddress ip)
        {
            return dominioDe != null && ip != null ? dominioDe(pid, ip) : null;
        }

        public List<Conexion> Capturar()
        {
            var nombres = new Dictionary<int, string>();
            foreach (var p in Process.GetProcesses())
            {
                try { nombres[p.Id] = p.ProcessName; } catch { }
                p.Dispose();
            }
            foreach (int pid in procesos.Keys.Where(x => !nombres.ContainsKey(x)).ToList())
                procesos.Remove(pid);

            var filas = Nativo.TablaTcp(Nativo.AF_INET);
            filas.AddRange(Nativo.TablaTcp(Nativo.AF_INET6));
            var puertosEnEscucha = new HashSet<int>(filas.Where(f => f.Estado == Tcp.Escuchando).Select(f => f.PuertoLocal));

            var lista = new List<Conexion>();
            foreach (var f in filas)
            {
                string nombre;
                if (f.Pid == 0) nombre = "(ninguno)";
                else if (!nombres.TryGetValue(f.Pid, out nombre)) nombre = "(programa ya cerrado)";
                var info = Proceso(f.Pid, nombre);

                var c = new Conexion
                {
                    Protocolo = f.Protocolo, Pid = f.Pid, Ruta = info.Ruta,
                    Proceso = info.Ruta.Length > 0 ? Path.GetFileName(info.Ruta) : NombreVisible(f.Pid, nombre),
                    IpLocal = f.IpLocal, PuertoLocal = f.PuertoLocal, IpRemota = f.IpRemota, PuertoRemoto = f.PuertoRemoto,
                    EstadoTcp = f.Estado, Estado = Tcp.Nombre(f.Estado)
                };
                c.EsLocal = !c.EnEscucha && (IPAddress.IsLoopback(c.IpRemota) || Red.EsNula(c.IpRemota));
                c.Direccion = c.EnEscucha ? "En escucha" : puertosEnEscucha.Contains(c.PuertoLocal) ? "Entrante" : "Saliente";
                if (!c.EnEscucha && !c.EsLocal) c.Dominio = Dominio(c.Pid, c.IpRemota);
                Firma firma = info.Ruta.Length > 0 ? ObtenerFirma(info.Ruta) : new Firma { Desconocida = true };
                c.Firmante = DescribirFirma(firma, info.Ruta);
                Evaluar(c, firma);
                c.Clave = string.Join("|", c.Protocolo, c.IpLocal, c.PuertoLocal, c.IpRemota, c.PuertoRemoto, c.Pid);
                c.ClaveHistorial = ClaveHistorial(c);
                lista.Add(c);
            }
            return lista;
        }

        // Convierte los avisos de la captura en tiempo real en conexiones evaluadas como las demás.
        public List<Conexion> Convertir(List<EventoRed> eventos)
        {
            var lista = new List<Conexion>();
            foreach (var ev in eventos)
            {
                string ruta, nombre;
                Identificar(ev.Pid, ev.Ruta, out ruta, out nombre);
                var c = new Conexion
                {
                    Protocolo = ev.Protocolo, Pid = ev.Pid, Ruta = ruta, Proceso = nombre,
                    IpLocal = ev.IpLocal, PuertoLocal = ev.PuertoLocal, IpRemota = ev.IpRemota, PuertoRemoto = ev.PuertoRemoto,
                    Estado = ev.Entrante ? "Conexión recibida" : ev.Protocolo.StartsWith("UDP") ? "Envío UDP" : "Conexión abierta",
                    Direccion = ev.Entrante ? "Entrante" : "Saliente", Desde = ev.Hora,
                    Dominio = Dominio(ev.Pid, ev.IpRemota)
                };
                Firma firma = ruta.Length > 0 ? ObtenerFirma(ruta) : new Firma { Desconocida = true };
                c.Firmante = DescribirFirma(firma, ruta);
                Evaluar(c, firma);
                c.Clave = "tr|" + ev.Protocolo + "|" + ev.PuertoLocal + "|" + ev.IpRemota + "|" + ev.PuertoRemoto + "|" + ev.Pid;
                c.ClaveHistorial = ClaveHistorial(c);
                lista.Add(c);
            }
            return lista;
        }

        // Decide cuáles de las lecturas de archivos sensibles son sospechosas (las de su propio programa no lo son).
        public List<LecturaSospechosa> EvaluarLecturas(List<EventoArchivo> eventos)
        {
            var lista = new List<LecturaSospechosa>();
            foreach (var ev in eventos)
            {
                if (ev.Pid <= 4 || ev.Pid == pidPropio) continue; // el núcleo de Windows y este monitor
                string ruta, nombre;
                Identificar(ev.Pid, ev.RutaProceso, out ruta, out nombre);
                if (EsPropio(ev.Pid, ruta)) continue;
                Firma firma = ruta.Length > 0 ? ObtenerFirma(ruta) : new Firma { Desconocida = true };
                string exe = nombre.ToLowerInvariant();
                if (DetectorRobo.EsDueno(ev.Categoria, exe, ruta, ev.Archivo, firma)) continue;

                string rutaMin = ruta.ToLowerInvariant();
                string que = DetectorRobo.Descripcion(ev.Categoria);
                int nivel;
                string motivo;
                if (herramientasAbusadas.Contains(exe))
                {
                    nivel = NivelRiesgo.Alto;
                    motivo = "Una herramienta de Windows (" + nombre + ") leyó " + que + ": muchos virus que roban datos lo hacen así, con scripts";
                }
                else if (rutaMin.StartsWith(carpetaWindows) || (firma.Valida && EsMicrosoft(firma.Firmante)))
                {
                    continue; // componentes de Windows y de Microsoft (antivirus, indexador de búsqueda...)
                }
                else if (!firma.Valida)
                {
                    nivel = NivelRiesgo.Alto;
                    motivo = "Un programa sin firma digital leyó " + que + ": así empiezan los virus que roban datos";
                }
                else
                {
                    nivel = NivelRiesgo.Medio;
                    motivo = "Un programa que no es el dueño de estos datos leyó " + que + ". Si no es tu antivirus ni tu programa de copias de seguridad, revísalo";
                }
                lista.Add(new LecturaSospechosa
                {
                    Hora = ev.Hora, Pid = ev.Pid, Proceso = nombre, Ruta = ruta, Firmante = DescribirFirma(firma, ruta),
                    Archivo = ev.Archivo, Categoria = ev.Categoria, Riesgo = nivel, Motivo = motivo
                });
            }
            return lista;
        }

        // Ruta y nombre del programa de un aviso en tiempo real, aunque el programa ya se haya cerrado.
        void Identificar(int pid, string rutaAviso, out string ruta, out string nombre)
        {
            InfoProceso info;
            procesos.TryGetValue(pid, out info);
            ruta = !string.IsNullOrEmpty(rutaAviso) ? rutaAviso : info != null ? info.Ruta : "";
            nombre = ruta.Length > 0 ? Path.GetFileName(ruta)
                : pid == 4 ? "System"
                : info != null ? NombreVisible(pid, info.Nombre) : "(programa ya cerrado)";
        }

        bool EsPropio(int pid, string ruta)
        {
            return pid == pidPropio || string.Equals(ruta, rutaPropia, StringComparison.OrdinalIgnoreCase);
        }

        InfoProceso Proceso(int pid, string nombre)
        {
            InfoProceso info;
            if (procesos.TryGetValue(pid, out info) && info.Nombre == nombre) return info;
            info = new InfoProceso { Nombre = nombre, Ruta = pid > 4 ? Nativo.RutaProceso(pid) : "" };
            procesos[pid] = info;
            return info;
        }

        Firma ObtenerFirma(string ruta)
        {
            Firma f;
            if (firmas.TryGetValue(ruta, out f)) return f;
            // Rutas que no son de disco (por ejemplo \Device\... sin traducir): no se puede comprobar.
            if (ruta.Length < 3 || ruta[1] != ':') return new Firma { Desconocida = true };
            if (!File.Exists(ruta)) return new Firma { Desconocida = true, Borrado = true };

            f = new Firma();
            switch (Nativo.VerificarFirma(ruta))
            {
                case 0: f.Valida = true; break;
                case 0x800B0100: f.SinFirma = true; break;      // TRUST_E_NOSIGNATURE
                case 0x80096010: f.Alterada = true; break;      // TRUST_E_BAD_DIGEST
                case 0x800B0101: f.Caducada = true; break;      // CERT_E_EXPIRED
                case 0x80070002:
                case 0x80070003:
                case 0x80070005:
                case 0x80070020: f.Desconocida = true; break;   // no se pudo leer el archivo
            }
            if (!f.SinFirma && !f.Desconocida)
            {
                try { f.Firmante = NombreFirmante(X509Certificate.CreateFromSignedFile(ruta).Subject); } catch { }
            }
            firmas[ruta] = f;
            return f;
        }

        static string NombreFirmante(string sujeto)
        {
            var m = Regex.Match(sujeto, @"(?:^|,\s*)O=(""[^""]*""|[^,]*)");
            if (!m.Success) m = Regex.Match(sujeto, @"(?:^|,\s*)CN=(""[^""]*""|[^,]*)");
            return m.Success ? m.Groups[1].Value.Trim('"', ' ') : sujeto;
        }

        string DescribirFirma(Firma f, string ruta)
        {
            if (ruta.Length == 0) return "";
            if (string.Equals(ruta, rutaPropia, StringComparison.OrdinalIgnoreCase)) return "(este monitor)";
            string r = ruta.ToLowerInvariant();
            if (f.Valida) return f.Firmante ?? "Firmado";
            if (f.Borrado) return "(archivo borrado)";
            if (f.Desconocida) return "(no se pudo comprobar)";
            if (f.Alterada) return "¡Firma alterada!";
            if (f.SinFirma) return r.StartsWith(carpetaWindows) ? "Windows" : r.StartsWith(carpetaStore) ? "Microsoft Store" : "Sin firma";
            if (f.Caducada) return "Caducada" + (f.Firmante != null ? ": " + f.Firmante : "");
            return "No reconocida" + (f.Firmante != null ? ": " + f.Firmante : "");
        }

        void Evaluar(Conexion c, Firma firma)
        {
            // Este mismo monitor (por ejemplo, al descargar las listas negras) no se evalúa.
            if (EsPropio(c.Pid, c.Ruta))
            {
                c.Riesgo = NivelRiesgo.Ninguno;
                c.Motivo = "";
                return;
            }

            int nivel = NivelRiesgo.Ninguno;
            var motivos = new List<string>();
            Action<int, string> marcar = (n, motivo) => { nivel = Math.Max(nivel, n); motivos.Add(motivo); };

            string ruta = c.Ruta.ToLowerInvariant();
            string exe = ruta.Length > 0 ? Path.GetFileName(ruta) : c.Proceso.ToLowerInvariant();
            bool enWindows = ruta.StartsWith(carpetaWindows);
            bool haciaFuera = !c.EnEscucha && !c.EsLocal;
            bool herramienta = herramientasAbusadas.Contains(exe);

            if (ruta.Length > 0)
            {
                if (firma.Borrado)
                    marcar(NivelRiesgo.Medio, "El archivo del programa ya no existe: se borró después de conectarse (algunos virus lo hacen para no dejar rastro)");

                if (nombresDeWindows.Contains(exe) && !enWindows)
                    marcar(NivelRiesgo.Alto, "Usa el nombre de un programa de Windows pero está fuera de la carpeta de Windows (truco típico del malware)");

                bool carpetaDudosa = ruta.Contains(@"\appdata\local\temp\") || ruta.Contains(@"\windows\temp\") || ruta.Contains(@"\downloads\")
                    || ruta.Contains(@"\users\public\") || ruta.Contains(@"\$recycle.bin\") || Carpeta(Path.GetDirectoryName(ruta)) == carpetaProgramData;
                if (carpetaDudosa)
                {
                    if (firma.Valida || firma.Desconocida) marcar(NivelRiesgo.Bajo, "Se ejecuta desde una carpeta temporal o de descargas (normal en instaladores)");
                    else marcar(NivelRiesgo.Alto, "Programa sin firma válida que se ejecuta desde una carpeta temporal o de descargas");
                }

                if (firma.Alterada)
                    marcar(NivelRiesgo.Alto, "La firma digital no corresponde al archivo: puede haber sido modificado");
                else if (firma.Caducada)
                    marcar(NivelRiesgo.Bajo, "Su firma digital está caducada");
                else if (!carpetaDudosa && firma.SinFirma && !enWindows && !ruta.StartsWith(carpetaStore))
                    marcar(NivelRiesgo.Medio, "El programa no tiene firma digital: no se puede saber quién lo hizo");
                else if (!carpetaDudosa && !firma.Valida && !firma.SinFirma && !firma.Desconocida)
                    marcar(NivelRiesgo.Medio, "Su firma digital no es válida o es de un emisor no reconocido");
            }

            if (haciaFuera && herramienta)
                marcar(NivelRiesgo.Medio, "Herramienta de Windows que el malware usa a menudo para conectarse a Internet. Si no la estás usando tú (o un programa que conoces), revísala");

            string puerto;
            if (haciaFuera && puertosSospechosos.TryGetValue(c.PuertoRemoto, out puerto))
                marcar(NivelRiesgo.Medio, "Puerto remoto " + c.PuertoRemoto + ": " + puerto);

            if (haciaFuera)
            {
                int nivelLista;
                string fuente;
                if (listas != null && (fuente = listas.BuscarIp(c.IpRemota, out nivelLista)) != null)
                    marcar(nivelLista, "La IP está en una lista negra de " + fuente);
                if (c.Dominio != null)
                {
                    if (listas != null && (fuente = listas.BuscarDominio(c.Dominio, out nivelLista)) != null)
                        marcar(nivelLista, "El dominio " + c.Dominio + " está en una lista negra de " + fuente);
                    int nivelDestino;
                    string destino = DetectorRobo.EvaluarDestino(c.Dominio, exe, herramienta || (!firma.Valida && !enWindows), out nivelDestino);
                    if (destino != null) marcar(nivelDestino, destino);
                }
                if (conocidos != null && ruta.Length > 0 && !firma.Borrado)
                {
                    bool sinAvisos = enWindows || ruta.StartsWith(carpetaStore) || (firma.Valida && EsMicrosoft(firma.Firmante));
                    string novedad = conocidos.Comprobar(c.Ruta, c.Proceso, firma, c.Firmante, sinAvisos);
                    if (novedad != null) marcar(NivelRiesgo.Medio, novedad);
                }
            }

            if (c.EnEscucha && nivel >= NivelRiesgo.Medio && !IPAddress.IsLoopback(c.IpLocal))
                motivos.Add("Además acepta conexiones desde otros equipos");

            c.Riesgo = nivel;
            c.Motivo = string.Join(" · ", motivos);
        }
    }
}
