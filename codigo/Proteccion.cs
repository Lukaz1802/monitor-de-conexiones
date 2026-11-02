// Protección: bloqueos con el Firewall de Windows, arranque con Windows, listas negras de servidores maliciosos
// y las reglas que delatan el robo de datos.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace MonitorConexiones
{
    // Bloqueos con el Firewall de Windows. Las reglas del monitor llevan el grupo «Monitor de conexiones» para encontrarlas y quitarlas.
    static class Cortafuegos
    {
        public const string Grupo = "Monitor de conexiones";
        const string PrefijoPrograma = "Monitor de conexiones: bloquear programa ";
        const string PrefijoIp = "Monitor de conexiones: bloquear IP ";
        const string CorteSalida = "Monitor de conexiones: CORTE DE INTERNET (salida)";
        const string CorteEntrada = "Monitor de conexiones: CORTE DE INTERNET (entrada)";
        const int ENTRADA = 1, SALIDA = 2, BLOQUEAR = 0, TODOS_LOS_PERFILES = 0x7FFFFFFF;

        public class Estado
        {
            public readonly HashSet<string> Programas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            public readonly HashSet<string> Ips = new HashSet<string>();
            public bool InternetCortado;
        }

        static dynamic Politica()
        {
            return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
        }

        // null si el firewall está activo en las redes que se usan ahora; si no, la explicación para el usuario.
        public static string ProblemaDelFirewall()
        {
            try
            {
                object politica = Politica();
                Type tipo = politica.GetType();
                int perfiles = (int)tipo.InvokeMember("CurrentProfileTypes", BindingFlags.GetProperty, null, politica, null);
                foreach (int perfil in new[] { 1, 2, 4 })
                    if ((perfiles & perfil) != 0 && !(bool)tipo.InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, politica, new object[] { perfil }))
                        return "El Firewall de Windows está desactivado en la red que usas, así que el bloqueo no tendría efecto.\n\n" +
                               "Actívalo en Seguridad de Windows → Firewall y protección de red.";
                return null;
            }
            catch (Exception ex)
            {
                return "No se pudo consultar el Firewall de Windows: " + ex.Message;
            }
        }

        public static Estado Leer()
        {
            var estado = new Estado();
            dynamic politica = Politica();
            foreach (dynamic regla in politica.Rules)
            {
                string grupo = regla.Grouping;
                if (grupo != Grupo) continue;
                string nombre = regla.Name;
                if (nombre == CorteSalida)
                {
                    estado.InternetCortado = true;
                }
                else if (nombre.StartsWith(PrefijoPrograma))
                {
                    string aplicacion = regla.ApplicationName;
                    if (!string.IsNullOrEmpty(aplicacion)) estado.Programas.Add(aplicacion);
                }
                else if (nombre.StartsWith(PrefijoIp))
                {
                    // Windows guarda una IP suelta como "1.2.3.4/255.255.255.255".
                    string direcciones = regla.RemoteAddresses;
                    IPAddress ip;
                    if (direcciones != null && IPAddress.TryParse(direcciones.Split('/')[0], out ip)) estado.Ips.Add(ip.ToString());
                }
            }
            return estado;
        }

        public static void BloquearPrograma(string ruta)
        {
            Agregar(PrefijoPrograma + ruta, "Impide que este programa se conecte a Internet.", SALIDA, ruta, null);
        }

        public static void DesbloquearPrograma(string ruta)
        {
            Quitar(regla => ((string)regla.Name).StartsWith(PrefijoPrograma) &&
                            string.Equals((string)regla.ApplicationName, ruta, StringComparison.OrdinalIgnoreCase));
        }

        public static void BloquearIp(IPAddress ip)
        {
            Agregar(PrefijoIp + ip + " (salida)", "Impide conectarse a esta IP.", SALIDA, null, ip.ToString());
            Agregar(PrefijoIp + ip + " (entrada)", "Impide que esta IP se conecte a este equipo.", ENTRADA, null, ip.ToString());
        }

        public static void DesbloquearIp(IPAddress ip)
        {
            string texto = ip.ToString();
            Quitar(regla =>
            {
                string direcciones = regla.RemoteAddresses;
                return ((string)regla.Name).StartsWith(PrefijoIp) && direcciones != null && direcciones.Split('/')[0] == texto;
            });
        }

        // Freno de emergencia: una regla que bloquea todo tiene prioridad sobre cualquier regla que permita.
        public static void CortarInternet()
        {
            Agregar(CorteSalida, "Corta todo el tráfico de salida. Quítala con «Restablecer Internet» en el monitor.", SALIDA, null, null);
            Agregar(CorteEntrada, "Corta todo el tráfico de entrada. Quítala con «Restablecer Internet» en el monitor.", ENTRADA, null, null);
        }

        public static void RestablecerInternet()
        {
            Quitar(regla => (string)regla.Name == CorteSalida || (string)regla.Name == CorteEntrada);
        }

        public static void QuitarTodo()
        {
            Quitar(regla => true);
        }

        static void Agregar(string nombre, string descripcion, int direccion, string programa, string direccionRemota)
        {
            dynamic regla = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            regla.Name = nombre;
            regla.Description = "Creada por el Monitor de conexiones. " + descripcion;
            if (programa != null) regla.ApplicationName = programa;
            if (direccionRemota != null) regla.RemoteAddresses = direccionRemota;
            regla.Direction = direccion;
            regla.Action = BLOQUEAR;
            regla.Profiles = TODOS_LOS_PERFILES;
            regla.Grouping = Grupo;
            regla.Enabled = true;
            Politica().Rules.Add(regla);
        }

        // Quita las reglas del monitor que cumplan la condición. Se quitan por nombre, una vez por cada regla encontrada.
        static void Quitar(Func<dynamic, bool> condicion)
        {
            dynamic politica = Politica();
            var nombres = new List<string>();
            foreach (dynamic regla in politica.Rules)
            {
                string grupo = regla.Grouping;
                if (grupo == Grupo && condicion(regla)) nombres.Add((string)regla.Name);
            }
            foreach (string nombre in nombres) politica.Rules.Remove(nombre);
        }
    }

    // Arranque automático con una tarea programada: así se abre en la bandeja y como administrador sin que Windows pregunte.
    static class InicioConWindows
    {
        const string NombreTarea = "MonitorConexiones";

        public static bool Activado()
        {
            string salida;
            return Ejecutar("/Query /TN \"" + NombreTarea + "\"", out salida) == 0;
        }

        // Ruta del programa que abre la tarea, para corregirla si se movió la carpeta. null si la tarea no existe.
        public static string RutaRegistrada()
        {
            string xml;
            if (Ejecutar("/Query /TN \"" + NombreTarea + "\" /XML", out xml) != 0) return null;
            var m = Regex.Match(xml, "<Command>(.*?)</Command>");
            return m.Success ? WebUtility.HtmlDecode(m.Groups[1].Value).Trim().Trim('"') : null;
        }

        public static void Activar(string rutaExe)
        {
            string archivo = Path.Combine(Path.GetTempPath(), "MonitorConexiones-tarea.xml");
            File.WriteAllText(archivo, CrearXml(rutaExe, WindowsIdentity.GetCurrent().Name), Encoding.Unicode);
            try
            {
                string salida;
                if (Ejecutar("/Create /TN \"" + NombreTarea + "\" /XML \"" + archivo + "\" /F", out salida) != 0)
                    throw new InvalidOperationException(salida.Trim());
            }
            finally
            {
                File.Delete(archivo);
            }
        }

        public static void Desactivar()
        {
            string salida;
            if (Ejecutar("/Delete /TN \"" + NombreTarea + "\" /F", out salida) != 0) throw new InvalidOperationException(salida.Trim());
        }

        // Tarea al iniciar sesión, con los máximos permisos del usuario, sin límite de tiempo y aunque el portátil use batería.
        public static string CrearXml(string rutaExe, string usuario)
        {
            string u = SecurityElement.Escape(usuario);
            return
                "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
                "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
                "  <RegistrationInfo>\r\n" +
                "    <Author>" + SecurityElement.Escape(Autoria.Nombre) + "</Author>\r\n" +
                "    <Description>Abre el Monitor de conexiones en la bandeja al iniciar sesión, con permisos de administrador.</Description>\r\n" +
                "  </RegistrationInfo>\r\n" +
                "  <Triggers>\r\n" +
                "    <LogonTrigger>\r\n" +
                "      <Enabled>true</Enabled>\r\n" +
                "      <UserId>" + u + "</UserId>\r\n" +
                "      <Delay>PT15S</Delay>\r\n" +
                "    </LogonTrigger>\r\n" +
                "  </Triggers>\r\n" +
                "  <Principals>\r\n" +
                "    <Principal id=\"Author\">\r\n" +
                "      <UserId>" + u + "</UserId>\r\n" +
                "      <LogonType>InteractiveToken</LogonType>\r\n" +
                "      <RunLevel>HighestAvailable</RunLevel>\r\n" +
                "    </Principal>\r\n" +
                "  </Principals>\r\n" +
                "  <Settings>\r\n" +
                "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n" +
                "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n" +
                "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n" +
                "    <AllowHardTerminate>true</AllowHardTerminate>\r\n" +
                "    <StartWhenAvailable>false</StartWhenAvailable>\r\n" +
                "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n" +
                "    <IdleSettings>\r\n" +
                "      <StopOnIdleEnd>false</StopOnIdleEnd>\r\n" +
                "      <RestartOnIdle>false</RestartOnIdle>\r\n" +
                "    </IdleSettings>\r\n" +
                "    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n" +
                "    <Enabled>true</Enabled>\r\n" +
                "    <Hidden>false</Hidden>\r\n" +
                "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n" +
                "    <WakeToRun>false</WakeToRun>\r\n" +
                "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n" +
                "    <Priority>5</Priority>\r\n" +
                "  </Settings>\r\n" +
                "  <Actions Context=\"Author\">\r\n" +
                "    <Exec>\r\n" +
                "      <Command>\"" + SecurityElement.Escape(rutaExe) + "\"</Command>\r\n" +
                "      <Arguments>--bandeja</Arguments>\r\n" +
                "      <WorkingDirectory>" + SecurityElement.Escape(Path.GetDirectoryName(rutaExe)) + "</WorkingDirectory>\r\n" +
                "    </Exec>\r\n" +
                "  </Actions>\r\n" +
                "</Task>\r\n";
        }

        static int Ejecutar(string argumentos, out string salida)
        {
            var info = new ProcessStartInfo("schtasks.exe", argumentos)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage),
                StandardErrorEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage)
            };
            using (var p = Process.Start(info))
            {
                var error = p.StandardError.ReadToEndAsync();
                salida = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                salida += error.Result;
                return p.ExitCode;
            }
        }
    }

    // Listas públicas y gratuitas de servidores maliciosos. Se descargan una vez al día y se guardan en disco.
    class ListasNegras
    {
        class Fuente
        {
            public string Archivo, Url, Nombre;
            public int Nivel;
            public bool Dominios, Json;
        }

        class Rango
        {
            public byte[] Red;
            public int Prefijo;
            public Fuente Fuente;

            public bool Contiene(byte[] ip)
            {
                if (ip.Length != Red.Length) return false;
                int bits = Prefijo;
                for (int i = 0; i < Red.Length && bits > 0; i++, bits -= 8)
                {
                    int mascara = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
                    if ((ip[i] & mascara) != (Red[i] & mascara)) return false;
                }
                return true;
            }
        }

        class Contenido
        {
            public readonly Dictionary<string, Fuente> Ips = new Dictionary<string, Fuente>();
            public readonly List<Rango> Rangos = new List<Rango>();
            public readonly Dictionary<string, Fuente> Dominios = new Dictionary<string, Fuente>(StringComparer.OrdinalIgnoreCase);
            public DateTime Fecha = DateTime.MinValue;
        }

        // En orden de prioridad: si una IP está en varias, se informa de la primera.
        static readonly Fuente[] fuentes =
        {
            new Fuente { Archivo = "feodo.txt", Url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                         Nombre = "servidores de control de botnets (Feodo Tracker, abuse.ch)", Nivel = NivelRiesgo.Alto },
            new Fuente { Archivo = "spamhaus_drop_v4.json", Url = "https://www.spamhaus.org/drop/drop_v4.json", Json = true,
                         Nombre = "redes en manos de delincuentes (Spamhaus DROP)", Nivel = NivelRiesgo.Alto },
            new Fuente { Archivo = "spamhaus_drop_v6.json", Url = "https://www.spamhaus.org/drop/drop_v6.json", Json = true,
                         Nombre = "redes en manos de delincuentes (Spamhaus DROP)", Nivel = NivelRiesgo.Alto },
            new Fuente { Archivo = "urlhaus_dominios.txt", Url = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt", Dominios = true,
                         Nombre = "sitios que reparten virus (URLhaus)", Nivel = NivelRiesgo.Alto },
            new Fuente { Archivo = "et_bloqueo.txt", Url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
                         Nombre = "servidores maliciosos (Emerging Threats)", Nivel = NivelRiesgo.Medio },
            new Fuente { Archivo = "et_comprometidos.txt", Url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                         Nombre = "equipos comprometidos (Emerging Threats)", Nivel = NivelRiesgo.Medio }
        };

        readonly ConcurrentDictionary<string, Fuente> cacheIps = new ConcurrentDictionary<string, Fuente>();
        readonly string carpeta = Path.Combine(Datos.Carpeta, "listas");
        volatile Contenido actual = new Contenido();
        volatile bool descargando;
        volatile string ultimoError;

        // Carga lo guardado y, si tiene más de un día (o no existe), lo descarga de nuevo. Todo en segundo plano.
        public void Iniciar()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                Cargar();
                Descargar(false);
            });
        }

        public void ActualizarAhora()
        {
            ThreadPool.QueueUserWorkItem(_ => Descargar(true));
        }

        public string Resumen
        {
            get
            {
                var c = actual;
                if (descargando) return "Listas negras: descargando…";
                if (c.Fecha == DateTime.MinValue) return "Listas negras: sin descargar" + (ultimoError != null ? " (" + ultimoError + ")" : "");
                return string.Format("Listas negras: {0:N0} IPs y redes, {1:N0} dominios · {2}", c.Ips.Count + c.Rangos.Count, c.Dominios.Count,
                    c.Fecha.Date == DateTime.Today ? "al día" : "del " + c.Fecha.ToString("dd/MM"));
            }
        }

        public string BuscarIp(IPAddress ip, out int nivel)
        {
            nivel = NivelRiesgo.Ninguno;
            if (ip == null || Red.EsPrivada(ip)) return null;
            string clave = ip.ToString();
            Fuente f;
            if (!cacheIps.TryGetValue(clave, out f))
            {
                var c = actual;
                if (!c.Ips.TryGetValue(clave, out f))
                {
                    byte[] bytes = ip.GetAddressBytes();
                    var rango = c.Rangos.FirstOrDefault(r => r.Contiene(bytes));
                    f = rango != null ? rango.Fuente : null;
                }
                cacheIps[clave] = f;
            }
            if (f == null) return null;
            nivel = f.Nivel;
            return f.Nombre;
        }

        public string BuscarDominio(string dominio, out int nivel)
        {
            nivel = NivelRiesgo.Ninguno;
            Fuente f;
            if (string.IsNullOrEmpty(dominio) || !actual.Dominios.TryGetValue(dominio, out f)) return null;
            nivel = f.Nivel;
            return f.Nombre;
        }

        void Descargar(bool siempre)
        {
            if (descargando) return;
            descargando = true;
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
                Directory.CreateDirectory(carpeta);
                bool algunaNueva = false;
                ultimoError = null;
                foreach (var f in fuentes)
                {
                    string ruta = Path.Combine(carpeta, f.Archivo);
                    if (!siempre && File.Exists(ruta) && (DateTime.Now - File.GetLastWriteTime(ruta)).TotalHours < 24) continue;
                    try
                    {
                        string texto = Bajar(f.Url);
                        if (texto.Length > 0)
                        {
                            File.WriteAllText(ruta, texto, Encoding.UTF8);
                            algunaNueva = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        ultimoError = ex is WebException ? "sin conexión con " + new Uri(f.Url).Host : ex.Message;
                    }
                }
                if (algunaNueva) Cargar();
            }
            finally
            {
                descargando = false;
            }
        }

        static string Bajar(string url)
        {
            var peticion = (HttpWebRequest)WebRequest.Create(url);
            peticion.UserAgent = "MonitorConexiones/" + Autoria.Version;
            peticion.Timeout = 30000;
            peticion.ReadWriteTimeout = 30000;
            peticion.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            using (var respuesta = (HttpWebResponse)peticion.GetResponse())
            using (var lector = new StreamReader(respuesta.GetResponseStream(), Encoding.UTF8))
                return lector.ReadToEnd();
        }

        void Cargar()
        {
            var c = new Contenido();
            foreach (var f in fuentes)
            {
                string ruta = Path.Combine(carpeta, f.Archivo);
                if (!File.Exists(ruta)) continue;
                try
                {
                    DateTime fecha = File.GetLastWriteTime(ruta);
                    if (fecha > c.Fecha) c.Fecha = fecha;
                    foreach (string bruta in File.ReadLines(ruta))
                    {
                        string linea = bruta.Trim();
                        if (linea.Length == 0 || linea[0] == '#' || linea[0] == ';' || linea[0] == '!') continue;
                        if (f.Dominios)
                        {
                            // Formato de archivo hosts: "0.0.0.0 dominio".
                            var partes = linea.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            string dominio = partes[partes.Length - 1].ToLowerInvariant();
                            if (dominio.Contains('.') && !c.Dominios.ContainsKey(dominio)) c.Dominios[dominio] = f;
                            continue;
                        }
                        if (f.Json)
                        {
                            var m = Regex.Match(linea, "\"cidr\"\\s*:\\s*\"([^\"]+)\"");
                            if (!m.Success) continue;
                            linea = m.Groups[1].Value;
                        }
                        Anotar(c, linea, f);
                    }
                }
                catch (Exception) { } // un archivo dañado no impide usar los demás
            }
            actual = c;
            cacheIps.Clear();
        }

        static void Anotar(Contenido c, string texto, Fuente f)
        {
            IPAddress ip;
            int barra = texto.IndexOf('/');
            if (barra < 0)
            {
                if (IPAddress.TryParse(texto, out ip) && !c.Ips.ContainsKey(ip.ToString())) c.Ips[ip.ToString()] = f;
                return;
            }
            int prefijo;
            if (IPAddress.TryParse(texto.Substring(0, barra), out ip) && int.TryParse(texto.Substring(barra + 1), out prefijo))
                c.Rangos.Add(new Rango { Red = ip.GetAddressBytes(), Prefijo = prefijo, Fuente = f });
        }
    }

    // Reglas contra el robo de datos: qué archivos suelen robar los virus (y qué programas son sus dueños legítimos),
    // y a qué destinos suelen mandar lo robado.
    static class DetectorRobo
    {
        public const string Contrasenas = "contrasenas", Cookies = "cookies", Tarjetas = "tarjetas", ClaveNavegador = "clave-navegador",
            ContrasenasFirefox = "contrasenas-firefox", CookiesFirefox = "cookies-firefox", Cartera = "cartera",
            CarteraNavegador = "cartera-navegador", Discord = "discord", Telegram = "telegram", Steam = "steam", FileZilla = "filezilla";

        // Extensiones de carteras de criptomonedas para Chrome y Edge: MetaMask, Phantom, Coinbase, Trust, Binance, Ronin.
        static readonly string[] extensionesCartera =
        {
            "nkbihfbeogaeaoehlefnkodbefgpgknn", "ejbalbakoplchlghecdalmeeeajnimhm", "bfnaelmomeimhlpmgjnjophhpkkoljpa",
            "hnfanknocfeofbddgcijnmhnfnkdnaad", "egjidjbpglichdcondbcbdnbeeppgdph", "fhbohimaelbohpjbbldcngcnapndodjp",
            "fnjhmkhhmkbjkkabndcnnogagogbneec"
        };

        static readonly string[] carpetasCartera =
        {
            @"\exodus\exodus.wallet\", @"\electrum\wallets\", @"\ethereum\keystore\", @"\atomic\local storage\",
            @"\bitcoin\wallets\", @"\com.liberty.jaxx\", @"\guarda\local storage\", @"\coinomi\coinomi\wallets\", @"\armory\"
        };

        static readonly HashSet<string> navegadores = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "chrome.exe", "msedge.exe", "msedgewebview2.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe", "chromium.exe",
            "arc.exe", "thorium.exe", "firefox.exe", "waterfox.exe", "librewolf.exe", "floorp.exe", "iexplore.exe", "tor.exe"
        };

        class Dueno
        {
            public string[] Programas;  // nombres de archivo (con firma digital válida)
            public string[] Firmantes;  // o cualquier programa firmado por alguno de estos (texto contenido en el firmante)
        }

        static readonly Dueno duenoChromium = new Dueno
        {
            Programas = new[] { "chrome.exe", "msedge.exe", "msedgewebview2.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe",
                                "chromium.exe", "arc.exe", "thorium.exe", "elevation_service.exe" },
            Firmantes = new[] { "google", "brave software", "opera norway", "vivaldi technologies", "yandex" }
        };

        static readonly Dictionary<string, Dueno> duenos = new Dictionary<string, Dueno>
        {
            { Contrasenas, duenoChromium }, { Cookies, duenoChromium }, { Tarjetas, duenoChromium }, { ClaveNavegador, duenoChromium },
            { CarteraNavegador, duenoChromium },
            { ContrasenasFirefox, new Dueno { Programas = new[] { "firefox.exe", "thunderbird.exe", "waterfox.exe", "librewolf.exe", "floorp.exe" }, Firmantes = new[] { "mozilla" } } },
            { CookiesFirefox, new Dueno { Programas = new[] { "firefox.exe", "waterfox.exe", "librewolf.exe", "floorp.exe" }, Firmantes = new[] { "mozilla" } } },
            { Discord, new Dueno { Programas = new[] { "discord.exe", "discordcanary.exe", "discordptb.exe" }, Firmantes = new[] { "discord" } } },
            { Telegram, new Dueno { Programas = new[] { "telegram.exe" }, Firmantes = new[] { "telegram" } } },
            { Steam, new Dueno { Programas = new[] { "steam.exe", "steamwebhelper.exe", "steamservice.exe" }, Firmantes = new[] { "valve" } } },
            { FileZilla, new Dueno { Programas = new[] { "filezilla.exe", "fzsftp.exe" }, Firmantes = new[] { "tim kosse" } } },
            { Cartera, new Dueno { Programas = new string[0], Firmantes = new[] { "exodus", "electrum", "atomic", "bitcoin", "guarda", "coinomi" } } }
        };

        static readonly Dictionary<string, string> descripciones = new Dictionary<string, string>
        {
            { Contrasenas, "las contraseñas guardadas del navegador" },
            { Cookies, "las cookies del navegador (tus sesiones abiertas)" },
            { Tarjetas, "las tarjetas y los datos de autocompletar del navegador" },
            { ClaveNavegador, "la clave que protege las contraseñas del navegador" },
            { ContrasenasFirefox, "las contraseñas guardadas de Firefox" },
            { CookiesFirefox, "las cookies de Firefox (tus sesiones abiertas)" },
            { Cartera, "una cartera de criptomonedas" },
            { CarteraNavegador, "una cartera de criptomonedas del navegador (como MetaMask)" },
            { Discord, "la sesión de Discord (su llave de acceso)" },
            { Telegram, "la sesión de Telegram" },
            { Steam, "la sesión de Steam" },
            { FileZilla, "las contraseñas guardadas de FileZilla" }
        };

        public static string Descripcion(string categoria)
        {
            string d;
            return descripciones.TryGetValue(categoria, out d) ? d : "datos sensibles";
        }

        static bool Contiene(string texto, string parte)
        {
            return texto.IndexOf(parte, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static bool EnNavegadorChromium(string ruta)
        {
            return Contiene(ruta, @"\user data\") || Contiene(ruta, @"\opera software\");
        }

        // Clasifica una ruta (de disco o del núcleo, \Device\...) y devuelve la categoría si es un archivo sensible, o null.
        // Se llama por cada archivo que se abre en el equipo, así que primero mira solo el nombre del archivo.
        public static string Clasificar(string ruta)
        {
            if (ruta == null || ruta.Length < 12) return null;
            int barra = ruta.LastIndexOf('\\');
            if (barra < 0 || barra == ruta.Length - 1) return null;
            string archivo = ruta.Substring(barra + 1).ToLowerInvariant();
            switch (archivo)
            {
                case "login data":
                case "login data for account":
                    return EnNavegadorChromium(ruta) ? Contrasenas : null;
                case "cookies":
                    return EnNavegadorChromium(ruta) ? Cookies : null;
                case "web data":
                    return EnNavegadorChromium(ruta) ? Tarjetas : null;
                case "local state":
                    return EnNavegadorChromium(ruta) ? ClaveNavegador : null;
                case "logins.json":
                case "key4.db":
                case "key3.db":
                case "signons.sqlite":
                    return Contiene(ruta, @"\mozilla\firefox\profiles\") || Contiene(ruta, @"\thunderbird\profiles\") ? ContrasenasFirefox : null;
                case "cookies.sqlite":
                    return Contiene(ruta, @"\mozilla\firefox\profiles\") ? CookiesFirefox : null;
                case "wallet.dat":
                    return Cartera;
                case "loginusers.vdf":
                case "config.vdf":
                    return Contiene(ruta, @"\steam\config\") ? Steam : null;
                case "sitemanager.xml":
                case "recentservers.xml":
                    return Contiene(ruta, @"\filezilla\") ? FileZilla : null;
            }
            if (archivo.StartsWith("ssfn") && Contiene(ruta, @"\steam\")) return Steam;

            if (Contiene(ruta, @"\local storage\leveldb\") &&
                (Contiene(ruta, @"\discord\") || Contiene(ruta, @"\discordcanary\") || Contiene(ruta, @"\discordptb\") || Contiene(ruta, @"\lightcord\")))
                return Discord;
            if (Contiene(ruta, @"\telegram desktop\tdata\")) return Telegram;
            foreach (string carpeta in carpetasCartera)
                if (Contiene(ruta, carpeta)) return Cartera;
            if (Contiene(ruta, @"\local extension settings\") || Contiene(ruta, @"\indexeddb\chrome-extension_"))
                foreach (string id in extensionesCartera)
                    if (Contiene(ruta, id)) return CarteraNavegador;
            return null;
        }

        // true si el programa es el dueño legítimo de esos datos (el propio navegador, el propio Discord...).
        public static bool EsDueno(string categoria, string exe, string rutaPrograma, string rutaArchivo, Firma firma)
        {
            Dueno d;
            if (!duenos.TryGetValue(categoria, out d)) return false;
            if (firma.Valida && d.Programas.Contains(exe, StringComparer.OrdinalIgnoreCase)) return true;
            if (firma.Valida && firma.Firmante != null && d.Firmantes.Any(f => Contiene(firma.Firmante, f))) return true;
            if (categoria == Cartera && d.Firmantes.Any(f => Contiene(exe, f))) return true; // carteras que no siempre están firmadas
            // Programas que guardan su propio navegador interno junto a sus datos: ...\Empresa\Programa\User Data\...
            int pos = rutaArchivo.IndexOf(@"\User Data\", StringComparison.OrdinalIgnoreCase);
            if (pos > 3 && rutaPrograma.StartsWith(rutaArchivo.Substring(0, pos) + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            // Apps de la Tienda: su navegador interno guarda los datos en su propia carpeta de paquete.
            string paquete = PaqueteDe(rutaPrograma);
            return paquete != null && Contiene(rutaArchivo, @"\Packages\" + paquete + @"\");
        }

        // Nombre de familia del paquete de una app de la Tienda a partir de su carpeta de instalación:
        // ...\WindowsApps\Claude_4.4212.0.0_x64__pzs8sxrjxfjjc\... -> Claude_pzs8sxrjxfjjc
        static string PaqueteDe(string rutaPrograma)
        {
            const string marca = @"\WindowsApps\";
            int inicio = rutaPrograma.IndexOf(marca, StringComparison.OrdinalIgnoreCase);
            if (inicio < 0) return null;
            inicio += marca.Length;
            int fin = rutaPrograma.IndexOf('\\', inicio);
            string carpeta = fin < 0 ? rutaPrograma.Substring(inicio) : rutaPrograma.Substring(inicio, fin - inicio);
            int guion = carpeta.IndexOf('_');
            int editor = carpeta.LastIndexOf("__", StringComparison.Ordinal);
            return guion > 0 && editor > guion ? carpeta.Substring(0, guion) + "_" + carpeta.Substring(editor + 2) : null;
        }

        class Destino
        {
            public string[] Dominios;
            public string[] Clientes; // programas que lo usan legítimamente (además de los navegadores)
            public string Motivo;
            public bool Leve;         // solo informativo
        }

        static readonly Destino[] destinos =
        {
            new Destino
            {
                Dominios = new[] { "api.telegram.org" }, Clientes = new string[0],
                Motivo = "Se conecta a la API de bots de Telegram: los virus que roban datos la usan mucho para enviar lo robado"
            },
            new Destino
            {
                Dominios = new[] { "discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com" },
                Clientes = new[] { "discord.exe", "discordcanary.exe", "discordptb.exe" },
                Motivo = "Se conecta a Discord sin ser Discord: los virus que roban datos usan sus webhooks para enviar lo robado"
            },
            new Destino
            {
                Dominios = new[] { "transfer.sh", "file.io", "gofile.io", "anonfiles.com", "sendspace.com", "catbox.moe", "tmpfiles.org",
                                   "bashupload.com", "temp.sh", "pixeldrain.com", "uguu.se", "0x0.st", "filebin.net", "oshi.at", "ufile.io",
                                   "pastebin.com", "paste.ee", "hastebin.com", "rentry.co", "ghostbin.site" },
                Clientes = new string[0],
                Motivo = "Se conecta a un servicio de subida anónima de archivos o textos, muy usado para sacar datos robados"
            },
            new Destino
            {
                Dominios = new[] { "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev", "trycloudflare.com", "serveo.net", "localtonet.com",
                                   "loca.lt", "portmap.io", "portmap.host", "duckdns.org", "ddns.net", "no-ip.com", "no-ip.org", "no-ip.biz",
                                   "noip.com", "hopto.org", "zapto.org", "sytes.net", "servebeer.com", "serveftp.com", "myftp.biz",
                                   "myddns.me", "dynu.net", "freeddns.org", "linkpc.net" },
                Clientes = new[] { "ngrok.exe", "cloudflared.exe", "duc.exe", "duc30.exe", "duckdns.exe" },
                Motivo = "Se conecta a un servidor detrás de un túnel o de un DNS dinámico, muy usado por los virus de control remoto"
            },
            new Destino
            {
                Dominios = new[] { "ip-api.com", "ipinfo.io", "api.ipify.org", "icanhazip.com", "checkip.amazonaws.com", "ipwho.is",
                                   "ifconfig.me", "myexternalip.com", "wtfismyip.com", "freegeoip.app", "ipapi.co", "geolocation-db.com" },
                Clientes = new string[0], Leve = true,
                Motivo = "Consulta tu IP pública y tu ubicación (es lo primero que hacen muchos virus que roban datos)"
            }
        };

        // Motivo de alerta si un programa que no es un navegador ni el cliente oficial se conecta a un destino típico de robo.
        public static string EvaluarDestino(string dominio, string exe, bool sinFirmaFiable, out int nivel)
        {
            nivel = NivelRiesgo.Ninguno;
            if (navegadores.Contains(exe)) return null;
            foreach (var d in destinos)
            {
                if (!d.Dominios.Any(x => dominio == x || dominio.EndsWith("." + x))) continue;
                if (d.Clientes.Contains(exe, StringComparer.OrdinalIgnoreCase)) return null;
                nivel = d.Leve ? NivelRiesgo.Bajo : sinFirmaFiable ? NivelRiesgo.Alto : NivelRiesgo.Medio;
                return d.Motivo + " (" + dominio + ")";
            }
            return null;
        }
    }
}
