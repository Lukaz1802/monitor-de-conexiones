// Lo que el monitor guarda en disco, en %LOCALAPPDATA%\MonitorConexiones: ajustes, alertas y programas conocidos.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace MonitorConexiones
{
    static class Datos
    {
        // En el modo de prueba se usa otra carpeta para no mezclar sus datos con los reales.
        public static string Carpeta = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MonitorConexiones");

        public static string Ruta(string archivo)
        {
            return Path.Combine(Carpeta, archivo);
        }

        // Los campos de los archivos .tsv van separados por tabuladores: no pueden contener tabuladores ni saltos de línea.
        public static string Limpiar(string s)
        {
            return (s ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
        }

        public static bool LeerFecha(string texto, out DateTime fecha)
        {
            return DateTime.TryParse(texto, null, DateTimeStyles.RoundtripKind, out fecha);
        }
    }

    class Ajustes
    {
        readonly string ruta = Datos.Ruta("ajustes.txt");
        readonly Dictionary<string, string> valores = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public Ajustes()
        {
            try
            {
                if (!File.Exists(ruta)) return;
                foreach (string linea in File.ReadAllLines(ruta))
                {
                    int igual = linea.IndexOf('=');
                    if (igual > 0) valores[linea.Substring(0, igual).Trim()] = linea.Substring(igual + 1).Trim();
                }
            }
            catch (Exception) { }
        }

        public bool Leer(string clave, bool porDefecto)
        {
            string texto;
            bool valor;
            return valores.TryGetValue(clave, out texto) && bool.TryParse(texto, out valor) ? valor : porDefecto;
        }

        public void Escribir(string clave, bool valor)
        {
            valores[clave] = valor.ToString();
            try
            {
                Directory.CreateDirectory(Datos.Carpeta);
                File.WriteAllLines(ruta, valores.Select(x => x.Key + "=" + x.Value));
            }
            catch (Exception) { }
        }
    }

    // Alertas guardadas en disco para que sigan disponibles aunque se cierre el programa.
    class RegistroAlertas
    {
        const int Maximo = 5000;
        public readonly string Ruta;
        readonly Dictionary<string, Alerta> alertas = new Dictionary<string, Alerta>();
        bool cambios;

        public RegistroAlertas(string ruta)
        {
            Ruta = ruta;
            Cargar();
        }

        public IEnumerable<Alerta> Todas { get { return alertas.Values; } }
        public int Cantidad { get { return alertas.Count; } }

        static string ClaveDe(string proceso, string objetivo, string motivo)
        {
            return (proceso + "|" + objetivo + "|" + motivo).ToLowerInvariant();
        }

        // contar = false solo actualiza los datos si la alerta ya existía (para no contar dos veces lo que ya avisó la captura en tiempo real).
        public void Registrar(Conexion c, string origen, bool contar)
        {
            Alerta a = Obtener(ClaveDe(c.Proceso, c.IpRemota + ":" + c.PuertoRemoto, c.Motivo), c.Desde, origen, contar);
            a.Tipo = "Conexión";
            a.Detalle = "";
            a.Proceso = c.Proceso;
            a.Ruta = c.Ruta;
            a.Firmante = c.Firmante;
            a.Pid = c.Pid;
            a.IpRemota = c.IpRemota;
            a.PuertoRemoto = c.PuertoRemoto;
            a.Protocolo = c.Protocolo;
            a.Dominio = c.Dominio ?? a.Dominio;
            a.Riesgo = c.Riesgo;
            a.Motivo = c.Motivo;
        }

        public void Registrar(LecturaSospechosa l)
        {
            Alerta a = Obtener(ClaveDe(l.Proceso, "archivo:" + l.Categoria, l.Motivo), l.Hora, "Tiempo real", true);
            a.Tipo = "Archivo";
            a.Detalle = l.Archivo;
            a.Proceso = l.Proceso;
            a.Ruta = l.Ruta;
            a.Firmante = l.Firmante;
            a.Pid = l.Pid;
            a.Protocolo = "Archivo";
            a.Riesgo = l.Riesgo;
            a.Motivo = l.Motivo;
        }

        Alerta Obtener(string clave, DateTime cuando, string origen, bool contar)
        {
            Alerta a;
            if (!alertas.TryGetValue(clave, out a))
            {
                a = new Alerta { Clave = clave, Primera = cuando, Ultima = cuando, Origen = origen };
                alertas.Add(clave, a);
                contar = true;
            }
            if (contar) a.Veces++;
            if (cuando > a.Ultima) a.Ultima = cuando;
            cambios = true;
            return a;
        }

        public void Vaciar()
        {
            alertas.Clear();
            cambios = true;
            GuardarSiHayCambios();
        }

        public void GuardarSiHayCambios()
        {
            if (!cambios) return;
            cambios = false;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Ruta));
                var lineas = new List<string>
                {
                    "Primera vez\tÚltima vez\tVeces\tRiesgo\tPrograma\tIP remota\tPuerto\tProtocolo\tPor qué revisarla\tDetectada por\tUbicación\tFirmado por\tTipo\tDetalle\tDominio\tClave"
                };
                foreach (var a in alertas.Values.OrderByDescending(x => x.Ultima).Take(Maximo))
                {
                    var campos = new[]
                    {
                        a.Primera.ToString("o"), a.Ultima.ToString("o"), a.Veces.ToString(), a.Riesgo.ToString(), a.Proceso,
                        a.IpRemota != null ? a.IpRemota.ToString() : "-", a.PuertoRemoto.ToString(), a.Protocolo, a.Motivo, a.Origen,
                        a.Ruta, a.Firmante, a.Tipo, a.Detalle, a.Dominio, a.Clave
                    };
                    lineas.Add(string.Join("\t", campos.Select(Datos.Limpiar)));
                }
                File.WriteAllLines(Ruta, lineas, new UTF8Encoding(true));
            }
            catch (Exception) { cambios = true; } // se reintenta en la próxima actualización
        }

        void Cargar()
        {
            try
            {
                if (!File.Exists(Ruta)) return;
                foreach (var linea in File.ReadAllLines(Ruta).Skip(1))
                {
                    var p = linea.Split('\t');
                    DateTime primera, ultima;
                    int veces, riesgo, puerto;
                    IPAddress ip = null;
                    if (p.Length < 12 || !Datos.LeerFecha(p[0], out primera) || !Datos.LeerFecha(p[1], out ultima)
                        || !int.TryParse(p[2], out veces) || !int.TryParse(p[3], out riesgo) || !int.TryParse(p[6], out puerto)
                        || (p[5] != "-" && !IPAddress.TryParse(p[5], out ip))) continue;
                    var a = new Alerta
                    {
                        Primera = primera, Ultima = ultima, Veces = veces, Riesgo = riesgo, Proceso = p[4], IpRemota = ip, PuertoRemoto = puerto,
                        Protocolo = p[7], Motivo = p[8], Origen = p[9], Ruta = p[10], Firmante = p[11],
                        Tipo = p.Length > 12 && p[12].Length > 0 ? p[12] : "Conexión",
                        Detalle = p.Length > 13 ? p[13] : "",
                        Dominio = p.Length > 14 && p[14].Length > 0 ? p[14] : null
                    };
                    a.Clave = p.Length > 15 && p[15].Length > 0 ? p[15] : ClaveDe(a.Proceso, a.IpRemota + ":" + a.PuertoRemoto, a.Motivo);
                    alertas[a.Clave] = a;
                }
            }
            catch (Exception) { }
        }
    }

    // Recuerda qué programas han usado la red, para avisar cuando uno se conecta por primera vez o cuando su archivo cambia.
    // La primera vez que se abre el monitor aprende durante unos minutos lo que ya usas, sin avisar.
    class ProgramasConocidos
    {
        public class Programa : Entrada
        {
            public string Huella;                 // SHA-256 del archivo, solo en los programas sin firma (en los firmados manda la firma)
            public DateTime Primera, Ultima;
            public DateTime Nuevo, Modificado;    // cuándo se detectó como nuevo o como modificado (MinValue si nunca)
        }

        class EstadoArchivo
        {
            public DateTime Revisado, Fecha;
            public long Tamano;
        }

        public const int MinutosAprendizaje = 10, MinutosNovedad = 60;
        readonly object cerrojo = new object();
        readonly Dictionary<string, Programa> programas = new Dictionary<string, Programa>();
        readonly Dictionary<string, EstadoArchivo> archivos = new Dictionary<string, EstadoArchivo>(StringComparer.OrdinalIgnoreCase); // solo hilo de captura
        readonly string ruta = Datos.Ruta("programas.tsv");
        DateTime aprendizajeHasta;
        DateTime ultimoGuardado = DateTime.Now;
        bool cambios;

        public ProgramasConocidos()
        {
            if (!Cargar())
            {
                aprendizajeHasta = DateTime.Now.AddMinutes(MinutosAprendizaje);
                cambios = true;
            }
        }

        public DateTime AprendizajeHasta { get { return aprendizajeHasta; } }
        public bool Aprendiendo { get { return DateTime.Now < aprendizajeHasta; } }

        public int Cantidad
        {
            get { lock (cerrojo) return programas.Count; }
        }

        public List<Programa> Copia()
        {
            lock (cerrojo) return programas.Values.ToList();
        }

        // Anota que el programa usó la red. Devuelve el motivo de alerta si es nuevo o si su archivo cambió, o null.
        // sinAvisos: componentes de Windows, de Microsoft y de la Tienda, que se anotan pero no generan avisos.
        public string Comprobar(string rutaPrograma, string nombre, Firma firma, string firmante, bool sinAvisos)
        {
            DateTime ahora = DateTime.Now;
            string clave = firma.Valida && !string.IsNullOrEmpty(firma.Firmante)
                ? "firma:" + firma.Firmante.ToLowerInvariant() + "|" + Path.GetFileName(rutaPrograma).ToLowerInvariant()
                : "ruta:" + rutaPrograma.ToLowerInvariant();
            bool vigilarArchivo = !firma.Valida && !sinAvisos;

            bool esNuevo;
            lock (cerrojo) esNuevo = !programas.ContainsKey(clave);
            // La huella se calcula fuera del cerrojo para no congelar la ventana con archivos grandes.
            string huella = vigilarArchivo && (esNuevo || ArchivoCambio(rutaPrograma)) ? Huella(rutaPrograma) : null;

            // El motivo se devuelve solo en la conexión que lo descubre: así un programa nuevo genera una alerta, no una por servidor.
            // En la pestaña Programas sigue marcado como nuevo o modificado durante una hora.
            string motivo = null;
            lock (cerrojo)
            {
                Programa p;
                if (!programas.TryGetValue(clave, out p))
                {
                    p = new Programa { Clave = clave, Primera = ahora, Huella = huella ?? "" };
                    if (!sinAvisos && !Aprendiendo)
                    {
                        p.Nuevo = ahora;
                        motivo = "Programa nuevo: es la primera vez que se conecta a Internet. Si lo acabas de instalar o abrir tú, es normal";
                    }
                    programas.Add(clave, p);
                }
                else if (!string.IsNullOrEmpty(huella))
                {
                    if (p.Huella.Length > 0 && huella != p.Huella && !Aprendiendo)
                    {
                        p.Modificado = ahora;
                        motivo = "El archivo del programa cambió desde la última vez que se conectó (puede ser una actualización o una modificación)";
                    }
                    p.Huella = huella;
                }
                p.Ultima = ahora;
                p.Ruta = rutaPrograma;
                p.Proceso = nombre;
                p.Firmante = firmante;
                cambios = true;
            }
            return motivo;
        }

        // true si hay que recalcular la huella: primera vez en esta sesión, o el archivo cambió de tamaño o de fecha.
        bool ArchivoCambio(string rutaPrograma)
        {
            DateTime ahora = DateTime.Now;
            EstadoArchivo e;
            if (archivos.TryGetValue(rutaPrograma, out e) && (ahora - e.Revisado).TotalSeconds < 60) return false;
            try
            {
                var info = new FileInfo(rutaPrograma);
                bool cambio = e == null || info.Length != e.Tamano || info.LastWriteTimeUtc != e.Fecha;
                archivos[rutaPrograma] = new EstadoArchivo { Revisado = ahora, Tamano = info.Length, Fecha = info.LastWriteTimeUtc };
                return cambio;
            }
            catch (Exception) { return false; }
        }

        static string Huella(string rutaPrograma)
        {
            try
            {
                using (var fs = new FileStream(rutaPrograma, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var sha = SHA256.Create())
                    return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
            }
            catch (Exception) { return ""; }
        }

        public void GuardarSiHayCambios(bool ahoraMismo)
        {
            List<string> lineas;
            lock (cerrojo)
            {
                if (!cambios || (!ahoraMismo && (DateTime.Now - ultimoGuardado).TotalSeconds < 60)) return;
                cambios = false;
                ultimoGuardado = DateTime.Now;
                lineas = new List<string> { "#aprendizaje_hasta=" + aprendizajeHasta.ToString("o") };
                foreach (var p in programas.Values)
                    lineas.Add(string.Join("\t", new[] { p.Clave, p.Proceso, p.Ruta, p.Firmante, p.Huella, p.Primera.ToString("o"), p.Ultima.ToString("o") }.Select(Datos.Limpiar)));
            }
            try
            {
                Directory.CreateDirectory(Datos.Carpeta);
                File.WriteAllLines(ruta, lineas, new UTF8Encoding(true));
            }
            catch (Exception)
            {
                lock (cerrojo) cambios = true;
            }
        }

        // Devuelve false si todavía no existía el archivo (primera vez que se usa esta función).
        bool Cargar()
        {
            try
            {
                if (!File.Exists(ruta)) return false;
                foreach (string linea in File.ReadAllLines(ruta))
                {
                    DateTime fecha, primera, ultima;
                    if (linea.StartsWith("#aprendizaje_hasta="))
                    {
                        if (Datos.LeerFecha(linea.Substring(19), out fecha)) aprendizajeHasta = fecha;
                        continue;
                    }
                    var p = linea.Split('\t');
                    if (p.Length < 7 || !Datos.LeerFecha(p[5], out primera) || !Datos.LeerFecha(p[6], out ultima)) continue;
                    programas[p[0]] = new Programa
                    {
                        Clave = p[0], Proceso = p[1], Ruta = p[2], Firmante = p[3], Huella = p[4], Primera = primera, Ultima = ultima
                    };
                }
                return true;
            }
            catch (Exception) { return true; } // existe pero no se pudo leer: mejor no volver a aprender
        }
    }
}
