// Captura en tiempo real con ETW, el registro de eventos del núcleo de Windows (el mismo que usa el Monitor de recursos).
// Windows avisa en el momento en que ocurre cada cosa, así que no se escapa nada aunque dure un instante:
//   - cada conexión TCP que se abre y cada envío UDP,
//   - cada programa que se inicia (para saber su nombre aunque se cierre enseguida),
//   - cada archivo que se abre (solo se quedan los que suelen robar los virus: contraseñas, cookies, carteras...),
//   - cada consulta DNS (para saber el dominio real detrás de cada IP).
// Necesita permisos de administrador y Windows de 64 bits.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace MonitorConexiones
{
    class CapturaTiempoReal
    {
        static readonly Guid ProveedorRed = new Guid("7DD42A49-5329-4832-8DFD-43D979153A88");      // Microsoft-Windows-Kernel-Network
        static readonly Guid ProveedorProcesos = new Guid("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"); // Microsoft-Windows-Kernel-Process
        static readonly Guid ProveedorArchivos = new Guid("EDD08927-9CC4-4E65-B970-C2560FB5C289"); // Microsoft-Windows-Kernel-File
        static readonly Guid ProveedorDns = new Guid("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");      // Microsoft-Windows-DNS-Client
        const int DATA1_RED = 0x7DD42A49, DATA1_PROCESOS = 0x22FB2CD6, DATA1_DNS = 0x1C95126E;
        static readonly int DATA1_ARCHIVOS = unchecked((int)0xEDD08927);
        const int TamPropiedades = 120;  // sizeof(EVENT_TRACE_PROPERTIES) en 64 bits
        const int TamLogfile = 448;      // sizeof(EVENT_TRACE_LOGFILEW) en 64 bits
        const int MaximoEnCola = 20000;

        const uint ERROR_ACCESS_DENIED = 5, ERROR_ALREADY_EXISTS = 183, EVENT_TRACE_CONTROL_STOP = 1;
        const int WNODE_FLAG_TRACED_GUID = 0x00020000, EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
        const int PROCESS_TRACE_MODE_REAL_TIME = 0x00000100, PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
        const int EVENT_HEADER_FLAG_32_BIT_HEADER = 0x20;

        delegate void RegistroCallback(IntPtr registro);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern uint StartTrace(out ulong sesion, string nombre, IntPtr propiedades);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern uint ControlTrace(ulong sesion, string nombre, IntPtr propiedades, uint control);

        [DllImport("advapi32.dll")]
        static extern uint EnableTraceEx2(ulong sesion, ref Guid proveedor, uint control, byte nivel, ulong algunaPalabraClave,
            ulong todasLasPalabrasClave, uint espera, IntPtr parametros);

        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenTraceW")]
        static extern ulong OpenTrace(IntPtr logfile);

        [DllImport("advapi32.dll")]
        static extern uint ProcessTrace(ulong[] consumidores, uint cantidad, IntPtr inicio, IntPtr fin);

        [DllImport("advapi32.dll")]
        static extern uint CloseTrace(ulong consumidor);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern uint QueryDosDevice(string unidad, StringBuilder destino, int tamano);

        readonly string nombreSesion;
        readonly int pidPropio = Process.GetCurrentProcess().Id;
        readonly ConcurrentQueue<EventoRed> cola = new ConcurrentQueue<EventoRed>();
        readonly ConcurrentQueue<EventoArchivo> colaArchivos = new ConcurrentQueue<EventoArchivo>();
        readonly ConcurrentDictionary<int, string> imagenes = new ConcurrentDictionary<int, string>();        // PID -> ruta, desde el aviso de inicio de proceso
        readonly ConcurrentDictionary<string, string> dominios = new ConcurrentDictionary<string, string>();  // IP -> último dominio pedido
        readonly ConcurrentDictionary<string, string> dominiosPorProceso = new ConcurrentDictionary<string, string>(); // "PID|IP" -> dominio
        readonly ConcurrentQueue<string> muestrasDns = new ConcurrentQueue<string>();
        readonly Dictionary<string, DateTime> recientes = new Dictionary<string, DateTime>();             // solo se usa en el hilo de captura
        readonly List<KeyValuePair<string, string>> unidades = new List<KeyValuePair<string, string>>(); // \Device\HarddiskVolume3 -> C:
        readonly int[] eventosRed = new int[64];
        int eventosProcesos, eventosArchivos, eventosDns, lecturasSensibles;
        RegistroCallback callback; // referencia para que el recolector de basura no lo libere mientras Windows lo usa
        IntPtr propiedades;
        ulong sesion, consumidor;
        volatile bool activa;
        int descartados;

        public CapturaTiempoReal(string nombreSesion)
        {
            this.nombreSesion = nombreSesion;
        }

        public bool Activa { get { return activa; } }
        public string Error { get; private set; }

        public bool Iniciar()
        {
            if (!Environment.Is64BitProcess)
            {
                Error = "necesita Windows de 64 bits";
                return false;
            }
            foreach (string unidad in Environment.GetLogicalDrives())
            {
                string letra = unidad.TrimEnd('\\');
                var destino = new StringBuilder(1024);
                if (QueryDosDevice(letra, destino, destino.Capacity) > 0)
                    unidades.Add(new KeyValuePair<string, string>(destino.ToString(), letra));
            }

            propiedades = Marshal.AllocHGlobal(TamPropiedades + 2 * (nombreSesion.Length + 1));
            uint r = StartTrace(out sesion, nombreSesion, PrepararPropiedades());
            if (r == ERROR_ALREADY_EXISTS)
            {
                // Quedó abierta de una ejecución anterior que no se cerró bien.
                ControlTrace(0, nombreSesion, PrepararPropiedades(), EVENT_TRACE_CONTROL_STOP);
                r = StartTrace(out sesion, nombreSesion, PrepararPropiedades());
            }
            if (r != 0)
            {
                Error = r == ERROR_ACCESS_DENIED ? "hace falta abrir el monitor como administrador" : "Windows devolvió el error " + r;
                sesion = 0;
                return false;
            }

            r = Habilitar(ProveedorProcesos, 0x10, new ushort[] { 1 });                             // inicio de procesos
            if (r == 0) r = Habilitar(ProveedorRed, 0x30, new ushort[] { 12, 15, 28, 31, 42, 58 }); // conexiones TCP y envíos UDP
            if (r != 0)
            {
                Error = r == ERROR_ACCESS_DENIED ? "hace falta abrir el monitor como administrador" : "no se pudo activar el aviso de conexiones (error " + r + ")";
                Detener();
                return false;
            }
            // Estos dos son un extra: si fallan, la captura de conexiones sigue funcionando.
            Habilitar(ProveedorArchivos, 0x80, new ushort[] { 12 });                                 // apertura de archivos
            Habilitar(ProveedorDns, 0x8000000000000000, new ushort[] { 3008, 3020 });                // consultas DNS completadas

            // Esta memoria se usa mientras dure la captura, es decir, hasta que se cierra el programa.
            IntPtr logfile = Marshal.AllocHGlobal(TamLogfile);
            Cero(logfile, TamLogfile);
            Marshal.WriteIntPtr(logfile, 8, Marshal.StringToHGlobalUni(nombreSesion));                   // LoggerName
            Marshal.WriteInt32(logfile, 28, PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD); // ProcessTraceMode
            callback = AlRecibir;
            Marshal.WriteIntPtr(logfile, 424, Marshal.GetFunctionPointerForDelegate(callback));          // EventRecordCallback
            consumidor = OpenTrace(logfile);
            if (consumidor == ulong.MaxValue)
            {
                Error = "no se pudo abrir la captura (error " + Marshal.GetLastWin32Error() + ")";
                consumidor = 0;
                Detener();
                return false;
            }

            activa = true;
            var hilo = new Thread(() =>
            {
                ProcessTrace(new[] { consumidor }, 1, IntPtr.Zero, IntPtr.Zero);
                activa = false;
            });
            hilo.IsBackground = true;
            hilo.Start();
            return true;
        }

        public void Detener()
        {
            if (sesion != 0)
            {
                ControlTrace(sesion, null, PrepararPropiedades(), EVENT_TRACE_CONTROL_STOP);
                sesion = 0;
            }
            if (consumidor != 0)
            {
                CloseTrace(consumidor);
                consumidor = 0;
            }
            activa = false;
        }

        public List<EventoRed> Extraer()
        {
            var lista = new List<EventoRed>();
            EventoRed ev;
            while (cola.TryDequeue(out ev)) lista.Add(ev);
            return lista;
        }

        public List<EventoArchivo> ExtraerArchivos()
        {
            var lista = new List<EventoArchivo>();
            EventoArchivo ev;
            while (colaArchivos.TryDequeue(out ev)) lista.Add(ev);
            return lista;
        }

        // Dominio que pidió ese mismo programa para esa IP. Es el dato fiable para las reglas: una IP de una red de
        // distribución (Cloudflare, Akamai...) puede servir a muchos dominios distintos.
        public string Dominio(int pid, IPAddress ip)
        {
            string d;
            return dominiosPorProceso.TryGetValue(pid + "|" + ip, out d) ? d : null;
        }

        // Último dominio que cualquier programa pidió para esa IP: solo para mostrarlo.
        public string DominioCualquiera(IPAddress ip)
        {
            string d;
            return ip != null && dominios.TryGetValue(ip.ToString(), out d) ? d : null;
        }

        public string Diagnostico()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Activa: " + activa + (Error != null ? " · Error: " + Error : ""));
            sb.AppendLine("Descartados por cola llena: " + descartados);
            for (int i = 0; i < eventosRed.Length; i++)
                if (eventosRed[i] > 0) sb.AppendLine("Eventos de red con id " + i + ": " + eventosRed[i]);
            sb.AppendLine("Eventos de inicio de programa: " + eventosProcesos);
            sb.AppendLine("Archivos abiertos (todos): " + eventosArchivos + " · sensibles: " + lecturasSensibles);
            sb.AppendLine("Consultas DNS: " + eventosDns + " · IPs con dominio: " + dominios.Count + " · por programa: " + dominiosPorProceso.Count);
            foreach (string m in muestrasDns) sb.AppendLine("  DNS " + m);
            sb.AppendLine("Programas iniciados durante la captura: " + imagenes.Count);
            foreach (var par in imagenes.Take(5)) sb.AppendLine("  PID " + par.Key + " = " + par.Value);
            return sb.ToString();
        }

        IntPtr PrepararPropiedades()
        {
            int tam = TamPropiedades + 2 * (nombreSesion.Length + 1);
            Cero(propiedades, tam);
            Marshal.WriteInt32(propiedades, 0, tam);                         // Wnode.BufferSize
            Marshal.WriteInt32(propiedades, 40, 1);                          // Wnode.ClientContext: reloj de alta resolución
            Marshal.WriteInt32(propiedades, 44, WNODE_FLAG_TRACED_GUID);     // Wnode.Flags
            Marshal.WriteInt32(propiedades, 48, 64);                         // BufferSize en KB
            Marshal.WriteInt32(propiedades, 64, EVENT_TRACE_REAL_TIME_MODE); // LogFileMode
            Marshal.WriteInt32(propiedades, 68, 1);                          // FlushTimer: entregar los eventos cada segundo
            Marshal.WriteInt32(propiedades, 116, TamPropiedades);            // LoggerNameOffset
            return propiedades;
        }

        // Activa un proveedor pidiendo a Windows que entregue solo estos eventos (filtro por id; Windows 8.1 o posterior).
        uint Habilitar(Guid proveedor, ulong palabrasClave, ushort[] eventos)
        {
            int tamFiltro = 4 + 2 * eventos.Length;
            IntPtr filtro = Marshal.AllocHGlobal(tamFiltro);
            IntPtr descriptor = Marshal.AllocHGlobal(16);
            IntPtr parametros = Marshal.AllocHGlobal(48);
            try
            {
                // EVENT_FILTER_EVENT_ID: FilterIn, Reserved, Count, Events[]
                Marshal.WriteByte(filtro, 0, 1);
                Marshal.WriteByte(filtro, 1, 0);
                Marshal.WriteInt16(filtro, 2, (short)eventos.Length);
                for (int i = 0; i < eventos.Length; i++) Marshal.WriteInt16(filtro, 4 + 2 * i, unchecked((short)eventos[i]));
                // EVENT_FILTER_DESCRIPTOR: Ptr, Size, Type = EVENT_FILTER_TYPE_EVENT_ID
                Marshal.WriteInt64(descriptor, 0, filtro.ToInt64());
                Marshal.WriteInt32(descriptor, 8, tamFiltro);
                Marshal.WriteInt32(descriptor, 12, unchecked((int)0x80000200));
                // ENABLE_TRACE_PARAMETERS versión 2: EnableFilterDesc en +32, FilterDescCount en +40
                Cero(parametros, 48);
                Marshal.WriteInt32(parametros, 0, 2);
                Marshal.WriteIntPtr(parametros, 32, descriptor);
                Marshal.WriteInt32(parametros, 40, 1);

                uint r = EnableTraceEx2(sesion, ref proveedor, 1, 4, palabrasClave, 0, 0, parametros);
                if (r != 0) r = EnableTraceEx2(sesion, ref proveedor, 1, 4, palabrasClave, 0, 0, IntPtr.Zero); // sin filtro
                return r;
            }
            finally
            {
                Marshal.FreeHGlobal(filtro);
                Marshal.FreeHGlobal(descriptor);
                Marshal.FreeHGlobal(parametros);
            }
        }

        // Windows llama a esto por cada evento, desde el hilo de ProcessTrace.
        void AlRecibir(IntPtr registro)
        {
            try
            {
                // EVENT_RECORD en 64 bits: Flags +4, ProcessId +12, TimeStamp +16, ProviderId +24, Id +40, Version +42,
                // UserDataLength +86, UserData +96.
                int proveedor = Marshal.ReadInt32(registro, 24);
                int id = (ushort)Marshal.ReadInt16(registro, 40);
                int version = Marshal.ReadByte(registro, 42);
                int largo = (ushort)Marshal.ReadInt16(registro, 86);
                IntPtr datos = Marshal.ReadIntPtr(registro, 96);

                if (proveedor == DATA1_ARCHIVOS)
                {
                    if (id == 12) RegistrarArchivo(datos, largo, version, Marshal.ReadInt32(registro, 12), Marshal.ReadInt16(registro, 4));
                }
                else if (proveedor == DATA1_RED)
                {
                    if (id < eventosRed.Length) Interlocked.Increment(ref eventosRed[id]);
                    RegistrarRed(datos, largo, id, Marshal.ReadInt64(registro, 16));
                }
                else if (proveedor == DATA1_PROCESOS && id == 1)
                {
                    Interlocked.Increment(ref eventosProcesos);
                    RegistrarProceso(datos, largo, version);
                }
                else if (proveedor == DATA1_DNS && (id == 3008 || id == 3020))
                {
                    Interlocked.Increment(ref eventosDns);
                    RegistrarDns(datos, largo, id, version, Marshal.ReadInt32(registro, 12));
                }
            }
            catch (Exception) { } // una excepción nunca debe volver al código de Windows
        }

        void RegistrarProceso(IntPtr datos, int largo, int version)
        {
            // La posición del nombre de la imagen depende de la versión del evento (ver Get-WinEvent -ListProvider).
            // Desde la versión 3 va detrás de un SID de longitud variable: 8 bytes + 4 por cada subautoridad.
            int pos = version >= 3 ? 56 + 4 * Marshal.ReadByte(datos, 49) : version >= 1 ? 24 : 20;
            string imagen = LeerTexto(datos, largo, ref pos);
            if (!string.IsNullOrEmpty(imagen)) imagenes[Marshal.ReadInt32(datos, 0)] = RutaDos(imagen);
        }

        void RegistrarArchivo(IntPtr datos, int largo, int version, int pid, int flags)
        {
            Interlocked.Increment(ref eventosArchivos);
            // Las aperturas del propio Windows (PID 4, por ejemplo el antivirus revisando un archivo) no son sospechosas.
            if (pid <= 4 || pid == pidPropio) return;
            // Campos: Irp, FileObject, IssuingThreadId, CreateOptions, CreateAttributes, ShareAccess y el nombre
            // (en la versión 0, ThreadId es un puntero y va antes de FileObject).
            int puntero = (flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 ? 4 : 8;
            int pos = version >= 1 ? 2 * puntero + 16 : 3 * puntero + 12;
            string archivo = LeerTexto(datos, largo, ref pos);
            string categoria = DetectorRobo.Clasificar(archivo);
            if (categoria == null) return;

            Interlocked.Increment(ref lecturasSensibles);
            DateTime ahora = DateTime.Now;
            if (Repetido("a" + pid + "|" + categoria, ahora, 30)) return;
            if (colaArchivos.Count >= MaximoEnCola) return;
            colaArchivos.Enqueue(new EventoArchivo { Hora = ahora, Pid = pid, RutaProceso = RutaDe(pid), Archivo = RutaDos(archivo), Categoria = categoria });
        }

        void RegistrarDns(IntPtr datos, int largo, int id, int version, int pid)
        {
            int pos = 0;
            string nombre = LeerTexto(datos, largo, ref pos);
            if (string.IsNullOrEmpty(nombre)) return;
            // 3008: QueryName, QueryType, QueryOptions (8 bytes), QueryStatus, QueryResults
            // 3020: QueryName, QueryType, NetworkIndex, InterfaceIndex, Status, QueryResults y, desde la versión 1, ClientPID
            pos += id == 3008 ? 4 + 8 : 4 + 4 + 4;
            if (pos + 4 > largo || Marshal.ReadInt32(datos, pos) != 0) return; // la consulta falló
            pos += 4;
            string resultados = LeerTexto(datos, largo, ref pos);
            if (string.IsNullOrEmpty(resultados)) return;
            if (id == 3020 && version >= 1 && pos + 4 <= largo) pid = Marshal.ReadInt32(datos, pos);

            nombre = nombre.TrimEnd('.').ToLowerInvariant();
            foreach (string parte in resultados.Split(';'))
            {
                // Las direcciones vienen como "1.2.3.4", "::ffff:1.2.3.4" o IPv6; los alias como "type:  5 nombre".
                IPAddress ip;
                string texto = parte.Trim();
                if (texto.Length == 0 || texto.StartsWith("type") || !IPAddress.TryParse(texto, out ip)) continue;
                if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
                dominios[ip.ToString()] = nombre;
                dominiosPorProceso[pid + "|" + ip] = nombre;
            }
            if (dominiosPorProceso.Count > 200000) dominiosPorProceso.Clear();
            if (dominios.Count > 100000) dominios.Clear();
            muestrasDns.Enqueue("PID " + pid + " (" + (RutaDe(pid).Length > 0 ? System.IO.Path.GetFileName(RutaDe(pid)) : "?") + ") pidió " + nombre);
            string sobrante;
            while (muestrasDns.Count > 8) muestrasDns.TryDequeue(out sobrante);
        }

        void RegistrarRed(IntPtr datos, int largo, int id, long marcaDeTiempo)
        {
            bool v6, entrante = false, udp = false;
            switch (id)
            {
                case 12: v6 = false; break;                  // TCP IPv4: conexión intentada
                case 15: v6 = false; entrante = true; break; // TCP IPv4: conexión aceptada
                case 28: v6 = true; break;                   // TCP IPv6: conexión intentada
                case 31: v6 = true; entrante = true; break;  // TCP IPv6: conexión aceptada
                case 42: v6 = false; udp = true; break;      // UDP IPv4: datos enviados
                case 58: v6 = true; udp = true; break;       // UDP IPv6: datos enviados
                default: return;
            }
            if (largo < (v6 ? 44 : 20)) return;

            // Campos: PID, size, daddr (remota), saddr (local), dport, sport; direcciones y puertos en orden de red.
            int pid = Marshal.ReadInt32(datos, 0);
            IPAddress remota = v6 ? Ip(datos + 8, 16) : Ip(datos + 8, 4);
            IPAddress local = v6 ? Ip(datos + 24, 16) : Ip(datos + 12, 4);
            int puertoRemoto = Puerto(datos, v6 ? 40 : 16);
            int puertoLocal = Puerto(datos, v6 ? 42 : 18);
            if (IPAddress.IsLoopback(remota) || Red.EsNula(remota) || Red.EsDifusion(remota)) return;

            // La misma conexión repetida en pocos segundos se anota una vez (los envíos UDP pueden ser miles por segundo).
            DateTime ahora = DateTime.Now;
            if (Repetido((udp ? "u" : entrante ? "e" : "s") + pid + "|" + remota + "|" + puertoRemoto, ahora, udp ? 60 : 5)) return;

            if (cola.Count >= MaximoEnCola)
            {
                Interlocked.Increment(ref descartados);
                return;
            }
            DateTime hora = ahora;
            try
            {
                hora = DateTime.FromFileTime(marcaDeTiempo);
                if (Math.Abs((hora - ahora).TotalHours) > 1) hora = ahora;
            }
            catch (ArgumentOutOfRangeException) { }

            cola.Enqueue(new EventoRed
            {
                Hora = hora, Pid = pid, Protocolo = (udp ? "UDP" : "TCP") + (v6 ? "v6" : ""), Entrante = entrante,
                IpRemota = remota, PuertoRemoto = puertoRemoto, IpLocal = local, PuertoLocal = puertoLocal, Ruta = RutaDe(pid)
            });
        }

        // Ruta del programa: la del aviso de inicio si arrancó durante la captura, o la que dé Windows si sigue abierto.
        string RutaDe(int pid)
        {
            string ruta;
            if (imagenes.TryGetValue(pid, out ruta)) return ruta;
            return pid > 4 ? Nativo.RutaProceso(pid) : "";
        }

        // Evita anotar lo mismo una y otra vez: true si ya se anotó hace menos de 'segundos'.
        bool Repetido(string clave, DateTime ahora, int segundos)
        {
            DateTime anterior;
            if (recientes.TryGetValue(clave, out anterior) && (ahora - anterior).TotalSeconds < segundos) return true;
            recientes[clave] = ahora;
            if (recientes.Count > 20000)
                foreach (var k in recientes.Where(x => (ahora - x.Value).TotalSeconds > 120).Select(x => x.Key).ToList())
                    recientes.Remove(k);
            return false;
        }

        string RutaDos(string rutaNt)
        {
            foreach (var u in unidades)
                if (rutaNt.StartsWith(u.Key + "\\", StringComparison.OrdinalIgnoreCase)) return u.Value + rutaNt.Substring(u.Key.Length);
            return rutaNt.StartsWith(@"\??\") ? rutaNt.Substring(4) : rutaNt;
        }

        // Lee un texto UTF-16 terminado en cero sin pasarse del final de los datos del evento, y avanza 'pos'.
        static string LeerTexto(IntPtr datos, int largo, ref int pos)
        {
            int maximo = (largo - pos) / 2;
            if (maximo <= 0) return null;
            string texto = Marshal.PtrToStringUni(datos + pos, maximo);
            int fin = texto.IndexOf('\0');
            if (fin >= 0) texto = texto.Substring(0, fin);
            pos += 2 * (texto.Length + 1);
            return texto;
        }

        static IPAddress Ip(IntPtr p, int tam)
        {
            var bytes = new byte[tam];
            Marshal.Copy(p, bytes, 0, tam);
            var ip = new IPAddress(bytes);
            return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        }

        static int Puerto(IntPtr p, int pos)
        {
            int v = (ushort)Marshal.ReadInt16(p, pos);
            return ((v & 0xFF) << 8) | (v >> 8);
        }

        static void Cero(IntPtr p, int tam)
        {
            for (int i = 0; i < tam; i++) Marshal.WriteByte(p, i, 0);
        }
    }
}
