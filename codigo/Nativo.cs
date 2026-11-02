// Llamadas directas a Windows: tabla de conexiones TCP, ruta de un proceso, firma digital y DNS inverso.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace MonitorConexiones
{
    static class Nativo
    {
        public const int AF_INET = 2, AF_INET6 = 23;
        const int TCP_TABLE_OWNER_PID_ALL = 5;
        const uint ERROR_INSUFFICIENT_BUFFER = 122;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public class FilaTcp
        {
            public string Protocolo;
            public IPAddress IpLocal, IpRemota;
            public int PuertoLocal, PuertoRemoto, Estado, Pid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] ucLocalAddr;
            public uint dwLocalScopeId, dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] ucRemoteAddr;
            public uint dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [DllImport("iphlpapi.dll")]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool QueryFullProcessImageName(IntPtr proceso, int flags, StringBuilder ruta, ref int tamano);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid accion, IntPtr datos);

        [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
        static extern int DnsQuery(string nombre, ushort tipo, uint opciones, IntPtr servidores, out IntPtr resultados, IntPtr reservado);

        [DllImport("dnsapi.dll")]
        static extern void DnsRecordListFree(IntPtr lista, int tipoLiberacion);

        public static List<FilaTcp> TablaTcp(int familia)
        {
            var lista = new List<FilaTcp>();
            int tam = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref tam, false, familia, TCP_TABLE_OWNER_PID_ALL, 0);
            for (int intento = 0; intento < 5; intento++)
            {
                IntPtr buf = Marshal.AllocHGlobal(tam);
                try
                {
                    uint r = GetExtendedTcpTable(buf, ref tam, false, familia, TCP_TABLE_OWNER_PID_ALL, 0);
                    if (r == ERROR_INSUFFICIENT_BUFFER) continue; // la tabla creció entre las dos llamadas
                    if (r != 0) break;
                    int n = Marshal.ReadInt32(buf);
                    IntPtr p = buf + 4;
                    if (familia == AF_INET)
                    {
                        int paso = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                        for (int i = 0; i < n; i++, p += paso)
                        {
                            var f = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(p, typeof(MIB_TCPROW_OWNER_PID));
                            lista.Add(new FilaTcp
                            {
                                Protocolo = "TCP", IpLocal = new IPAddress(f.dwLocalAddr), PuertoLocal = Puerto(f.dwLocalPort),
                                IpRemota = new IPAddress(f.dwRemoteAddr), PuertoRemoto = Puerto(f.dwRemotePort),
                                Estado = (int)f.dwState, Pid = (int)f.dwOwningPid
                            });
                        }
                    }
                    else
                    {
                        int paso = Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID));
                        for (int i = 0; i < n; i++, p += paso)
                        {
                            var f = (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(p, typeof(MIB_TCP6ROW_OWNER_PID));
                            lista.Add(new FilaTcp
                            {
                                Protocolo = "TCPv6", IpLocal = Ip6(f.ucLocalAddr, f.dwLocalScopeId), PuertoLocal = Puerto(f.dwLocalPort),
                                IpRemota = Ip6(f.ucRemoteAddr, f.dwRemoteScopeId), PuertoRemoto = Puerto(f.dwRemotePort),
                                Estado = (int)f.dwState, Pid = (int)f.dwOwningPid
                            });
                        }
                    }
                    break;
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            return lista;
        }

        static int Puerto(uint valor)
        {
            return (int)(((valor & 0xFF) << 8) | ((valor >> 8) & 0xFF));
        }

        static IPAddress Ip6(byte[] bytes, uint ambito)
        {
            var ip = new IPAddress(bytes, ambito);
            return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        }

        public static string RutaProceso(int pid)
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return "";
            try
            {
                var sb = new StringBuilder(1024);
                int tam = sb.Capacity;
                if (!QueryFullProcessImageName(h, 0, sb, ref tam)) return "";
                string ruta = sb.ToString();
                return Path.IsPathRooted(ruta) ? ruta : "";
            }
            finally
            {
                CloseHandle(h);
            }
        }

        // Comprueba la firma digital incrustada en el archivo. Devuelve 0 si es válida o el código de error de Windows.
        public static uint VerificarFirma(string ruta)
        {
            var info = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = ruta };
            IntPtr pInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            IntPtr pDatos = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
            Marshal.StructureToPtr(info, pInfo, false);
            try
            {
                var datos = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    dwUIChoice = 2,               // sin ventanas
                    fdwRevocationChecks = 0,      // sin consultar revocaciones (evita esperas de red)
                    dwUnionChoice = 1,            // un archivo
                    pFile = pInfo,
                    dwStateAction = 1,            // verificar
                    dwProvFlags = 0x1000 | 0x10   // solo caché de URL, sin comprobar revocación
                };
                Marshal.StructureToPtr(datos, pDatos, false);
                int resultado = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pDatos);

                datos = (WINTRUST_DATA)Marshal.PtrToStructure(pDatos, typeof(WINTRUST_DATA));
                datos.dwStateAction = 2;          // liberar el estado de la verificación
                Marshal.StructureToPtr(datos, pDatos, false);
                WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pDatos);
                return unchecked((uint)resultado);
            }
            finally
            {
                Marshal.DestroyStructure(pInfo, typeof(WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(pInfo);
                Marshal.FreeHGlobal(pDatos);
            }
        }

        // Nombre del servidor por DNS inverso (registro PTR). A diferencia de Dns.GetHostEntry, no recurre a NetBIOS,
        // que mandaría consultas al puerto 137 de cada IP sin nombre y aparecerían en el propio historial.
        public static string NombreInverso(IPAddress ip)
        {
            const ushort DNS_TYPE_PTR = 12;
            IntPtr lista;
            if (DnsQuery(NombreArpa(ip), DNS_TYPE_PTR, 0, IntPtr.Zero, out lista, IntPtr.Zero) != 0 || lista == IntPtr.Zero) return "";
            try
            {
                // DNS_RECORD: pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved y después Data (pNameHost en un PTR).
                for (IntPtr r = lista; r != IntPtr.Zero; r = Marshal.ReadIntPtr(r))
                    if ((ushort)Marshal.ReadInt16(r, 2 * IntPtr.Size) == DNS_TYPE_PTR)
                        return Marshal.PtrToStringUni(Marshal.ReadIntPtr(r, 2 * IntPtr.Size + 16)).TrimEnd('.');
                return "";
            }
            finally
            {
                DnsRecordListFree(lista, 1);
            }
        }

        static string NombreArpa(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            if (b.Length == 4) return b[3] + "." + b[2] + "." + b[1] + "." + b[0] + ".in-addr.arpa";
            var sb = new StringBuilder();
            for (int i = b.Length - 1; i >= 0; i--) sb.AppendFormat("{0:x}.{1:x}.", b[i] & 0xF, b[i] >> 4);
            return sb.Append("ip6.arpa").ToString();
        }
    }
}
