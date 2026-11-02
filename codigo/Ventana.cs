// La ventana del monitor: tablas, menús, avisos, bandeja del sistema y acciones de protección.

using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace MonitorConexiones
{
    class VentanaPrincipal : Form
    {
        public string RutaCaptura;
        public bool IniciarEnBandeja;

        const string OrigenTiempoReal = "Tiempo real";
        const string OrigenRevision = "Revisión periódica";

        class Aviso
        {
            public string Titulo, Texto;
            public int Riesgo;
        }

        readonly Ajustes ajustes = new Ajustes();
        readonly ListasNegras listas = new ListasNegras();
        readonly ProgramasConocidos conocidos = new ProgramasConocidos();
        readonly RegistroAlertas registro = new RegistroAlertas(Datos.Ruta("registro_alertas.tsv"));
        readonly Recolector recolector;
        CapturaTiempoReal tiempoReal = new CapturaTiempoReal("MonitorConexiones-TiempoReal");
        readonly ConcurrentDictionary<string, string> nombresDns = new ConcurrentDictionary<string, string>();
        readonly Dictionary<string, DateTime> vistaDesde = new Dictionary<string, DateTime>();
        readonly Dictionary<string, Visto> historial = new Dictionary<string, Visto>();
        readonly Dictionary<string, DataGridViewRow> filasActuales = new Dictionary<string, DataGridViewRow>();
        readonly Dictionary<string, DataGridViewRow> filasHistorial = new Dictionary<string, DataGridViewRow>();
        readonly Dictionary<string, DataGridViewRow> filasAlertas = new Dictionary<string, DataGridViewRow>();
        readonly Dictionary<string, DataGridViewRow> filasProgramas = new Dictionary<string, DataGridViewRow>();
        readonly HashSet<string> avisados = new HashSet<string>();
        readonly HashSet<DataGridView> tablasTocadas = new HashSet<DataGridView>();
        readonly bool esAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        readonly float escala;
        readonly Font negrita;

        Cortafuegos.Estado bloqueos = new Cortafuegos.Estado();
        List<Conexion> ultimaCaptura;
        DateTime inicio = DateTime.MinValue;
        DateTime horaCaptura;
        bool ocupado, pausado, arrancado, saliendo;
        Action accionAviso;

        readonly DataGridView tablaActual, tablaHistorial, tablaAlertas, tablaProgramas;
        readonly TextBox txtBuscar;
        readonly CheckBox chkSoloSospechosas, chkLocales, chkEscucha, chkCerradas;
        readonly ComboBox cmbIntervalo;
        readonly Button btnPausa, btnCortar, btnAviso;
        readonly Panel pnlAviso;
        readonly Label lblAviso, lblProgramas;
        readonly ToolStripStatusLabel lblEstado, lblListas;
        readonly ToolStripMenuItem miCortar, miCortarBandeja, miInicioWindows, miAvisar, miBandeja;
        readonly TabControl pestanas;
        readonly TabPage pagAlertas, pagProgramas;
        readonly NotifyIcon icono;
        readonly System.Windows.Forms.Timer temporizador;

        public VentanaPrincipal()
        {
            recolector = new Recolector(listas, conocidos, (pid, ip) => tiempoReal.Dominio(pid, ip));
            using (var g = CreateGraphics()) escala = g.DpiX / 96f;
            Text = "Monitor de conexiones de red" + (esAdmin ? " (administrador)" : "");
            Font = new Font("Segoe UI", 9f);
            negrita = new Font(Font, FontStyle.Bold);
            Size = new Size(Px(1280), Px(760));
            MinimumSize = new Size(Px(800), Px(420));
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            // ---------- Tablas ----------
            tablaActual = CrearTabla();
            AgregarColumna(tablaActual, "riesgo", "Riesgo", 60, typeof(int));
            AgregarColumna(tablaActual, "proceso", "Programa", 170, typeof(string));
            AgregarColumna(tablaActual, "motivo", "Por qué revisarla", 300, typeof(string));
            AgregarColumna(tablaActual, "direccion", "Sentido", 70, typeof(string));
            AgregarColumna(tablaActual, "ip", "IP remota", 130, typeof(string));
            AgregarColumna(tablaActual, "puerto", "Puerto", 55, typeof(int));
            AgregarColumna(tablaActual, "servicio", "Servicio", 125, typeof(string));
            AgregarColumna(tablaActual, "host", "Nombre del servidor", 220, typeof(string));
            AgregarColumna(tablaActual, "firmante", "Firmado por", 170, typeof(string));
            AgregarColumna(tablaActual, "estado", "Estado", 110, typeof(string));
            AgregarColumna(tablaActual, "pid", "PID", 55, typeof(int));
            AgregarColumna(tablaActual, "desde", "Vista desde", 80, typeof(DateTime)).DefaultCellStyle.Format = "HH:mm:ss";
            AgregarColumna(tablaActual, "local", "Dirección local", 170, typeof(string));
            AgregarColumna(tablaActual, "ruta", "Ubicación del programa", 420, typeof(string));

            tablaHistorial = CrearTabla();
            AgregarColumna(tablaHistorial, "riesgo", "Riesgo", 60, typeof(int));
            AgregarColumna(tablaHistorial, "proceso", "Programa", 170, typeof(string));
            AgregarColumna(tablaHistorial, "motivo", "Por qué revisarla", 300, typeof(string));
            AgregarColumna(tablaHistorial, "ip", "IP remota", 130, typeof(string));
            AgregarColumna(tablaHistorial, "puerto", "Puerto", 55, typeof(int));
            AgregarColumna(tablaHistorial, "servicio", "Servicio", 125, typeof(string));
            AgregarColumna(tablaHistorial, "host", "Nombre del servidor", 220, typeof(string));
            AgregarColumna(tablaHistorial, "veces", "Conexiones", 80, typeof(int));
            AgregarColumna(tablaHistorial, "primera", "Primera vez", 85, typeof(DateTime)).DefaultCellStyle.Format = "HH:mm:ss";
            AgregarColumna(tablaHistorial, "ultima", "Última vez", 85, typeof(DateTime)).DefaultCellStyle.Format = "HH:mm:ss";
            AgregarColumna(tablaHistorial, "firmante", "Firmado por", 170, typeof(string));
            AgregarColumna(tablaHistorial, "ruta", "Ubicación del programa", 420, typeof(string));

            tablaAlertas = CrearTabla();
            AgregarColumna(tablaAlertas, "riesgo", "Riesgo", 60, typeof(int));
            AgregarColumna(tablaAlertas, "ultima", "Última vez", 130, typeof(DateTime)).DefaultCellStyle.Format = "dd/MM/yyyy HH:mm:ss";
            AgregarColumna(tablaAlertas, "proceso", "Programa", 170, typeof(string));
            AgregarColumna(tablaAlertas, "motivo", "Por qué revisarla", 300, typeof(string));
            AgregarColumna(tablaAlertas, "ip", "IP remota", 130, typeof(string));
            AgregarColumna(tablaAlertas, "puerto", "Puerto", 55, typeof(int));
            AgregarColumna(tablaAlertas, "protocolo", "Tipo", 70, typeof(string));
            AgregarColumna(tablaAlertas, "host", "Nombre del servidor", 220, typeof(string));
            AgregarColumna(tablaAlertas, "detalle", "Archivo leído", 300, typeof(string));
            AgregarColumna(tablaAlertas, "veces", "Veces", 55, typeof(int));
            AgregarColumna(tablaAlertas, "primera", "Primera vez", 130, typeof(DateTime)).DefaultCellStyle.Format = "dd/MM/yyyy HH:mm:ss";
            AgregarColumna(tablaAlertas, "origen", "Detectada por", 120, typeof(string));
            AgregarColumna(tablaAlertas, "ruta", "Ubicación del programa", 420, typeof(string));

            tablaProgramas = CrearTabla();
            AgregarColumna(tablaProgramas, "estado", "Estado", 90, typeof(string));
            AgregarColumna(tablaProgramas, "proceso", "Programa", 190, typeof(string));
            AgregarColumna(tablaProgramas, "firmante", "Firmado por", 200, typeof(string));
            AgregarColumna(tablaProgramas, "primera", "Primera conexión", 130, typeof(DateTime)).DefaultCellStyle.Format = "dd/MM/yyyy HH:mm";
            AgregarColumna(tablaProgramas, "ultima", "Última conexión", 130, typeof(DateTime)).DefaultCellStyle.Format = "dd/MM/yyyy HH:mm";
            AgregarColumna(tablaProgramas, "ruta", "Ubicación del programa", 520, typeof(string));

            // ---------- Menú ----------
            var menu = new MenuStrip();
            var mArchivo = new ToolStripMenuItem("&Archivo");
            mArchivo.DropDownItems.Add("Exportar historial…", null, (s, e) => ExportarHistorial());
            mArchivo.DropDownItems.Add("Abrir la carpeta de datos (alertas, ajustes, listas)", null, (s, e) => AbrirCarpetaDatos());
            mArchivo.DropDownItems.Add(new ToolStripSeparator());
            mArchivo.DropDownItems.Add("Salir del todo", null, (s, e) => Salir());

            var mProteccion = new ToolStripMenuItem("&Protección");
            miCortar = new ToolStripMenuItem("Cortar Internet ahora (emergencia)", null, (s, e) => AlternarCorte());
            mProteccion.DropDownItems.Add(miCortar);
            mProteccion.DropDownItems.Add("Ver los programas y cuáles están bloqueados", null, (s, e) => pestanas.SelectedTab = pagProgramas);
            mProteccion.DropDownItems.Add("Quitar todos los bloqueos del monitor…", null, (s, e) => QuitarTodosLosBloqueos());
            mProteccion.DropDownItems.Add(new ToolStripSeparator());
            mProteccion.DropDownItems.Add("Actualizar las listas negras ahora", null, (s, e) => listas.ActualizarAhora());

            var mOpciones = new ToolStripMenuItem("&Opciones");
            miInicioWindows = new ToolStripMenuItem("Iniciar con Windows (en la bandeja y como administrador)", null, (s, e) => AlternarInicioConWindows());
            miAvisar = new ToolStripMenuItem("Avisarme con una notificación de cada alerta nueva") { CheckOnClick = true, Checked = ajustes.Leer("Avisar", true) };
            miAvisar.CheckedChanged += (s, e) => ajustes.Escribir("Avisar", miAvisar.Checked);
            miBandeja = new ToolStripMenuItem("Al cerrar la ventana, seguir vigilando en la bandeja") { CheckOnClick = true, Checked = ajustes.Leer("CerrarALaBandeja", true) };
            miBandeja.CheckedChanged += (s, e) => ajustes.Escribir("CerrarALaBandeja", miBandeja.Checked);
            mOpciones.DropDownItems.AddRange(new ToolStripItem[] { miInicioWindows, miAvisar, miBandeja });
            mOpciones.DropDownOpening += (s, e) => miInicioWindows.Checked = InicioConWindows.Activado();

            var mAyuda = new ToolStripMenuItem("A&yuda");
            // La prueba no se reparte en la versión pública: si no está junto al monitor, el menú no la ofrece.
            if (File.Exists(RutaPrueba())) mAyuda.DropDownItems.Add("Probar el monitor (simula lo que hace un virus)…", null, (s, e) => AbrirPrueba());
            mAyuda.DropDownItems.Add("Acerca del Monitor de conexiones", null, (s, e) => AcercaDe());
            menu.Items.AddRange(new ToolStripItem[] { mArchivo, mProteccion, mOpciones, mAyuda });
            MainMenuStrip = menu;

            // ---------- Barra de filtros ----------
            var barra = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(Px(6), Px(4), Px(6), Px(2)) };
            barra.Controls.Add(Etiqueta("Buscar:"));
            txtBuscar = new TextBox { Width = Px(180) };
            txtBuscar.TextChanged += (s, e) => RefrescarTablas();
            barra.Controls.Add(txtBuscar);
            chkSoloSospechosas = Casilla(barra, "Solo lo que hay que revisar", false);
            chkLocales = Casilla(barra, "Incluir conexiones internas del equipo", false);
            chkEscucha = Casilla(barra, "Incluir puertos abiertos (en escucha)", false);
            chkCerradas = Casilla(barra, "Incluir conexiones recién cerradas", false);
            // La etiqueta y su desplegable van juntos para que no se separen al saltar de línea.
            var grupoIntervalo = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty };
            grupoIntervalo.Controls.Add(Etiqueta("Actualizar cada:"));
            cmbIntervalo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Px(70) };
            cmbIntervalo.Items.AddRange(new object[] { "1 s", "2 s", "3 s", "5 s", "10 s" });
            cmbIntervalo.SelectedIndex = 1;
            cmbIntervalo.SelectedIndexChanged += (s, e) => temporizador.Interval = int.Parse(cmbIntervalo.Text.Split(' ')[0]) * 1000;
            grupoIntervalo.Controls.Add(cmbIntervalo);
            barra.Controls.Add(grupoIntervalo);
            btnPausa = Boton(barra, "Pausar", (s, e) => AlternarPausa());
            btnCortar = Boton(barra, "Cortar Internet", (s, e) => AlternarCorte());
            btnCortar.ForeColor = Color.FromArgb(176, 0, 32);

            var leyenda = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(Px(6), 0, Px(6), Px(4)) };
            leyenda.Controls.Add(Muestra(NivelRiesgo.ColorAlto, "Alto: revísalo ya"));
            leyenda.Controls.Add(Muestra(NivelRiesgo.ColorMedio, "Medio: conviene revisarlo"));
            leyenda.Controls.Add(Muestra(NivelRiesgo.ColorBajo, "Bajo: casi seguro normal"));
            leyenda.Controls.Add(Muestra(NivelRiesgo.ColorNueva, "Conexión nueva"));
            leyenda.Controls.Add(new Label
            {
                Text = "Clic derecho sobre una fila para investigarla o bloquearla (reputación de la IP, analizar el programa, firewall…)",
                AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(Px(12), Px(5), 0, 0)
            });

            // Franja de aviso: Internet cortado (roja) o captura en tiempo real desactivada (amarilla).
            pnlAviso = new Panel { Dock = DockStyle.Top, Height = Px(36), Visible = false, Padding = new Padding(Px(10), Px(4), Px(8), Px(4)) };
            lblAviso = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
            btnAviso = new Button { Dock = DockStyle.Right, AutoSize = true, Visible = false, BackColor = SystemColors.Control, UseVisualStyleBackColor = true };
            btnAviso.Click += (s, e) => { if (accionAviso != null) accionAviso(); };
            pnlAviso.Controls.Add(lblAviso);
            pnlAviso.Controls.Add(btnAviso);

            // ---------- Pestañas ----------
            pestanas = new TabControl { Dock = DockStyle.Fill };
            var pagActual = new TabPage("Conexiones ahora");
            pagActual.Controls.Add(tablaActual);
            var pagHistorial = new TabPage("Historial (todo lo visto desde que se abrió)");
            pagHistorial.Controls.Add(tablaHistorial);

            var barraAlertas = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(Px(4), Px(4), Px(4), Px(2)) };
            barraAlertas.Controls.Add(new Label
            {
                Text = "Cada conexión sospechosa y cada lectura de contraseñas o carteras queda guardada aquí, aunque cierres el programa.",
                AutoSize = true, Margin = new Padding(Px(3), Px(7), Px(10), 0)
            });
            Boton(barraAlertas, "Abrir la carpeta del registro", (s, e) => AbrirCarpetaDatos());
            Boton(barraAlertas, "Vaciar el registro…", (s, e) => VaciarRegistro());
            pagAlertas = new TabPage("Alertas guardadas");
            pagAlertas.Controls.Add(tablaAlertas);
            pagAlertas.Controls.Add(barraAlertas);

            var barraProgramas = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(Px(4), Px(4), Px(4), Px(2)) };
            lblProgramas = new Label { AutoSize = true, Margin = new Padding(Px(3), Px(7), Px(10), Px(4)) };
            barraProgramas.Controls.Add(lblProgramas);
            pagProgramas = new TabPage("Programas");
            pagProgramas.Controls.Add(tablaProgramas);
            pagProgramas.Controls.Add(barraProgramas);

            pestanas.TabPages.AddRange(new[] { pagActual, pagHistorial, pagAlertas, pagProgramas });
            pestanas.SelectedIndexChanged += (s, e) => BeginInvoke((Action)(() => QuitarSeleccionInicial(TablaVisible())));

            var barraEstado = new StatusStrip();
            lblEstado = new ToolStripStatusLabel("Cargando conexiones…") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            lblListas = new ToolStripStatusLabel("") { ForeColor = SystemColors.GrayText };
            var lblAutor = new ToolStripStatusLabel("Creado por " + Autoria.Nombre + " · " + Autoria.Web)
            {
                IsLink = true, LinkBehavior = LinkBehavior.HoverUnderline, ToolTipText = "Abrir " + Autoria.Web
            };
            lblAutor.Click += (s, e) => AbrirWeb("https://" + Autoria.Web);
            barraEstado.Items.AddRange(new ToolStripItem[] { lblEstado, lblListas, lblAutor });

            // El control que ocupa el resto va primero para que las barras se acoplen alrededor.
            Controls.Add(pestanas);
            Controls.Add(pnlAviso);
            Controls.Add(leyenda);
            Controls.Add(barra);
            Controls.Add(menu);
            Controls.Add(barraEstado);

            // ---------- Menú de clic derecho ----------
            var menuFila = new ContextMenuStrip();
            var miCarpeta = menuFila.Items.Add("Abrir la carpeta del programa", null, (s, e) => AbrirCarpeta());
            var miArchivo = menuFila.Items.Add("Analizar el programa en VirusTotal (solo se envía su huella)", null, (s, e) => AnalizarArchivo());
            var miGoogle = menuFila.Items.Add("Buscar el programa en Google", null, (s, e) => BuscarPrograma());
            menuFila.Items.Add(new ToolStripSeparator());
            var miAbuse = menuFila.Items.Add("Ver la reputación de la IP en AbuseIPDB", null, (s, e) => AbrirWeb("https://www.abuseipdb.com/check/" + Seleccionada().IpRemota));
            var miVtIp = menuFila.Items.Add("Ver la IP en VirusTotal", null, (s, e) => AbrirWeb("https://www.virustotal.com/gui/ip-address/" + Seleccionada().IpRemota));
            menuFila.Items.Add(new ToolStripSeparator());
            var miBloquearPrograma = menuFila.Items.Add("Bloquear el acceso a Internet de este programa…", null, (s, e) => BloquearPrograma());
            var miDesbloquearPrograma = menuFila.Items.Add("Desbloquear este programa", null, (s, e) => DesbloquearPrograma());
            var miBloquearIp = menuFila.Items.Add("Bloquear esta IP…", null, (s, e) => BloquearIp());
            var miDesbloquearIp = menuFila.Items.Add("Desbloquear esta IP", null, (s, e) => DesbloquearIp());
            menuFila.Items.Add(new ToolStripSeparator());
            menuFila.Items.Add("Copiar los datos de la fila", null, (s, e) => CopiarFila());
            var miTerminar = menuFila.Items.Add("Cerrar el programa (terminar proceso)…", null, (s, e) => TerminarProceso());
            menuFila.Opening += (s, e) =>
            {
                var en = Seleccionada();
                if (en == null) { e.Cancel = true; return; }
                bool hayRuta = !string.IsNullOrEmpty(en.Ruta);
                bool programaBloqueado = hayRuta && bloqueos.Programas.Contains(en.Ruta);
                bool ipValida = en.IpRemota != null && !Red.EsNula(en.IpRemota) && !IPAddress.IsLoopback(en.IpRemota);
                bool ipBloqueada = ipValida && bloqueos.Ips.Contains(en.IpRemota.ToString());
                bool ipPublica = ipValida && !Red.EsPrivada(en.IpRemota);
                miCarpeta.Enabled = hayRuta;
                miArchivo.Enabled = hayRuta;
                miGoogle.Enabled = !en.Proceso.StartsWith("(");
                miAbuse.Enabled = ipPublica;
                miVtIp.Enabled = ipPublica;
                miBloquearPrograma.Visible = !programaBloqueado;
                miBloquearPrograma.Enabled = hayRuta;
                miDesbloquearPrograma.Visible = programaBloqueado;
                miBloquearIp.Visible = !ipBloqueada;
                miBloquearIp.Enabled = ipValida;
                miDesbloquearIp.Visible = ipBloqueada;
                miTerminar.Enabled = en is Conexion && en.Pid > 4;
            };
            foreach (var tabla in new[] { tablaActual, tablaHistorial, tablaAlertas, tablaProgramas }) tabla.ContextMenuStrip = menuFila;

            // ---------- Bandeja del sistema ----------
            icono = new NotifyIcon { Icon = Icon ?? SystemIcons.Shield, Text = "Monitor de conexiones de red" };
            var menuBandeja = new ContextMenuStrip();
            menuBandeja.Items.Add("Abrir el monitor", null, (s, e) => Restaurar());
            miCortarBandeja = new ToolStripMenuItem("Cortar Internet ahora (emergencia)", null, (s, e) => AlternarCorte());
            menuBandeja.Items.Add(miCortarBandeja);
            menuBandeja.Items.Add(new ToolStripSeparator());
            menuBandeja.Items.Add("Salir del todo", null, (s, e) => Salir());
            icono.ContextMenuStrip = menuBandeja;
            icono.DoubleClick += (s, e) => Restaurar();
            icono.BalloonTipClicked += (s, e) =>
            {
                Restaurar();
                pestanas.SelectedTab = pagAlertas;
            };

            temporizador = new System.Windows.Forms.Timer { Interval = 2000 };
            temporizador.Tick += (s, e) => Capturar();

            // Con el foco en el buscador, las tablas no marcan su primera fila al abrir.
            ActiveControl = txtBuscar;
        }

        // ---------- Ciclo de vida de la ventana ----------

        protected override bool ShowWithoutActivation
        {
            get { return RutaCaptura != null; }
        }

        // Con --bandeja (al iniciar Windows) la ventana se crea sin mostrarse: solo se ve el icono junto al reloj.
        protected override void SetVisibleCore(bool value)
        {
            if (IniciarEnBandeja && !arrancado)
            {
                if (!IsHandleCreated) CreateHandle();
                value = false;
                Arrancar();
            }
            base.SetVisibleCore(value);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Arrancar();
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            InstanciaUnica.PermitirAviso(Handle);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == InstanciaUnica.MensajeMostrar && m.Msg != 0)
            {
                Restaurar(); // alguien abrió el monitor otra vez
                return;
            }
            base.WndProc(ref m);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing && !saliendo && RutaCaptura == null && miBandeja.Checked)
            {
                // Cerrar la ventana no detiene la vigilancia: sigue en la bandeja hasta «Salir del todo».
                e.Cancel = true;
                Hide();
                if (!ajustes.Leer("AvisoBandejaMostrado", false))
                {
                    icono.ShowBalloonTip(10000, "Sigo vigilando",
                        "El monitor sigue funcionando junto al reloj. Para cerrarlo del todo: clic derecho en este icono → Salir del todo.", ToolTipIcon.Info);
                    ajustes.Escribir("AvisoBandejaMostrado", true);
                }
                return;
            }
            temporizador.Stop();
            tiempoReal.Detener();
            registro.GuardarSiHayCambios();
            conocidos.GuardarSiHayCambios(true);
            icono.Visible = false;
            icono.Dispose();
            base.OnFormClosing(e);
        }

        void Arrancar()
        {
            if (arrancado) return;
            arrancado = true;
            if (RutaCaptura != null)
            {
                // Las pruebas usan otra sesión de captura para no cortar la del monitor que pueda estar abierto.
                tiempoReal = new CapturaTiempoReal("MonitorConexiones-Prueba");
                PrepararCaptura();
            }
            else icono.Visible = true;
            tiempoReal.Iniciar();
            listas.Iniciar();
            ActualizarBloqueos();
            CorregirInicioConWindows();
            Capturar();
            temporizador.Start();
        }

        void Restaurar()
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
            BringToFront();
        }

        void Salir()
        {
            saliendo = true;
            Close();
        }

        int Px(int valor)
        {
            return (int)Math.Round(valor * escala);
        }

        // ---------- Captura y actualización ----------

        void Capturar()
        {
            if (ocupado || pausado) return;
            ocupado = true;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                List<Conexion> lista = null, breves = null;
                List<LecturaSospechosa> lecturas = null;
                string error = null;
                try
                {
                    lista = recolector.Capturar();
                    breves = recolector.Convertir(tiempoReal.Extraer());
                    lecturas = recolector.EvaluarLecturas(tiempoReal.ExtraerArchivos());
                    conocidos.GuardarSiHayCambios(false);
                }
                catch (Exception ex) { error = ex.Message; }
                try
                {
                    BeginInvoke((Action)(() =>
                    {
                        ocupado = false;
                        try
                        {
                            if (error != null) lblEstado.Text = "Error al leer las conexiones: " + error;
                            else AplicarCaptura(lista, breves, lecturas);
                        }
                        catch (Exception ex) { lblEstado.Text = "Error: " + ex.Message; }
                    }));
                }
                catch (Exception) { } // la ventana ya se cerró
            });
        }

        void AplicarCaptura(List<Conexion> lista, List<Conexion> breves, List<LecturaSospechosa> lecturas)
        {
            horaCaptura = DateTime.Now;
            if (inicio == DateTime.MinValue) inicio = horaCaptura;
            // Con la captura en tiempo real activa, cada apertura ya llega por ahí; la revisión periódica solo completa lo que falte.
            bool enTiempoReal = tiempoReal.Activa;

            var avisos = new List<Aviso>();
            var actuales = new HashSet<string>();
            foreach (var c in lista)
            {
                actuales.Add(c.Clave);
                DateTime desde;
                bool nueva = !vistaDesde.TryGetValue(c.Clave, out desde);
                if (nueva) vistaDesde[c.Clave] = desde = horaCaptura;
                c.Desde = desde;

                if (c.EnEscucha || c.EsLocal || c.Pid == 0) continue;
                AnotarEnHistorial(c, horaCaptura, nueva && !enTiempoReal);
                if (nueva && c.Riesgo >= NivelRiesgo.Medio)
                {
                    registro.Registrar(c, OrigenRevision, !enTiempoReal);
                    AvisoDeConexion(c, avisos);
                }
            }
            foreach (var c in breves)
            {
                AnotarEnHistorial(c, c.Desde, true);
                if (c.Riesgo >= NivelRiesgo.Medio)
                {
                    registro.Registrar(c, OrigenTiempoReal, true);
                    AvisoDeConexion(c, avisos);
                }
            }
            foreach (var l in lecturas)
            {
                registro.Registrar(l);
                if (avisados.Add(l.Proceso + "|" + l.Categoria))
                    avisos.Add(new Aviso { Titulo = "Posible robo de datos: " + l.Proceso, Texto = l.Motivo, Riesgo = l.Riesgo });
            }
            foreach (var k in vistaDesde.Keys.Where(x => !actuales.Contains(x)).ToList())
                vistaDesde.Remove(k);

            registro.GuardarSiHayCambios();
            ultimaCaptura = lista;
            RefrescarTablas();
            ActualizarAviso();
            if (miAvisar.Checked && avisos.Count > 0 && RutaCaptura == null) Avisar(avisos);
        }

        void AvisoDeConexion(Conexion c, List<Aviso> avisos)
        {
            if (avisados.Add(c.Proceso + "|" + c.Motivo))
                avisos.Add(new Aviso { Titulo = "Conexión a revisar: " + c.Proceso, Texto = c.Motivo + "\nDestino: " + c.TextoRemoto, Riesgo = c.Riesgo });
        }

        void AnotarEnHistorial(Conexion c, DateTime cuando, bool contar)
        {
            Visto v;
            if (!historial.TryGetValue(c.ClaveHistorial, out v))
            {
                v = new Visto { Clave = c.ClaveHistorial, IpRemota = c.IpRemota, PuertoRemoto = c.PuertoRemoto, Primera = c.Desde };
                historial.Add(v.Clave, v);
                contar = true;
            }
            if (contar) v.Veces++;
            if (cuando > v.Ultima) v.Ultima = cuando;
            v.Proceso = c.Proceso;
            v.Ruta = c.Ruta;
            v.Firmante = c.Firmante;
            v.Pid = c.Pid;
            v.Riesgo = c.Riesgo;
            v.Motivo = c.Motivo;
            v.Dominio = c.Dominio ?? v.Dominio;
        }

        void Avisar(List<Aviso> avisos)
        {
            string titulo, texto;
            if (avisos.Count == 1)
            {
                titulo = avisos[0].Titulo;
                texto = avisos[0].Texto;
            }
            else
            {
                titulo = avisos.Count + " alertas nuevas";
                texto = string.Join("\n", avisos.Select(a => a.Titulo).Distinct().Take(4)) + "\nAbre el monitor y mira la pestaña de alertas.";
            }
            var tipo = avisos.Any(a => a.Riesgo >= NivelRiesgo.Alto) ? ToolTipIcon.Error : ToolTipIcon.Warning;
            icono.ShowBalloonTip(10000, Recortar(titulo, 60), Recortar(texto, 250), tipo);
        }

        static string Recortar(string s, int max)
        {
            return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
        }

        // Franja de aviso: roja si Internet está cortado, amarilla si la captura en tiempo real no funciona.
        void ActualizarAviso()
        {
            string texto = null, boton = null;
            Action accion = null;
            Color fondo = Color.FromArgb(255, 243, 205), letra = Color.FromArgb(102, 77, 3);
            if (bloqueos.InternetCortado)
            {
                texto = "⛔  Internet está CORTADO por el monitor: ningún programa puede conectarse.";
                fondo = Color.FromArgb(248, 215, 218);
                letra = Color.FromArgb(114, 28, 36);
                boton = "Restablecer Internet";
                accion = AlternarCorte;
            }
            else if (!tiempoReal.Activa && !esAdmin)
            {
                texto = "⚠  Sin permisos de administrador pueden escaparse las conexiones muy breves, y no se vigilan los archivos de contraseñas ni los dominios.";
                boton = "Abrir como administrador";
                accion = ReiniciarComoAdmin;
            }
            else if (!tiempoReal.Activa)
            {
                texto = "⚠  No se pudo activar la captura en tiempo real (" + (tiempoReal.Error ?? "se detuvo") + "): pueden escaparse las conexiones muy breves.";
            }

            pnlAviso.Visible = texto != null;
            if (texto == null) return;
            if (lblAviso.Text != texto) lblAviso.Text = texto;
            pnlAviso.BackColor = fondo;
            lblAviso.ForeColor = letra;
            btnAviso.Visible = boton != null;
            if (boton != null) btnAviso.Text = boton;
            accionAviso = accion;
        }

        void ActualizarBloqueos()
        {
            try { bloqueos = Cortafuegos.Leer(); }
            catch (Exception) { bloqueos = new Cortafuegos.Estado(); }
            string texto = bloqueos.InternetCortado ? "Restablecer Internet" : "Cortar Internet ahora (emergencia)";
            miCortar.Text = texto;
            miCortarBandeja.Text = texto;
            btnCortar.Text = bloqueos.InternetCortado ? "Restablecer Internet" : "Cortar Internet";
            ActualizarAviso();
        }

        // Si se movió la carpeta del programa, la tarea de inicio con Windows apunta a la ruta vieja: se corrige.
        void CorregirInicioConWindows()
        {
            if (!esAdmin || RutaCaptura != null) return;
            try
            {
                string registrada = InicioConWindows.RutaRegistrada();
                if (registrada != null && !string.Equals(registrada, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase))
                    InicioConWindows.Activar(Application.ExecutablePath);
            }
            catch (Exception) { }
        }

        void RefrescarTablas()
        {
            if (ultimaCaptura == null) return;
            string texto = txtBuscar.Text.Trim().ToLowerInvariant();

            var visibles = ultimaCaptura.Where(c => MostrarConexion(c, texto)).ToList();
            Sincronizar(tablaActual, filasActuales, visibles, RellenarActual, "riesgo");

            var vistos = historial.Values.Where(v => (!chkSoloSospechosas.Checked || v.Riesgo > 0)
                && Coincide(texto, v.Proceso, Red.Formato(v.IpRemota), v.PuertoRemoto.ToString(), v.Dominio, NombreHost(v.IpRemota), v.Ruta, v.Firmante, v.Motivo)).ToList();
            Sincronizar(tablaHistorial, filasHistorial, vistos, RellenarHistorial, "riesgo");

            var alertas = registro.Todas.Where(a => Coincide(texto, a.Proceso, Red.Formato(a.IpRemota), a.PuertoRemoto.ToString(), a.Dominio,
                NombreHost(a.IpRemota), a.Ruta, a.Motivo, a.Origen, a.Detalle)).ToList();
            Sincronizar(tablaAlertas, filasAlertas, alertas, RellenarAlerta, "ultima");
            Titular(pagAlertas, "Alertas guardadas (" + registro.Cantidad + ")");

            var programas = conocidos.Copia().Where(p => (!chkSoloSospechosas.Checked || EstadoPrograma(p) != "Conocido")
                && Coincide(texto, p.Proceso, p.Ruta, p.Firmante, EstadoPrograma(p))).ToList();
            Sincronizar(tablaProgramas, filasProgramas, programas, RellenarPrograma, "primera");
            Titular(pagProgramas, "Programas (" + conocidos.Cantidad + ")");
            string explicacion = conocidos.Aprendiendo
                ? "Aprendiendo qué programas usas: hasta las " + conocidos.AprendizajeHasta.ToString("HH:mm") + " no avisará de programas nuevos. Después avisará la primera vez que uno nuevo se conecte."
                : "Avisa la primera vez que un programa se conecta a Internet y cuando el archivo de uno sin firma cambia. Clic derecho para bloquearlo o desbloquearlo.";
            if (lblProgramas.Text != explicacion) lblProgramas.Text = explicacion;

            int revisar = visibles.Count(c => c.Riesgo >= NivelRiesgo.Medio);
            lblEstado.Text = string.Format("{0} conexiones en pantalla · {1} para revisar · {2} destinos en el historial · actualizado a las {3:HH:mm:ss}{4}{5}",
                visibles.Count, revisar, historial.Count, horaCaptura, pausado ? " · EN PAUSA" : "",
                tiempoReal.Activa ? " · Captura en tiempo real activa" : "");
            lblListas.Text = listas.Resumen;
        }

        static void Titular(TabPage pagina, string titulo)
        {
            if (pagina.Text != titulo) pagina.Text = titulo;
        }

        bool MostrarConexion(Conexion c, string texto)
        {
            if (c.EnEscucha)
            {
                if (!chkEscucha.Checked || (IPAddress.IsLoopback(c.IpLocal) && !chkLocales.Checked)) return false;
            }
            else
            {
                if (c.EsLocal && !chkLocales.Checked) return false;
                if (c.YaCerrada && !chkCerradas.Checked) return false;
            }
            if (chkSoloSospechosas.Checked && c.Riesgo == NivelRiesgo.Ninguno) return false;
            return Coincide(texto, c.Proceso, c.TextoRemoto, c.TextoLocal, c.Dominio, NombreHost(c.IpRemota), c.Ruta, c.Firmante, c.Motivo,
                c.Estado, c.Direccion, c.Pid.ToString(), Red.Servicio(c.PuertoRemoto));
        }

        static bool Coincide(string texto, params string[] campos)
        {
            if (texto.Length == 0) return true;
            foreach (var campo in campos)
                if (campo != null && campo.ToLowerInvariant().Contains(texto)) return true;
            return false;
        }

        // Actualiza las filas existentes en lugar de rehacer la tabla, para conservar la selección y el desplazamiento.
        void Sincronizar<T>(DataGridView tabla, Dictionary<string, DataGridViewRow> filas, List<T> entradas,
            Action<DataGridViewRow, T> rellenar, string columnaInicial) where T : Entrada
        {
            int primeraVisible = tabla.FirstDisplayedScrollingRowIndex;
            var claves = new HashSet<string>(entradas.Select(x => x.Clave));
            foreach (var k in filas.Keys.Where(x => !claves.Contains(x)).ToList())
            {
                tabla.Rows.Remove(filas[k]);
                filas.Remove(k);
            }
            foreach (var en in entradas)
            {
                DataGridViewRow fila;
                if (!filas.TryGetValue(en.Clave, out fila))
                {
                    fila = tabla.Rows[tabla.Rows.Add()];
                    filas.Add(en.Clave, fila);
                }
                fila.Tag = en;
                rellenar(fila, en);
            }
            if (tabla.SortedColumn == null) tabla.Sort(tabla.Columns[columnaInicial], ListSortDirection.Descending);
            else tabla.Sort(tabla.SortedColumn, tabla.SortOrder == SortOrder.Ascending ? ListSortDirection.Ascending : ListSortDirection.Descending);
            try
            {
                if (primeraVisible >= 0 && primeraVisible < tabla.Rows.Count) tabla.FirstDisplayedScrollingRowIndex = primeraVisible;
            }
            catch (InvalidOperationException) { }
            QuitarSeleccionInicial(tabla);
        }

        // Hasta que el usuario toque una tabla, ninguna fila aparece marcada (la tabla marca la primera por su cuenta).
        void QuitarSeleccionInicial(DataGridView tabla)
        {
            if (tablasTocadas.Contains(tabla) || (tabla.CurrentCell == null && tabla.SelectedRows.Count == 0)) return;
            tabla.CurrentCell = null;
            tabla.ClearSelection();
        }

        string Servidor(Entrada en)
        {
            return en.Dominio ?? NombreHost(en.IpRemota);
        }

        void RellenarActual(DataGridViewRow fila, Conexion c)
        {
            bool nueva = c.Desde > inicio && (horaCaptura - c.Desde).TotalSeconds < 15;
            Poner(fila, "riesgo", c.Riesgo);
            Poner(fila, "proceso", c.Proceso);
            Poner(fila, "direccion", c.Direccion);
            Poner(fila, "ip", c.EnEscucha ? "(acepta conexiones)" : Red.Formato(c.IpRemota));
            Poner(fila, "puerto", c.EnEscucha ? 0 : c.PuertoRemoto);
            Poner(fila, "servicio", Red.Servicio(c.EnEscucha ? c.PuertoLocal : c.PuertoRemoto));
            Poner(fila, "host", c.EnEscucha ? "" : Servidor(c));
            Poner(fila, "estado", c.Estado);
            Poner(fila, "firmante", c.Firmante);
            Poner(fila, "motivo", c.Motivo);
            Poner(fila, "pid", c.Pid);
            Poner(fila, "desde", c.Desde);
            Poner(fila, "local", c.TextoLocal);
            Poner(fila, "ruta", c.Ruta);
            Colorear(fila, NivelRiesgo.Fondo(c.Riesgo, nueva));
        }

        void RellenarHistorial(DataGridViewRow fila, Visto v)
        {
            Poner(fila, "riesgo", v.Riesgo);
            Poner(fila, "proceso", v.Proceso);
            Poner(fila, "ip", Red.Formato(v.IpRemota));
            Poner(fila, "puerto", v.PuertoRemoto);
            Poner(fila, "servicio", Red.Servicio(v.PuertoRemoto));
            Poner(fila, "host", Servidor(v));
            Poner(fila, "veces", v.Veces);
            Poner(fila, "primera", v.Primera);
            Poner(fila, "ultima", v.Ultima);
            Poner(fila, "firmante", v.Firmante);
            Poner(fila, "motivo", v.Motivo);
            Poner(fila, "ruta", v.Ruta);
            Colorear(fila, NivelRiesgo.Fondo(v.Riesgo, false));
        }

        void RellenarAlerta(DataGridViewRow fila, Alerta a)
        {
            bool archivo = a.Tipo == "Archivo";
            Poner(fila, "riesgo", a.Riesgo);
            Poner(fila, "ultima", a.Ultima);
            Poner(fila, "proceso", a.Proceso);
            Poner(fila, "motivo", a.Motivo);
            Poner(fila, "ip", Red.Formato(a.IpRemota));
            Poner(fila, "puerto", archivo ? 0 : a.PuertoRemoto);
            Poner(fila, "protocolo", a.Protocolo);
            Poner(fila, "host", archivo ? "" : Servidor(a));
            Poner(fila, "detalle", a.Detalle);
            Poner(fila, "veces", a.Veces);
            Poner(fila, "primera", a.Primera);
            Poner(fila, "origen", a.Origen);
            Poner(fila, "ruta", a.Ruta);
            Colorear(fila, NivelRiesgo.Fondo(a.Riesgo, false));
        }

        void RellenarPrograma(DataGridViewRow fila, ProgramasConocidos.Programa p)
        {
            string estado = EstadoPrograma(p);
            Poner(fila, "estado", estado);
            Poner(fila, "proceso", p.Proceso);
            Poner(fila, "firmante", p.Firmante);
            Poner(fila, "primera", p.Primera);
            Poner(fila, "ultima", p.Ultima);
            Poner(fila, "ruta", p.Ruta);
            Colorear(fila, estado == "Bloqueado" ? Color.FromArgb(222, 222, 222)
                : estado == "Nuevo" ? NivelRiesgo.ColorNueva
                : estado == "Modificado" ? NivelRiesgo.ColorMedio : Color.Empty);
        }

        string EstadoPrograma(ProgramasConocidos.Programa p)
        {
            if (bloqueos.Programas.Contains(p.Ruta ?? "")) return "Bloqueado";
            DateTime ahora = DateTime.Now;
            if ((ahora - p.Nuevo).TotalMinutes < ProgramasConocidos.MinutosNovedad) return "Nuevo";
            if ((ahora - p.Modificado).TotalMinutes < ProgramasConocidos.MinutosNovedad) return "Modificado";
            return "Conocido";
        }

        static void Poner(DataGridViewRow fila, string columna, object valor)
        {
            var celda = fila.Cells[columna];
            if (!Equals(celda.Value, valor)) celda.Value = valor;
        }

        static void Colorear(DataGridViewRow fila, Color fondo)
        {
            if (fila.DefaultCellStyle.BackColor != fondo) fila.DefaultCellStyle.BackColor = fondo;
        }

        // Nombre del servidor: el dominio que pidió algún programa (captura en tiempo real) o, si no, el DNS inverso,
        // que se resuelve en segundo plano y aparece en la siguiente actualización.
        string NombreHost(IPAddress ip)
        {
            if (ip == null || Red.EsNula(ip)) return "";
            if (IPAddress.IsLoopback(ip)) return "(este equipo)";
            string dominio = tiempoReal.DominioCualquiera(ip);
            if (dominio != null) return dominio;
            string clave = ip.ToString();
            string nombre;
            if (nombresDns.TryGetValue(clave, out nombre)) return nombre;
            nombresDns[clave] = "…";
            bool privada = Red.EsPrivada(ip);
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string n = "";
                try { n = Nativo.NombreInverso(ip); } catch { }
                if (n.Length == 0 || n == clave) n = privada ? "(red local)" : "(sin nombre)";
                else if (privada) n += " (red local)";
                nombresDns[clave] = n;
            });
            return "…";
        }

        // ---------- Construcción de la interfaz ----------

        DataGridView CrearTabla()
        {
            var g = new DataGridView
            {
                Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
                AllowUserToResizeRows = false, RowHeadersVisible = false, MultiSelect = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect, BackgroundColor = SystemColors.Window,
                BorderStyle = BorderStyle.None, ShowCellToolTips = true,
                ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize
            };
            g.RowTemplate.Height = Font.Height + Px(6);
            // Evita el parpadeo al actualizar cada pocos segundos.
            typeof(DataGridView).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(g, true, null);
            g.CellFormatting += FormatearCelda;
            g.SortCompare += CompararFilas;
            g.KeyDown += (s, e) => tablasTocadas.Add(g);
            g.CellMouseDown += (s, e) =>
            {
                tablasTocadas.Add(g);
                if (e.Button != MouseButtons.Right || e.RowIndex < 0) return;
                g.ClearSelection();
                g.Rows[e.RowIndex].Selected = true;
                g.CurrentCell = g.Rows[e.RowIndex].Cells[Math.Max(e.ColumnIndex, 0)];
            };
            return g;
        }

        DataGridViewColumn AgregarColumna(DataGridView g, string nombre, string titulo, int ancho, Type tipo)
        {
            var c = new DataGridViewTextBoxColumn
            {
                Name = nombre, HeaderText = titulo, Width = Px(ancho), ValueType = tipo, SortMode = DataGridViewColumnSortMode.Automatic
            };
            g.Columns.Add(c);
            return c;
        }

        void FormatearCelda(object sender, DataGridViewCellFormattingEventArgs e)
        {
            var g = (DataGridView)sender;
            string columna = g.Columns[e.ColumnIndex].Name;
            if (columna == "riesgo" && e.Value is int)
            {
                int nivel = (int)e.Value;
                e.Value = NivelRiesgo.Nombre(nivel);
                if (nivel >= NivelRiesgo.Medio) e.CellStyle.Font = negrita;
                e.FormattingApplied = true;
            }
            else if (columna == "puerto" && e.Value is int && (int)e.Value == 0)
            {
                e.Value = "";
                e.FormattingApplied = true;
            }
            else if (columna == "estado" && g == tablaProgramas && e.Value is string && (string)e.Value != "Conocido")
            {
                e.CellStyle.Font = negrita;
            }
        }

        void CompararFilas(object sender, DataGridViewSortCompareEventArgs e)
        {
            int r = Comparer.Default.Compare(e.CellValue1, e.CellValue2);
            if (r == 0)
            {
                // Desempate fijo para que las filas no cambien de sitio en cada actualización.
                var g = (DataGridView)sender;
                var a = (Entrada)g.Rows[e.RowIndex1].Tag;
                var b = (Entrada)g.Rows[e.RowIndex2].Tag;
                r = string.Compare(a.Proceso, b.Proceso, StringComparison.OrdinalIgnoreCase);
                if (r == 0) r = string.CompareOrdinal(a.Clave, b.Clave);
                if (g.SortOrder == SortOrder.Descending) r = -r;
            }
            e.SortResult = r;
            e.Handled = true;
        }

        Label Etiqueta(string texto)
        {
            return new Label { Text = texto, AutoSize = true, Margin = new Padding(Px(8), Px(6), 0, 0) };
        }

        Label Muestra(Color color, string texto)
        {
            return new Label
            {
                Text = texto, AutoSize = true, BackColor = color, BorderStyle = BorderStyle.FixedSingle,
                Padding = new Padding(Px(4), Px(1), Px(4), Px(1)), Margin = new Padding(Px(3))
            };
        }

        CheckBox Casilla(Control padre, string texto, bool marcada)
        {
            var c = new CheckBox { Text = texto, AutoSize = true, Checked = marcada, Margin = new Padding(Px(10), Px(5), 0, 0) };
            c.CheckedChanged += (s, e) => RefrescarTablas();
            padre.Controls.Add(c);
            return c;
        }

        Button Boton(Control padre, string texto, EventHandler accion)
        {
            var b = new Button { Text = texto, AutoSize = true, Margin = new Padding(Px(8), Px(1), 0, Px(2)) };
            b.Click += accion;
            padre.Controls.Add(b);
            return b;
        }

        // ---------- Acciones ----------

        DataGridView TablaVisible()
        {
            switch (pestanas.SelectedIndex)
            {
                case 1: return tablaHistorial;
                case 2: return tablaAlertas;
                case 3: return tablaProgramas;
                default: return tablaActual;
            }
        }

        Entrada Seleccionada()
        {
            var tabla = TablaVisible();
            return tabla.SelectedRows.Count > 0 ? tabla.SelectedRows[0].Tag as Entrada : null;
        }

        void AlternarPausa()
        {
            pausado = !pausado;
            btnPausa.Text = pausado ? "Reanudar" : "Pausar";
            if (pausado) lblEstado.Text += " · EN PAUSA";
            else Capturar();
        }

        bool ComprobarAdmin(string accion)
        {
            if (esAdmin) return true;
            if (MessageBox.Show(this, "Para " + accion + " hace falta abrir el monitor como administrador.\n\n¿Lo abro ahora como administrador?",
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                ReiniciarComoAdmin();
            return false;
        }

        bool Confirmar(string pregunta, string titulo)
        {
            return MessageBox.Show(this, pregunta, titulo, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        void Error(string texto)
        {
            MessageBox.Show(this, texto, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        // Comprueba que el firewall esté encendido antes de crear un bloqueo.
        bool FirewallListo()
        {
            string problema = Cortafuegos.ProblemaDelFirewall();
            if (problema == null) return true;
            MessageBox.Show(this, problema, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }

        void AlternarCorte()
        {
            if (!ComprobarAdmin(bloqueos.InternetCortado ? "restablecer Internet" : "cortar Internet")) return;
            try
            {
                if (bloqueos.InternetCortado)
                {
                    Cortafuegos.RestablecerInternet();
                }
                else
                {
                    if (!FirewallListo()) return;
                    if (!Confirmar("¿Cortar Internet en este equipo?\n\nNingún programa podrá conectarse (tampoco el navegador) hasta que pulses " +
                                   "«Restablecer Internet». Es un freno de emergencia por si crees que un virus está enviando tus datos.\n\n" +
                                   "El corte sigue aunque cierres el monitor o reinicies el equipo.", "Cortar Internet")) return;
                    Cortafuegos.CortarInternet();
                }
            }
            catch (Exception ex) { Error("No se pudo cambiar el Firewall de Windows: " + ex.Message); }
            ActualizarBloqueos();
        }

        void BloquearPrograma()
        {
            var en = Seleccionada();
            if (en == null || string.IsNullOrEmpty(en.Ruta) || !ComprobarAdmin("bloquear programas") || !FirewallListo()) return;
            if (!Confirmar("¿Bloquear el acceso a Internet de «" + en.Proceso + "»?\n\n" + en.Ruta + "\n\n" +
                           "Se crea una regla en el Firewall de Windows. Las conexiones que ya tenga abiertas pueden seguir hasta que se cierren: " +
                           "para cortarlas ya, cierra también el programa (clic derecho → Cerrar el programa).\n\n" +
                           "Para deshacerlo: clic derecho → Desbloquear este programa.", "Bloquear programa")) return;
            try { Cortafuegos.BloquearPrograma(en.Ruta); }
            catch (Exception ex) { Error("No se pudo crear el bloqueo: " + ex.Message); }
            ActualizarBloqueos();
            RefrescarTablas();
        }

        void DesbloquearPrograma()
        {
            var en = Seleccionada();
            if (en == null || string.IsNullOrEmpty(en.Ruta) || !ComprobarAdmin("desbloquear programas")) return;
            try { Cortafuegos.DesbloquearPrograma(en.Ruta); }
            catch (Exception ex) { Error("No se pudo quitar el bloqueo: " + ex.Message); }
            ActualizarBloqueos();
            RefrescarTablas();
        }

        void BloquearIp()
        {
            var en = Seleccionada();
            if (en == null || en.IpRemota == null || !ComprobarAdmin("bloquear IPs") || !FirewallListo()) return;
            string destino = en.IpRemota + (en.Dominio != null ? " (" + en.Dominio + ")" : "");
            if (!Confirmar("¿Bloquear la IP " + destino + "?\n\nNingún programa de este equipo podrá conectarse con ella, ni ella con este equipo.\n\n" +
                           "Para deshacerlo: clic derecho → Desbloquear esta IP.", "Bloquear IP")) return;
            try { Cortafuegos.BloquearIp(en.IpRemota); }
            catch (Exception ex) { Error("No se pudo crear el bloqueo: " + ex.Message); }
            ActualizarBloqueos();
            RefrescarTablas();
        }

        void DesbloquearIp()
        {
            var en = Seleccionada();
            if (en == null || en.IpRemota == null || !ComprobarAdmin("desbloquear IPs")) return;
            try { Cortafuegos.DesbloquearIp(en.IpRemota); }
            catch (Exception ex) { Error("No se pudo quitar el bloqueo: " + ex.Message); }
            ActualizarBloqueos();
            RefrescarTablas();
        }

        void QuitarTodosLosBloqueos()
        {
            if (!ComprobarAdmin("quitar los bloqueos")) return;
            if (!Confirmar("¿Quitar todos los bloqueos creados por el monitor (programas, IPs y corte de Internet)?", "Quitar bloqueos")) return;
            try { Cortafuegos.QuitarTodo(); }
            catch (Exception ex) { Error("No se pudieron quitar los bloqueos: " + ex.Message); }
            ActualizarBloqueos();
            RefrescarTablas();
        }

        void AlternarInicioConWindows()
        {
            try
            {
                if (InicioConWindows.Activado())
                {
                    if (!ComprobarAdmin("desactivar el inicio con Windows")) return;
                    InicioConWindows.Desactivar();
                    MessageBox.Show(this, "Listo: el monitor ya no se abrirá solo al iniciar Windows.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    if (!ComprobarAdmin("activar el inicio con Windows")) return;
                    InicioConWindows.Activar(Application.ExecutablePath);
                    MessageBox.Show(this, "Listo: cada vez que inicies sesión, el monitor se abrirá solo en la bandeja (junto al reloj), " +
                                          "con permisos de administrador y sin preguntar.\n\nSi mueves la carpeta del programa, ábrelo una vez como " +
                                          "administrador desde su nueva ubicación y se corregirá solo.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex) { Error("No se pudo cambiar el inicio con Windows: " + ex.Message); }
        }

        void AbrirWeb(string url)
        {
            try { Process.Start(url); }
            catch (Exception ex) { MessageBox.Show(this, "No se pudo abrir el navegador: " + ex.Message, Text); }
        }

        void AbrirCarpeta()
        {
            var en = Seleccionada();
            if (en != null && File.Exists(en.Ruta)) Process.Start("explorer.exe", "/select,\"" + en.Ruta + "\"");
        }

        void AbrirCarpetaDatos()
        {
            try
            {
                Directory.CreateDirectory(Datos.Carpeta);
                if (File.Exists(registro.Ruta)) Process.Start("explorer.exe", "/select,\"" + registro.Ruta + "\"");
                else Process.Start("explorer.exe", "\"" + Datos.Carpeta + "\"");
            }
            catch (Exception ex) { MessageBox.Show(this, "No se pudo abrir la carpeta: " + ex.Message, Text); }
        }

        static string RutaPrueba()
        {
            return Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "PruebaConexionFugaz.exe");
        }

        void AbrirPrueba()
        {
            string ruta = RutaPrueba();
            if (File.Exists(ruta)) Process.Start(ruta);
            else MessageBox.Show(this, "No encuentro PruebaConexionFugaz.exe en la carpeta del monitor.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void AcercaDe()
        {
            MessageBox.Show(this,
                "Monitor de conexiones de red " + Autoria.Version + "\n" +
                "Creado por " + Autoria.Nombre + " · " + Autoria.Web + "\n\n" +
                "Vigila qué programas se conectan a Internet, detecta conexiones sospechosas e intentos de robo de datos, y permite bloquearlos.\n\n" +
                "Listas negras: Feodo Tracker (abuse.ch), Spamhaus DROP, URLhaus (vía malware-filter) y Emerging Threats.\n\n" +
                "No sustituye al antivirus: úsalo junto a Seguridad de Windows.",
                "Acerca del Monitor de conexiones", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void BuscarPrograma()
        {
            var en = Seleccionada();
            if (en != null) AbrirWeb("https://www.google.com/search?q=" + Uri.EscapeDataString("\"" + en.Proceso + "\" qué es"));
        }

        // Calcula la huella SHA-256 del programa y la busca en VirusTotal (el archivo no se sube).
        void AnalizarArchivo()
        {
            var en = Seleccionada();
            if (en == null) return;
            try
            {
                Cursor = Cursors.WaitCursor;
                string huella;
                using (var fs = new FileStream(en.Ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var sha = SHA256.Create())
                    huella = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
                AbrirWeb("https://www.virustotal.com/gui/file/" + huella);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "No se pudo leer el archivo: " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                Cursor = Cursors.Default;
            }
        }

        void CopiarFila()
        {
            var tabla = TablaVisible();
            if (tabla.SelectedRows.Count == 0) return;
            var fila = tabla.SelectedRows[0];
            var partes = tabla.Columns.Cast<DataGridViewColumn>().OrderBy(c => c.DisplayIndex)
                .Select(c => c.HeaderText + ": " + Convert.ToString(fila.Cells[c.Index].FormattedValue));
            Clipboard.SetText(string.Join(Environment.NewLine, partes));
        }

        void TerminarProceso()
        {
            var c = Seleccionada() as Conexion;
            if (c == null || c.Pid <= 4) return;
            string pregunta = string.Format("¿Cerrar a la fuerza «{0}» (PID {1})?\n\nSi es un programa que estás usando, se cerrará sin guardar. " +
                "Si es malware puede volver a abrirse: en ese caso haz un análisis completo con Seguridad de Windows.", c.Proceso, c.Pid);
            if (!Confirmar(pregunta, "Cerrar programa")) return;
            try
            {
                using (var p = Process.GetProcessById(c.Pid)) p.Kill();
                Capturar();
            }
            catch (Exception ex)
            {
                Error("No se pudo cerrar: " + ex.Message + (esAdmin ? "" : "\n\nPrueba a abrir el monitor como administrador."));
            }
        }

        void VaciarRegistro()
        {
            if (registro.Cantidad == 0) return;
            if (!Confirmar("¿Borrar las " + registro.Cantidad + " alertas guardadas? No se puede deshacer.", "Vaciar el registro")) return;
            registro.Vaciar();
            RefrescarTablas();
        }

        void ExportarHistorial()
        {
            using (var dlg = new SaveFileDialog { Filter = "Archivo CSV (*.csv)|*.csv", FileName = "conexiones_" + DateTime.Now.ToString("yyyy-MM-dd_HHmm") + ".csv" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                string sep = CultureInfo.CurrentCulture.TextInfo.ListSeparator;
                var sb = new StringBuilder();
                sb.AppendLine(string.Join(sep, "Riesgo", "Programa", "IP remota", "Puerto", "Servicio", "Nombre del servidor", "Conexiones",
                    "Primera vez", "Última vez", "Firmado por", "Por qué revisarla", "Ubicación"));
                foreach (var v in historial.Values.OrderByDescending(x => x.Riesgo).ThenBy(x => x.Proceso))
                {
                    var campos = new[]
                    {
                        NivelRiesgo.Nombre(v.Riesgo), v.Proceso, v.IpRemota.ToString(), v.PuertoRemoto.ToString(), Red.Servicio(v.PuertoRemoto),
                        Servidor(v), v.Veces.ToString(), v.Primera.ToString("yyyy-MM-dd HH:mm:ss"), v.Ultima.ToString("yyyy-MM-dd HH:mm:ss"),
                        v.Firmante, v.Motivo, v.Ruta
                    };
                    sb.AppendLine(string.Join(sep, campos.Select(Csv)));
                }
                File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
            }
        }

        static string Csv(string s)
        {
            return "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
        }

        void ReiniciarComoAdmin()
        {
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--esperar-pid " + Process.GetCurrentProcess().Id)
                {
                    Verb = "runas", UseShellExecute = true
                });
                Salir();
            }
            catch (Win32Exception) { } // el usuario canceló el aviso de Windows
        }

        // ---------- Modo de prueba ----------

        void PrepararCaptura()
        {
            var espera = new System.Windows.Forms.Timer { Interval = 25000 };
            espera.Tick += (s, e) =>
            {
                espera.Stop();
                string baseRuta = Path.Combine(Path.GetDirectoryName(RutaCaptura), Path.GetFileNameWithoutExtension(RutaCaptura));
                string[] nombres = { "", "_historial", "_alertas", "_programas" };
                for (int i = 0; i < nombres.Length; i++)
                {
                    pestanas.SelectedIndex = i;
                    Application.DoEvents();
                    GuardarImagen(baseRuta + nombres[i] + ".png");
                }
                File.WriteAllText(baseRuta + "_tiempo_real.txt", tiempoReal.Diagnostico() + listas.Resumen + Environment.NewLine, Encoding.UTF8);
                Salir();
            };
            espera.Start();
        }

        void GuardarImagen(string ruta)
        {
            using (var bmp = new Bitmap(Width, Height))
            {
                DrawToBitmap(bmp, new Rectangle(Point.Empty, Size));
                bmp.Save(ruta, ImageFormat.Png);
            }
        }
    }
}
