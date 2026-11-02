@echo off
rem Compila el Monitor de conexiones con el compilador de C# que ya incluye Windows (.NET Framework 4).
rem Si esta el codigo de la prueba (PruebaConexionFugaz.cs), la compila tambien.
cd /d "%~dp0"
set CSC="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
set FUENTES=MonitorConexiones.cs Ventana.cs CapturaTiempoReal.cs Proteccion.cs Registros.cs Nativo.cs
set REFERENCIAS=/r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:Microsoft.CSharp.dll

rem Si el monitor esta abierto, su archivo no se puede sobrescribir pero si renombrar: la version nueva borra la vieja al abrirse.
if exist ..\MonitorConexiones.exe move /y ..\MonitorConexiones.exe ..\MonitorConexiones.old.exe >nul 2>&1

%CSC% /nologo /target:winexe /optimize+ /codepage:65001 /win32icon:icono.ico %REFERENCIAS% /out:..\MonitorConexiones.exe %FUENTES% || goto error
if exist PruebaConexionFugaz.cs (
    %CSC% /nologo /target:exe /optimize+ /codepage:65001 /r:System.dll /r:System.Core.dll /out:..\PruebaConexionFugaz.exe PruebaConexionFugaz.cs || goto error
)
echo.
for %%I in ("..\MonitorConexiones.exe") do echo Listo: %%~fI
if exist PruebaConexionFugaz.cs for %%I in ("..\PruebaConexionFugaz.exe") do echo Listo: %%~fI
echo.
pause
exit /b 0

:error
if not exist ..\MonitorConexiones.exe if exist ..\MonitorConexiones.old.exe move /y ..\MonitorConexiones.old.exe ..\MonitorConexiones.exe >nul 2>&1
echo.
echo Hubo errores al compilar.
pause
exit /b 1
