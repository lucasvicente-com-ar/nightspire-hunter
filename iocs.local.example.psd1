# Ejemplo de iocs.local.psd1: copiarlo con ese nombre junto a iocs.psd1 y completarlo.
# Sirve para lo que es propio de cada organizacion y no debe publicarse: datos de la nota
# de rescate recibida, IP vistas en los propios registros, redes internas a vigilar y
# excepciones (software legitimo que no se quiere ver en cada informe).
#
# Reglas de combinacion con iocs.psd1:
#   - listas (@(...))        -> se suman a las de iocs.psd1
#   - tablas (Sha256 = @{})  -> se agregan las entradas
#   - Version                -> se ignora
# Se puede usar cualquier clave de iocs.psd1. Las que no se necesiten se pueden borrar.
# Comillas simples; la barra invertida se escribe una sola vez (C:\Carpeta).
@{
    # Texto que identifica la nota que recibio la organizacion (direccion onion, correo, ID de qTox)
    NoteContentMarkers = @('ejemplo1234567890abcdefonionaddress', 'contacto@onionmail.org')

    # IP y rangos vistos en el propio incidente (fuerza bruta, C2, exfiltracion)
    IPs                = @('203.0.113.10')
    Cidrs              = @('198.51.100.0/24')

    # Redes propias que merecen revision si aparecen en un RDP (pool de la VPN, por ejemplo)
    WatchRanges        = @('10.10.200.0/24')

    # Hashes propios (muestras del incidente)
    Sha256             = @{
        '0000000000000000000000000000000000000000000000000000000000000000' = 'Descripcion de la muestra'
    }

    # Excepciones: patrones con * comparados contra la ruta y contra la clave (columna Key del CSV).
    # Agregar SOLO lo que se confirmo como legitimo: una excepcion amplia (por ejemplo
    # 'SERVICIO|AnyDesk*') tambien ocultaria un AnyDesk instalado por el atacante. Ejemplos:
    #   '*\Program Files (x86)\WinSCP\*'
    #   'SOFT|VMware Workstation*'
    Allowlist          = @()
}
