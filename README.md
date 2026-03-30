# Proyecto Vulnerable para Práctica SAST

Este proyecto contiene vulnerabilidades intencionales para practicar análisis estático de código con SonarCloud.

## Vulnerabilidades Incluidas

1. **Hardcoded Secrets** - Credenciales escritas directamente en el código
2. **SQL Injection** - Consultas SQL con concatenación directa
3. **Insecure Cookies** - Cookies sin flags HttpOnly y Secure
4. **Uso de eval()** - Ejecución de código arbitrario
5. **Información sensible en logs** - Contraseñas logueadas

## Instalación

```bash
pip install -r requirements.txt