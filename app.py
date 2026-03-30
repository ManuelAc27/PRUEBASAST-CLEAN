"""
Aplicación vulnerable para práctica de SAST con SonarCloud.
Contiene vulnerabilidades intencionales para demostrar el análisis estático.
"""

import sqlite3
import os
from flask import Flask, request, make_response, jsonify

app = Flask(__name__)

# ==========================================
# VULNERABILIDAD 1: Hardcoded Secrets
# ==========================================
# Esto es una mala práctica - las credenciales NO deben estar en el código
API_KEY = "sk_test_EJEMPLO1234567890_CLAVE_EDUCATIVA"
DB_PASSWORD = "admin123"
SECRET_TOKEN = "mi_token_super_secreto_12345"

# ==========================================
# VULNERABILIDAD 2: SQL Injection
# ==========================================

def init_database():
    """Inicializa una base de datos SQLite de ejemplo"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Crear tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    
    # Insertar datos de ejemplo
    cursor.execute("INSERT OR IGNORE INTO users (id, name, email) VALUES (1, 'admin', 'admin@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users (id, name, email) VALUES (2, 'user1', 'user1@example.com')")
    
    conn.commit()
    conn.close()

@app.route('/user')
def get_user():
    """
    Endpoint vulnerable a SQL Injection.
    El parámetro 'user' no está sanitizado.
    """
    username = request.args.get('user', '')
    
    # VULNERABLE: Concatenación directa en la consulta SQL
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(query)  # Línea vulnerable
        results = cursor.fetchall()
        conn.close()
        
        users = []
        for row in results:
            users.append({"id": row[0], "name": row[1], "email": row[2]})
        
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user-safe')
def get_user_safe():
    """
    Versión segura del endpoint (para demostrar la corrección).
    Usa consultas parametrizadas.
    """
    username = request.args.get('user', '')
    
    # SEGURO: Usando consulta parametrizada
    query = "SELECT * FROM users WHERE name = ?"
    
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(query, (username,))  # Parametrizado - seguro
        results = cursor.fetchall()
        conn.close()
        
        users = []
        for row in results:
            users.append({"id": row[0], "name": row[1], "email": row[2]})
        
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# VULNERABILIDAD 3: Insecure Cookies
# ==========================================

@app.route('/login')
def login():
    """
    Endpoint que establece cookies inseguras.
    Falta HttpOnly y Secure flags.
    """
    username = request.args.get('username', 'guest')
    
    # Crear respuesta
    resp = make_response(f"Usuario {username} ha iniciado sesión")
    
    # VULNERABLE: Cookie sin HttpOnly y sin Secure
    resp.set_cookie('session_id', 'abc123xyz789')
    resp.set_cookie('username', username)
    
    # VULNERABLE: Cookie que debería ser HttpOnly pero no lo es
    resp.set_cookie('auth_token', 'token_12345', httponly=False)
    
    return resp

@app.route('/login-secure')
def login_secure():
    """
    Versión segura con cookies configuradas correctamente.
    """
    username = request.args.get('username', 'guest')
    
    resp = make_response(f"Usuario {username} ha iniciado sesión (seguro)")
    
    # SEGURO: Cookie con HttpOnly y Secure
    resp.set_cookie('session_id', 'abc123xyz789', httponly=True, secure=True)
    resp.set_cookie('auth_token', 'token_12345', httponly=True, secure=True)
    
    return resp

# ==========================================
# VULNERABILIDAD 4: Uso de eval() (peligroso)
# ==========================================

@app.route('/calculate')
def calculate():
    """
    Endpoint que usa eval() - puede ejecutar código arbitrario.
    """
    expression = request.args.get('expr', '0')
    
    #  VULNERABLE: eval() puede ejecutar código malicioso
    # Ejemplo: /calculate?expr=__import__('os').system('ls')
    try:
        result = eval(expression)  # Línea vulnerable
        return jsonify({"expression": expression, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/calculate-safe')
def calculate_safe():
    """
    Versión segura sin usar eval().
    """
    expression = request.args.get('expr', '0')
    
    # SEGURO: Validar y evaluar de forma segura
    try:
        # Solo permitir números y operaciones básicas
        allowed_chars = set('0123456789+-*/(). ')
        if not all(c in allowed_chars for c in expression):
            return jsonify({"error": "Caracteres no permitidos"}), 400
        
        # Usar eval con restricciones o mejor usar un parser matemático
        # NOTA: Esto sigue siendo mejorable, pero es más seguro que eval() directo
        result = eval(expression, {"__builtins__": {}}, {})
        return jsonify({"expression": expression, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ==========================================
# VULNERABILIDAD 5: Información sensible en logs
# ==========================================

@app.route('/register')
def register():
    """
    Endpoint que loguea información sensible.
    """
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    email = request.args.get('email', '')
    
    #  VULNERABLE: Loggear contraseñas es una mala práctica
    app.logger.info(f"Registro de nuevo usuario: {username}")
    app.logger.info(f"Contraseña recibida: {password}")  # ¡No hacer esto!
    app.logger.info(f"Email: {email}")
    
    return jsonify({"message": f"Usuario {username} registrado exitosamente"})

# ==========================================
# Endpoint de prueba
# ==========================================

@app.route('/')
def index():
    """Endpoint principal con información de la API"""
    return jsonify({
        "name": "API Vulnerable para SAST",
        "version": "1.0.0",
        "endpoints": [
            "/user?user=nombre",
            "/user-safe?user=nombre",
            "/login?username=nombre",
            "/login-secure?username=nombre",
            "/calculate?expr=2+2",
            "/register?username=xxx&password=xxx&email=xxx"
        ]
    })

# ==========================================
# Inicialización de la aplicación
# ==========================================

if __name__ == '__main__':
    # Inicializar base de datos
    init_database()
    
    # Ejecutar la aplicación
    #  debug=True no debe usarse en producción
    app.run(debug=True, host='0.0.0.0', port=5000)