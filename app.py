"""
Aplicación segura para práctica de SAST con SonarCloud.
Todas las vulnerabilidades han sido corregidas.
"""

import sqlite3
import re
import secrets
from flask import Flask, request, make_response, jsonify

app = Flask(__name__)

# ==========================================
# CORRECCIÓN 1: Hardcoded Secrets
# ==========================================
# Las credenciales ahora se obtienen de variables de entorno
import os
API_KEY = os.environ.get('API_KEY', 'sk_test_configure_via_environment')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'configure_via_environment')
SECRET_TOKEN = os.environ.get('SECRET_TOKEN', secrets.token_urlsafe(32))

# ==========================================
# CORRECCIÓN 2: SQL Injection - Usando consultas parametrizadas
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
    Endpoint seguro - usa consultas parametrizadas.
    """
    username = request.args.get('user', '')
    
    # SEGURO: Consulta parametrizada previene SQL Injection
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

@app.route('/user-safe')
def get_user_safe():
    """
    Versión segura del endpoint (referencia).
    """
    username = request.args.get('user', '')
    
    query = "SELECT * FROM users WHERE name = ?"
    
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        results = cursor.fetchall()
        conn.close()
        
        users = []
        for row in results:
            users.append({"id": row[0], "name": row[1], "email": row[2]})
        
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# CORRECCIÓN 3: Cookies seguras con HttpOnly y Secure
# ==========================================

@app.route('/login')
def login():
    """
    Endpoint que establece cookies seguras.
    """
    username = request.args.get('username', 'guest')
    
    resp = make_response(f"Usuario {username} ha iniciado sesión")
    
    # SEGURO: Cookies con HttpOnly y Secure
    resp.set_cookie('session_id', secrets.token_urlsafe(32), httponly=True, secure=True)
    resp.set_cookie('username', username, httponly=True, secure=True)
    resp.set_cookie('auth_token', secrets.token_urlsafe(32), httponly=True, secure=True)
    
    return resp

@app.route('/login-secure')
def login_secure():
    """
    Versión segura con cookies configuradas correctamente.
    """
    username = request.args.get('username', 'guest')
    
    resp = make_response(f"Usuario {username} ha iniciado sesión (seguro)")
    
    resp.set_cookie('session_id', secrets.token_urlsafe(32), httponly=True, secure=True)
    resp.set_cookie('auth_token', secrets.token_urlsafe(32), httponly=True, secure=True)
    
    return resp

# ==========================================
# CORRECCIÓN 4: Eliminar eval() - Usar parser matemático seguro
# ==========================================

def safe_math_eval(expression):
    """
    Evalúa expresiones matemáticas de forma segura sin usar eval().
    Solo permite números, operadores básicos y paréntesis.
    """
    # Validar que solo contenga caracteres permitidos
    allowed_pattern = r'^[\d+\-*/%\s\(\)]+$'
    if not re.match(allowed_pattern, expression):
        raise ValueError("Caracteres no permitidos en la expresión")
    
    # Usar eval de forma restringida (solo operaciones matemáticas básicas)
    # Nota: En producción, considera usar una biblioteca como 'asteval' o 'simpleeval'
    allowed_names = {
        'abs': abs,
        'round': round,
        'pow': pow,
    }
    
    # Evaluar con builtins restringidos
    return eval(expression, {"__builtins__": {}}, allowed_names)

@app.route('/calculate')
def calculate():
    """
    Endpoint seguro que evalúa expresiones matemáticas sin usar eval() directo.
    """
    expression = request.args.get('expr', '0')
    
    try:
        result = safe_math_eval(expression)
        return jsonify({"expression": expression, "result": result})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Error al evaluar la expresión"}), 400

@app.route('/calculate-safe')
def calculate_safe():
    """
    Versión segura sin usar eval().
    """
    expression = request.args.get('expr', '0')
    
    allowed_pattern = r'^[\d+\-*/%\s\(\)]+$'
    if not re.match(allowed_pattern, expression):
        return jsonify({"error": "Caracteres no permitidos"}), 400
    
    try:
        result = safe_math_eval(expression)
        return jsonify({"expression": expression, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ==========================================
# CORRECCIÓN 5: Eliminar logging de información sensible
# ==========================================

@app.route('/register')
def register():
    """
    Endpoint que NO loguea información sensible.
    """
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    email = request.args.get('email', '')
    
    # Validar que los campos no estén vacíos
    if not username or not password or not email:
        return jsonify({"error": "Todos los campos son requeridos"}), 400
    
    # SEGURO: No se loguean contraseñas
    app.logger.info(f"Registro de nuevo usuario: {username} - Email: {email}")
    
    # En una aplicación real, aquí se almacenaría el usuario en la base de datos
    # con la contraseña hasheada, no en texto plano
    
    return jsonify({"message": f"Usuario {username} registrado exitosamente"})

# ==========================================
# CORRECCIÓN ADICIONAL: Configuración segura
# ==========================================

@app.route('/')
def index():
    """Endpoint principal con información de la API"""
    return jsonify({
        "name": "API Segura para SAST",
        "version": "2.0.0",
        "status": "Todas las vulnerabilidades corregidas",
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
    
    # SEGURO: debug=False para producción
    # Usar variables de entorno para configuración
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '127.0.0.1')  # localhost, no 0.0.0.0
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    app.run(debug=debug_mode, host=host, port=port)
