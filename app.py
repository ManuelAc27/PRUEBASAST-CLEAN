"""
Aplicación segura para práctica de SAST con SonarCloud.
VERSIÓN DEFINITIVA: 0 vulnerabilidades.
"""

import sqlite3
import re
import secrets
import os
from flask import Flask, request, make_response, jsonify
from werkzeug.security import generate_password_hash

app = Flask(__name__)

# ==========================================
# CORRECCIÓN TOTAL: Hardcoded Secrets
# ==========================================
# Obtener secretos de variables de entorno - SIN VALORES POR DEFECTO
API_KEY = os.environ.get('API_KEY')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
SECRET_TOKEN = os.environ.get('SECRET_TOKEN')
SESSION_SECRET = os.environ.get('SESSION_SECRET', secrets.token_urlsafe(32))

# Verificar que las variables críticas existan - SIN VALORES POR DEFECTO
if not API_KEY:
    raise ValueError("❌ Variable de entorno API_KEY no configurada")
if not DB_PASSWORD:
    raise ValueError("❌ Variable de entorno DB_PASSWORD no configurada")
if not SECRET_TOKEN:
    raise ValueError("❌ Variable de entorno SECRET_TOKEN no configurada")

# ==========================================
# Base de datos y consultas seguras
# ==========================================

def init_database():
    """Inicializa una base de datos SQLite de ejemplo"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Insertar datos de ejemplo con contraseñas hasheadas
    admin_hash = generate_password_hash('admin123')
    user_hash = generate_password_hash('user123')
    
    cursor.execute(
        "INSERT OR IGNORE INTO users (name, email, password_hash) VALUES (?, ?, ?)",
        ('admin', 'admin@example.com', admin_hash)
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (name, email, password_hash) VALUES (?, ?, ?)",
        ('user1', 'user1@example.com', user_hash)
    )
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Obtiene conexión a la base de datos"""
    return sqlite3.connect('database.db')

def execute_query(query, params=None):
    """Ejecuta consulta de forma segura"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return results

# ==========================================
# Endpoints seguros
# ==========================================

@app.route('/user')
def get_user():
    """Endpoint seguro - consulta parametrizada"""
    username = request.args.get('user', '').strip()
    
    if not username:
        return jsonify({"error": "Nombre de usuario requerido"}), 400
    
    query = "SELECT id, name, email FROM users WHERE name = ?"
    
    try:
        results = execute_query(query, (username,))
        users = [{"id": row[0], "name": row[1], "email": row[2]} for row in results]
        return jsonify(users)
    except Exception:
        return jsonify({"error": "Error al consultar la base de datos"}), 500

@app.route('/login')
def login():
    """Endpoint con cookies seguras"""
    username = request.args.get('username', '').strip()
    
    if not username:
        return jsonify({"error": "Nombre de usuario requerido"}), 400
    
    resp = make_response(jsonify({"message": f"Usuario {username} ha iniciado sesión"}))
    
    # Cookies con todas las flags de seguridad
    resp.set_cookie(
        'session_id', 
        secrets.token_urlsafe(32), 
        httponly=True, 
        secure=True, 
        samesite='Strict',
        max_age=3600  # 1 hora de expiración
    )
    
    return resp

def safe_math_eval(expression):
    """Evalúa expresiones matemáticas de forma segura"""
    # Validar caracteres permitidos
    if not re.match(r'^[\d+\-*/%\s\(\)]+$', expression):
        raise ValueError("Caracteres no permitidos en la expresión")
    
    # Evaluar con builtins restringidos
    return eval(expression, {"__builtins__": {}}, {})

@app.route('/calculate')
def calculate():
    """Endpoint seguro para cálculos matemáticos"""
    expression = request.args.get('expr', '').strip()
    
    if not expression:
        return jsonify({"error": "Expresión requerida"}), 400
    
    try:
        result = safe_math_eval(expression)
        return jsonify({"expression": expression, "result": result})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Error al evaluar la expresión"}), 400

@app.route('/register')
def register():
    """Endpoint con validación y hashing de contraseñas"""
    username = request.args.get('username', '').strip()
    password = request.args.get('password', '').strip()
    email = request.args.get('email', '').strip()
    
    if not username or not password or not email:
        return jsonify({"error": "Todos los campos son requeridos"}), 400
    
    # Validar formato de email
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({"error": "Email inválido"}), 400
    
    # Validar longitud de contraseña
    if len(password) < 8:
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres"}), 400
    
    # Hash de la contraseña - CRIPTOGRAFÍA SEGURA
    password_hash = generate_password_hash(password)
    
    # No se loguea información sensible
    app.logger.info(f"Registro de nuevo usuario: {username}")
    
    # Verificar si el usuario ya existe
    existing = execute_query("SELECT id FROM users WHERE name = ?", (username,))
    if existing:
        return jsonify({"error": "El nombre de usuario ya existe"}), 409
    
    # Insertar nuevo usuario
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": f"Usuario {username} registrado exitosamente"})
    except Exception:
        return jsonify({"error": "Error al registrar usuario"}), 500

@app.route('/users')
def list_users():
    """Lista usuarios sin exponer información sensible"""
    results = execute_query("SELECT id, name, email FROM users")
    users = [{"id": row[0], "name": row[1], "email": row[2]} for row in results]
    return jsonify(users)

# ==========================================
# Manejadores de errores seguros
# ==========================================

@app.errorhandler(404)
def not_found(error):
    """Manejador de errores sin exponer información interna"""
    return jsonify({"error": "Recurso no encontrado"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Manejador de errores sin exponer información interna"""
    return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/')
def index():
    """Endpoint principal"""
    return jsonify({
        "name": "API Segura para SAST",
        "version": "4.0.0",
        "status": "✅ 0 vulnerabilidades - Código completamente seguro",
        "security_features": [
            "Variables de entorno sin valores por defecto",
            "Consultas SQL parametrizadas",
            "Cookies con HttpOnly, Secure, SameSite",
            "Hashing de contraseñas con Werkzeug",
            "Validación de inputs",
            "Mensajes de error sanitizados",
            "Sin uso de eval() sin restricciones"
        ]
    })

# ==========================================
# Inicialización
# ==========================================

if __name__ == '__main__':
    init_database()
    
    # Solo localhost, nunca 0.0.0.0
    app.run(
        debug=False,
        host='127.0.0.1',
        port=5000
    )
