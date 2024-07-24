from flask import Flask, request, jsonify, g, make_response
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))

# Database connection
def get_db_connection():
    conn = psycopg2.connect(
        dbname='pencoba',
        user='postgres',
        password='artha',
        host='localhost'
    )
    return conn

# welcome
@app.route("/")
def root():
    return "Gacor Kang!!!!"

# Function to validate date
def validate_date(date_text):
    try:
        datetime.strptime(date_text, '%Y-%m-%d')
        return True
    except ValueError:
        return False

# Function to add a new user
def add_user(no_hp, password, role):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    hashed_password = generate_password_hash(password, method='sha256')

    cur.execute('''
        INSERT INTO "user" (no_hp, log, password, role)
        VALUES (%s, NOW(), %s, %s) RETURNING *;
    ''', (no_hp, hashed_password, role))
    user = cur.fetchone()
    conn.commit()

    token = jwt.encode({'id': user['id'], 'no_hp': no_hp, 'role': role}, app.config['SECRET_KEY'], algorithm='HS256')
    print(f"Generated token: {token}")

    cur.execute('''
        UPDATE "user" SET token = %s WHERE id = %s;
    ''', (token, user['id']))
    conn.commit()
    cur.close()
    conn.close()
    return user

# Function to authenticate a user with the provided no_hp and password
def authenticate_user(no_hp, password):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)  # Gunakan RealDictCursor di sini

    cur.execute('SELECT * FROM "user" WHERE no_hp = %s;', (no_hp,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        return user
    else:
        return None

# reset id user
def reset_user_ids():
    conn = None
    cur = None
    try:
        conn = psycopg2.connect(
            dbname="pencoba",
            user="postgres",
            password="artha",
            host="localhost",
            port=5432  # Port default PostgreSQL
        )
        cur = conn.cursor()

        # Step 1: Create a temporary table with new IDs
        cur.execute('''
            CREATE TEMP TABLE temp_user AS
            SELECT row_number() OVER () AS new_id, *
            FROM "user"
            ORDER BY id;
        ''')

        # Step 2: Remove primary key constraint temporarily with CASCADE
        cur.execute('ALTER TABLE "user" DROP CONSTRAINT user_pkey CASCADE;')

        # Step 3: Update original table with new IDs
        cur.execute('''
            UPDATE "user" u
            SET id = t.new_id
            FROM temp_user t
            WHERE u.id = t.id;
        ''')

        # Step 4: Restore primary key constraint
        cur.execute('ALTER TABLE "user" ADD PRIMARY KEY (id);')

        # Step 5: Reset sequence to follow the last used ID
        cur.execute('SELECT setval(\'user_id_seq\', (SELECT MAX(id) FROM "user"));')

        # Step 6: Re-add foreign key constraints that were dropped
        cur.execute('''
            ALTER TABLE umkm
            ADD CONSTRAINT umkm_id_user_fkey FOREIGN KEY (id_user) REFERENCES "user" (id);
        ''')

        conn.commit()
        print("ID reset successfully.")

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error: {e}")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# Run the function
reset_user_ids()

# Middleware for authentication
@app.before_request
def authenticate():
    exempt_routes = ['/register', '/login']
    if request.path in exempt_routes:
        return
    token = request.headers.get('Authorization')
    if token:
        if token.startswith("Bearer "):
            token = token[7:]  # Remove 'Bearer ' from the token
        try:
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(f"Decoded token: {decoded_token}")
            g.user = decoded_token
            g.user['id'] = decoded_token.get('id')  # Adding id to g.user
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'salah token!!: {str(e)}'}), 401
    else:
        return jsonify({'error': 'Hak akses tidak ada'}), 401

# Middleware for authorization
def admin_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if g.user['role'] != 'ADMIN':
            return jsonify({'error': 'Admin only'}), 403
        return f(*args, **kwargs)
    return decorator

def user_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if g.user['role'] != 'USER':
            return jsonify({'error': 'User only'}), 403
        return f(*args, **kwargs)
    return decorator

def user_or_admin_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if g.user['role'] not in ['USER', 'ADMIN']:
            return jsonify({'error': 'User or Admin only'}), 403
        return f(*args, **kwargs)
    return decorator

# Middleware to check if user is suspended
def user_suspended_check(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Ambil status suspended user dari database
        cur.execute('SELECT suspended FROM "user" WHERE id = %s;', (g.user['id'],))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({'error': 'User tidak ditemukan'}), 404
        
        if user['suspended']:
            return jsonify({'error': 'Akun Anda telah disuspend, operasi tidak diizinkan'}), 403

        return f(*args, **kwargs)
    return decorator

def get_missing_id(table_name, id_column):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    query = f"""
    WITH sequential_ids AS (
        SELECT generate_series(1, (SELECT MAX({id_column}) FROM {table_name})) AS seq_id
    )
    SELECT seq_id AS missing_id
    FROM sequential_ids
    LEFT JOIN {table_name} t ON sequential_ids.seq_id = t.{id_column}
    WHERE t.{id_column} IS NULL
    LIMIT 1;
    """
    cur.execute(query)
    result = cur.fetchone()
    cur.close()
    conn.close()
    if result:
        return result['missing_id']
    else:
        return None

# Middleware to check if UMKM is suspended for GET, POST, PUT, DELETE requests
def umkm_action_allowed(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        umkm_id = request.view_args.get('umkm_id') or request.json.get('id')
        if umkm_id:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT suspended, id_user, status_umkm FROM umkm WHERE id = %s;', (umkm_id,))
            umkm = cur.fetchone()
            cur.close()
            conn.close()

            if not umkm:
                return jsonify({'error': 'UMKM tidak ditemukan'}), 404

            if umkm['suspended'] and g.user['role'] != 'ADMIN':
                return jsonify({'error': f'UMKM telah di-suspend dengan id: {umkm_id}'}), 403
            elif not umkm['status_umkm'] and g.user['role'] != 'ADMIN' and g.user['id'] != umkm['id_user']:
                return jsonify({'error': 'UMKM tidak aktif, Anda tidak diizinkan untuk melakukan operasi ini'}), 403

        return f(*args, **kwargs)
    return decorator

# Middleware to check if UMKM is nonaktif for GET, PUT, DELETE requests
def umkm_nonaktif_allowed(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        user_id = request.view_args.get('user_id')
        if user_id:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT id, id_user, status_umkm FROM umkm WHERE id_user = %s AND status_umkm = FALSE;', (user_id,))
            umkms = cur.fetchall()
            cur.close()
            conn.close()

            if not umkms:
                return jsonify({'error': 'Tidak ada UMKM nonaktif ditemukan untuk user ini'}), 404

            if g.user['role'] != 'ADMIN' and g.user['id'] != int(user_id):
                return jsonify({'error': 'Anda tidak diizinkan untuk mengakses UMKM ini'}), 403

        return f(*args, **kwargs)
    return decorator

# Middleware to check if user is owner or admin
def admin_or_owner_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        user_id = request.view_args.get('user_id')
        if user_id:
            if g.user['role'] != 'ADMIN' and g.user['id'] != int(user_id):
                return jsonify({'error': 'Anda tidak diizinkan untuk mengakses atau mengubah UMKM ini'}), 403
        return f(*args, **kwargs)
    return decorator

# Endpoint to get all nonaktif UMKM
@app.route('/umkm/nonaktif', methods=['GET'])
@user_or_admin_required  # Ensure both user and admin can access
def get_nonaktif_umkm():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if g.user['role'] == 'ADMIN':
        cur.execute('SELECT * FROM umkm WHERE status_umkm = FALSE;')
    else:
        cur.execute('SELECT * FROM umkm WHERE status_umkm = FALSE AND id_user = %s;', (g.user['id'],))

    umkms = cur.fetchall()
    umkm_data = []

    for umkm in umkms:
        cur.execute('SELECT * FROM produk WHERE id_umkm = %s;', (umkm['id'],))
        products = cur.fetchall()
        umkm['products'] = products
        umkm_data.append(umkm)

    cur.close()
    conn.close()

    return jsonify(umkm_data)

# Endpoint to manage nonaktif UMKM
@app.route('/umkm/nonaktif/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@user_or_admin_required
@umkm_nonaktif_allowed
@admin_or_owner_required
def manage_nonaktif_umkm_by_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'GET':
        cur.execute('SELECT * FROM umkm WHERE id_user = %s AND status_umkm = FALSE;', (user_id,))
        umkms = cur.fetchall()
        if not umkms:
            cur.close()
            conn.close()
            return jsonify({'error': 'Tidak ada UMKM nonaktif ditemukan untuk user ini'}), 404

        umkm_data = []
        for umkm in umkms:
            cur.execute('SELECT * FROM produk WHERE id_umkm = %s;', (umkm['id'],))
            products = cur.fetchall()
            umkm['products'] = products
            umkm_data.append(umkm)
        
        cur.close()
        conn.close()
        return jsonify(umkm_data)

    elif request.method == 'PUT':
        updated_umkm = request.json
        umkm_id = updated_umkm['id']

        # Fetch the existing UMKM data
        cur.execute('SELECT * FROM umkm WHERE id = %s AND id_user = %s AND status_umkm = FALSE;', (umkm_id, user_id))
        existing_umkm = cur.fetchone()
        if not existing_umkm:
            cur.close()
            conn.close()
            return jsonify({'error': 'UMKM tidak ditemukan atau tidak nonaktif'}), 404

        cur.execute('''
            UPDATE umkm
            SET nama = %s, kategori = %s, deskripsi = %s, alamat = %s, no_kontak = %s, npwp = %s, jam_buka = %s, foto_umkm = %s, dokumen = %s, status_umkm = %s
            WHERE id = %s AND id_user = %s RETURNING *;
        ''', (
            updated_umkm['nama'], updated_umkm['kategori'], updated_umkm['deskripsi'], 
            updated_umkm['alamat'], updated_umkm['no_kontak'], updated_umkm['npwp'], updated_umkm['jam_buka'], 
            updated_umkm['foto_umkm'], updated_umkm['dokumen'], updated_umkm['status_umkm'], umkm_id, user_id
        ))
        umkm = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify(umkm)

    elif request.method == 'DELETE':
        umkm_id = request.json.get('id')

        # Pastikan user dapat menghapus UMKM miliknya sendiri yang nonaktif
        cur.execute('SELECT * FROM umkm WHERE id = %s AND id_user = %s AND status_umkm = FALSE;', (umkm_id, user_id))
        umkm = cur.fetchone()
        if not umkm:
            cur.close()
            conn.close()
            return jsonify({'error': 'UMKM tidak ditemukan atau tidak nonaktif'}), 404

        cur.execute('DELETE FROM umkm WHERE id = %s AND id_user = %s AND status_umkm = FALSE RETURNING *;', (umkm_id, user_id))
        deleted_umkm = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify(deleted_umkm)

# Tambahkan endpoint dashboard
@app.route('/admin/dashboard', methods=['GET'])
@admin_required
def admin_dashboard():
    return jsonify({"message": "Welcome to Admin lobby"})

@app.route('/user/dashboard', methods=['GET'])
@user_required
def user_dashboard():
    return jsonify({"message": "Welcome to User lobby"})

# Ubah nama endpoint suspend UMKM menjadi status
# Endpoint untuk mengubah status UMKM
@app.route('/umkm/status', methods=['PUT'])
@user_required
def change_umkm_status():
    umkm_id = request.json['id']
    status = request.json['status']
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Periksa apakah UMKM tersebut dimiliki oleh user yang sedang login
    cur.execute('SELECT id_user FROM umkm WHERE id = %s;', (umkm_id,))
    umkm = cur.fetchone()
    
    if not umkm:
        cur.close()
        conn.close()
        return jsonify({'error': 'UMKM tidak ditemukan'}), 404

    # Periksa apakah user yang sedang login adalah pemilik UMKM
    if umkm['id_user'] != g.user['id']:
        cur.close()
        conn.close()
        return jsonify({'error': 'Anda tidak diizinkan untuk mengubah status UMKM ini'}), 403

    # Lanjutkan untuk mengubah status UMKM
    cur.execute('''
        UPDATE umkm
        SET status_umkm = %s
        WHERE id = %s RETURNING *;
    ''', (status, umkm_id))
    umkm = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(umkm)

# Endpoint untuk mendapatkan UMKM dan produk milik user yang sedang login
@app.route('/umkm/user/<int:user_id>', methods=['GET'])
@user_or_admin_required  # Pastikan hanya user atau admin yang bisa mengakses endpoint ini
def get_umkm_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Query untuk mendapatkan semua UMKM berdasarkan user_id
        cur.execute("""
            SELECT id, nama, kategori, deskripsi, alamat, no_kontak, npwp, jam_buka, foto_umkm, dokumen, status_umkm, suspended
            FROM umkm
            WHERE id_user = %s
        """, (user_id,))
        umkms = cur.fetchall()

        result = []
        for umkm in umkms:
            if umkm['suspended']:
                result.append({
                    "pesan": f"data umkm dengan id: {umkm['id']} telah di suspend oleh admin!"
                })
            else:
                # Query untuk mendapatkan semua produk berdasarkan id_umkm
                cur.execute("""
                    SELECT id, id_umkm, kode_produk, nama_produk, deskripsi, harga, masa_berlaku, foto_produk, is_publik
                    FROM produk
                    WHERE id_umkm = %s
                """, (umkm['id'],))
                products = cur.fetchall()

                # Hanya tambahkan produk yang is_publik = True atau pemilik produk
                filtered_products = [
                    product for product in products
                    if product['is_publik'] or g.user['id'] == user_id
                ]

                umkm_data = {
                    "id_user": user_id,
                    "id": umkm['id'],
                    "nama": umkm['nama'],
                    "kategori": umkm['kategori'],
                    "deskripsi": umkm['deskripsi'],
                    "alamat": umkm['alamat'],
                    "no_kontak": umkm['no_kontak'],
                    "npwp": umkm['npwp'],
                    "jam_buka": umkm['jam_buka'],
                    "foto_umkm": umkm['foto_umkm'],
                    "dokumen": umkm['dokumen'],
                    "status_umkm": umkm['status_umkm'],
                    "suspended": umkm['suspended'],
                    "products": filtered_products
                }

                # Jika user bukan admin, hanya tampilkan UMKM yang aktif
                if g.user['role'] != 'ADMIN' and not umkm['status_umkm']:
                    continue
                
                result.append(umkm_data)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        cur.close()
        conn.close()

# Endpoint untuk mendapatkan semua UMKM dan produk untuk admin
@app.route('/umkm', methods=['GET'])
@admin_required
def get_all_umkm():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Get all UMKMs
    cur.execute('SELECT * FROM umkm;')
    umkms = cur.fetchall()

    # Get products for each UMKM
    umkm_data = []
    for umkm in umkms:
        cur.execute('SELECT * FROM produk WHERE id_umkm = %s;', (umkm['id'],))
        products = cur.fetchall()
        umkm['products'] = products
        umkm_data.append(umkm)

    cur.close()
    conn.close()

    return jsonify(umkm_data)

# Middleware to check if UMKM is suspended
def umkm_suspended_check(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        umkm_id = request.json.get('id_umkm') or request.view_args.get('umkm_id') or request.json.get('id')
        
        if umkm_id:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT suspended, id_user FROM umkm WHERE id = %s;', (umkm_id,))
            umkm = cur.fetchone()
            cur.close()
            conn.close()

            if not umkm:
                return jsonify({'error': 'UMKM tidak ditemukan'}), 404
            
            if umkm['suspended'] and g.user['role'] != 'ADMIN':
                return jsonify({'error': 'UMKM telah disuspend, operasi tidak diizinkan'}), 403

        return f(*args, **kwargs)
    return decorator

# Routes for UMKM
@app.route('/umkm', methods=['POST', 'PUT', 'DELETE'])
@user_or_admin_required
@umkm_action_allowed
@user_suspended_check  # Apply user suspended middleware
@umkm_suspended_check  # Apply UMKM suspended middleware
def manage_umkm():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        if request.method == 'POST':
            new_umkm = request.json

            # Ambil id_user dari request jika ada, jika tidak gunakan id user dari token terautentikasi
            id_user = new_umkm.get('id_user', g.user['id'])

            # Hanya admin yang boleh menambahkan data UMKM untuk user lain
            if g.user['role'] == 'ADMIN':
                if id_user == g.user['id']:
                    return jsonify({'error': 'Anda adalah admin, gak boleh yaa....'}), 403
                elif id_user != g.user['id']:
                    cur.execute('SELECT role FROM "user" WHERE id = %s', (id_user,))
                    target_user = cur.fetchone()
                    if target_user is None:
                        return jsonify({'error': 'User tidak ditemukan'}), 404
                    if target_user['role'] == 'ADMIN':
                        return jsonify({'error': 'Admin tidak dapat menambahkan data UMKM untuk admin lain'}), 403
            else:
                # User biasa hanya bisa menambahkan UMKM untuk dirinya sendiri
                if id_user != g.user['id']:
                    return jsonify({'error': 'Anda tidak diizinkan untuk menambahkan data UMKM untuk user lain'}), 403

            # Log untuk debugging
            print(f"Creating UMKM for user_id: {id_user}")

            missing_id = get_missing_id('umkm', 'id')
            if missing_id:
                umkm_id = missing_id
            else:
                cur.execute('SELECT COALESCE(MAX(id), 0) + 1 AS new_id FROM umkm')
                result = cur.fetchone()
                print(f"Max ID query result: {result}")  # Tambahkan logging di sini
                if result and 'new_id' in result:
                    umkm_id = result['new_id']
                else:
                    return jsonify({'error': 'Gagal mendapatkan ID baru untuk UMKM'}), 500

            # Log untuk debugging
            print(f"New UMKM id: {umkm_id}")

            cur.execute('''
                INSERT INTO umkm (id, id_user, nama, kategori, deskripsi, alamat, no_kontak, npwp, jam_buka, foto_umkm, dokumen, status_umkm)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *;
            ''', (
                umkm_id, id_user, new_umkm['nama'], new_umkm['kategori'], new_umkm['deskripsi'], 
                new_umkm['alamat'], new_umkm['no_kontak'], new_umkm['npwp'], new_umkm['jam_buka'], 
                new_umkm['foto_umkm'], new_umkm['dokumen'], new_umkm['status_umkm']
            ))
            umkm = cur.fetchone()
            conn.commit()

            # Log untuk debugging
            print(f"Inserted UMKM: {umkm}")

            if not umkm:
                return jsonify({'error': 'Gagal menyimpan UMKM baru'}), 500

            cur.close()
            conn.close()
            return jsonify(umkm), 201

        elif request.method == 'PUT':
            updated_umkm = request.json
            umkm_id = updated_umkm['id']

            # Fetch the existing UMKM data
            cur.execute('SELECT * FROM umkm WHERE id = %s;', (umkm_id,))
            existing_umkm = cur.fetchone()
            if not existing_umkm:
                cur.close()
                conn.close()
                return jsonify({'error': 'UMKM tidak ditemukan'}), 404

            cur.execute('''
                UPDATE umkm
                SET nama = %s, kategori = %s, deskripsi = %s, alamat = %s, no_kontak = %s, npwp = %s, jam_buka = %s, foto_umkm = %s, dokumen = %s, status_umkm = %s
                WHERE id = %s RETURNING *;
            ''', (
                updated_umkm['nama'], updated_umkm['kategori'], updated_umkm['deskripsi'], 
                updated_umkm['alamat'], updated_umkm['no_kontak'], updated_umkm['npwp'], updated_umkm['jam_buka'], 
                updated_umkm['foto_umkm'], updated_umkm['dokumen'], updated_umkm['status_umkm'], umkm_id
            ))
            umkm = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()
            return jsonify(umkm)

        elif request.method == 'DELETE':
            umkm_id = request.json['id']
            
            # Fetch the existing UMKM data
            cur.execute('SELECT * FROM umkm WHERE id = %s;', (umkm_id,))
            existing_umkm = cur.fetchone()
            if not existing_umkm:
                cur.close()
                conn.close()
                return jsonify({'error': 'UMKM tidak ditemukan'}), 404

            # Check if the user is allowed to delete this UMKM
            if g.user['role'] != 'ADMIN' and existing_umkm['id_user'] != g.user['id']:
                cur.close()
                conn.close()
                return jsonify({'error': 'Anda tidak diizinkan untuk menghapus UMKM ini'}), 403

            cur.execute('DELETE FROM umkm WHERE id = %s RETURNING *;', (umkm_id,))
            umkm = cur.fetchone()
            conn.commit()
            cur.close()
            conn.close()
            return jsonify(umkm)

    except Exception as e:
        # Log exception untuk debugging
        print(f"Exception: {e}")
        return jsonify({"error": str(e)})
    finally:
        cur.close()
        conn.close()

# Routes for Produk
@app.route('/produk', methods=['GET', 'POST', 'PUT', 'DELETE'])
@user_or_admin_required
def manage_produk():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        if request.method == 'POST':
            new_produk = request.json
            id_umkm = new_produk.get('id_umkm')
            kode_produk = new_produk.get('kode_produk')
            nama_produk = new_produk.get('nama_produk')
            deskripsi = new_produk.get('deskripsi')
            harga = new_produk.get('harga')
            masa_berlaku = new_produk.get('masa_berlaku')
            foto_produk = new_produk.get('foto_produk')
            is_publik = new_produk.get('is_publik')

            if isinstance(harga, (int, float)):
                harga = f'{harga:.2f}'

            cur.execute('''
                INSERT INTO produk (id_umkm, kode_produk, nama_produk, deskripsi, harga, masa_berlaku, foto_produk, is_publik)
                VALUES (%s, %s, %s, %s, %s::money, %s, %s, %s) RETURNING *;
            ''', (id_umkm, kode_produk, nama_produk, deskripsi, harga, masa_berlaku, foto_produk, is_publik))
            produk = cur.fetchone()
            conn.commit()
            return jsonify(produk), 201

        elif request.method == 'PUT':
            updated_produk = request.json
            produk_id = updated_produk.get('id')

            if not produk_id:
                return jsonify({'error': 'ID produk diperlukan!'}), 400

            # Verifikasi kepemilikan produk jika bukan admin
            if g.user['role'] != 'ADMIN':
                cur.execute('''
                    SELECT p.id, p.id_umkm, u.id_user FROM produk p
                    JOIN umkm u ON p.id_umkm = u.id
                    WHERE p.id = %s;
                ''', (produk_id,))
                produk = cur.fetchone()

                if not produk or produk['id_user'] != g.user['id']:
                    return jsonify({'error': 'Anda tidak diizinkan untuk memperbarui produk ini'}), 403

            # Pastikan harga dalam format string yang sesuai dengan tipe money
            harga = updated_produk['harga']
            if isinstance(harga, (int, float)):
                harga = f'{harga:.2f}'

            # Perbarui data produk
            cur.execute('''
                UPDATE produk
                SET id_umkm = %s, kode_produk = %s, nama_produk = %s, deskripsi = %s, harga = %s::money, masa_berlaku = %s, foto_produk = %s, is_publik = %s
                WHERE id = %s RETURNING *;
            ''', (
                updated_produk['id_umkm'], updated_produk['kode_produk'], updated_produk['nama_produk'],
                updated_produk['deskripsi'], harga, updated_produk['masa_berlaku'],
                updated_produk['foto_produk'], updated_produk['is_publik'], produk_id
            ))
            produk = cur.fetchone()
            conn.commit()
            return jsonify(produk)

        elif request.method == 'DELETE':
            produk_id = request.json.get('id')

            if not produk_id:
                return jsonify({'error': 'ID produk diperlukan!'}), 400

            cur.execute('''
                SELECT p.id, p.id_umkm, u.id_user FROM produk p
                JOIN umkm u ON p.id_umkm = u.id
                WHERE p.id = %s;
            ''', (produk_id,))
            produk = cur.fetchone()

            if not produk:
                return jsonify({'error': 'Produk tidak ditemukan'}), 404

            if g.user['role'] != 'ADMIN' and produk['id_user'] != g.user['id']:
                return jsonify({'error': 'Anda tidak diizinkan untuk menghapus produk ini'}), 403

            cur.execute('DELETE FROM produk WHERE id = %s RETURNING *;', (produk_id,))
            deleted_produk = cur.fetchone()
            conn.commit()

            # Panggil fungsi untuk mengatur ulang id
            cur.execute('''
                DO $$
                DECLARE
                    cur_id INTEGER := 1;
                    rec RECORD;
                BEGIN
                    FOR rec IN SELECT id FROM produk ORDER BY id ASC LOOP
                        UPDATE produk SET id = cur_id WHERE id = rec.id;
                        cur_id := cur_id + 1;
                    END LOOP;
                END $$;
            ''')
            conn.commit()

            return jsonify(deleted_produk)

        elif request.method == 'GET':
            cur.execute('SELECT * FROM produk;')
            produks = cur.fetchall()
            return jsonify(produks)

        return jsonify({'error': 'Metode tidak dikenal'}), 405

    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        cur.close()
        conn.close()

# Routes for User registration and login
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    no_hp = data['no_hp']
    password = data['password']
    role = data.get('role', 'USER')  # Default role is USER

    # Ensure no_hp and password are provided
    if not no_hp or not password:
        return jsonify({'error': 'Missing phone number or password'}), 400

    try:
        user = add_user(no_hp, password, role)
        return jsonify({'token': user['token'], 'log': user['log']}), 201
    except Exception as e:
        import traceback
        print(traceback.format_exc())  # Cetak traceback untuk debugging
        return jsonify({'error': str(e)}), 500  

@app.route('/login', methods=['POST'])
def login():
    data = request.json

    no_hp = data.get('no_hp')
    password = data.get('password')

    if not no_hp or not password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = authenticate_user(no_hp, password)

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    token = jwt.encode({'id': user['id'], 'no_hp': user['no_hp'], 'role': user['role']}, app.config['SECRET_KEY'], algorithm='HS256')

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)  # Gunakan RealDictCursor di sini
    cur.execute('UPDATE "user" SET token = %s, log = NOW() WHERE id = %s RETURNING log;', (token, user['id']))
    log_timestamp = cur.fetchone()['log']
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'token': token, 'log': log_timestamp})

# Routes for managing users
@app.route('/user', methods=['GET', 'POST', 'PUT', 'DELETE'])
@user_or_admin_required
def manage_user():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        new_user = request.json
        cur.execute('''
            INSERT INTO "user" (no_hp, token, log, password, role)
            VALUES (%s, %s, %s, %s, %s) RETURNING *;
        ''', (
            new_user['no_hp'], new_user['token'], new_user['log'], new_user['password'], new_user['role']
        ))
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify(user), 201

    elif request.method == 'GET':
        if g.user['role'] == 'ADMIN':
            cur.execute('SELECT * FROM "user";')
            users = cur.fetchall()
        else:
            cur.execute('SELECT * FROM "user" WHERE id = %s;', (g.user['id'],))
            users = cur.fetchall()

        cur.close()
        conn.close()
        return jsonify(users)

    elif request.method == 'PUT':
        updated_user = request.json
        user_id = updated_user.get('id')

        # Hanya izinkan pengguna untuk memperbarui data mereka sendiri atau jika mereka adalah admin
        if g.user['role'] != 'ADMIN' and g.user['id'] != user_id:
            return jsonify({'error': 'Kamu tidak punya izin untuk mengubah data ini!'}), 403

        no_hp = updated_user.get('no_hp')
        password = updated_user.get('password')
        role = updated_user.get('role')

        # Validasi panjang password
        if password and len(password) != 6:
            return jsonify({'error': 'Password harus 6 digit'}), 400

        # Perbarui data pengguna
        cur.execute('''
            UPDATE "user"
            SET no_hp = %s, password = %s, role = %s
            WHERE id = %s RETURNING *;
        ''', (
            no_hp, password, role, user_id
        ))
        user = cur.fetchone()
        conn.commit()

        # Perbarui token JWT jika role berubah
        if role:
            token = jwt.encode({'id': user['id'], 'no_hp': user['no_hp'], 'role': role}, app.config['SECRET_KEY'], algorithm='HS256')
            cur.execute('UPDATE "user" SET token = %s WHERE id = %s;', (token, user['id']))
            conn.commit()
            user['token'] = token

        cur.close()
        conn.close()
        return jsonify(user)

    elif request.method == 'DELETE':
        user_id = request.json['id']
        cur.execute('DELETE FROM "user" WHERE id = %s RETURNING *;', (user_id,))
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify(user)

# Routes for edit role
@app.route('/user/role', methods=['PUT'])
@user_or_admin_required
def change_user_role():
    data = request.json
    user_id = data.get('id')
    new_role = data.get('role')

    if not user_id or not new_role:
        return jsonify({'error': 'ID dan role baru diperlukan!'}), 400

    if new_role not in ['USER', 'ADMIN']:
        return jsonify({'error': 'Role tidak valid!'}), 400

    # Hanya admin yang dapat mengubah role pengguna lain
    if g.user['role'] != 'ADMIN' and g.user['id'] != user_id:
        return jsonify({'error': 'Kamu tidak punya izin untuk mengubah role ini!'}), 403

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute('UPDATE "user" SET role = %s WHERE id = %s RETURNING *;', (new_role, user_id))
    user = cur.fetchone()
    conn.commit()

    # Perbarui token JWT
    token = jwt.encode({'id': user['id'], 'no_hp': user['no_hp'], 'role': new_role}, app.config['SECRET_KEY'], algorithm='HS256')

    cur.execute('UPDATE "user" SET token = %s WHERE id = %s;', (token, user['id']))
    conn.commit()

    cur.close()
    conn.close()

    return jsonify({'message': 'Role berhasil diubah!', 'token': token})

# Routes for suspending/unsuspending users
@app.route('/user/suspend', methods=['PUT'])
@admin_required
def suspend_user():
    user_id = request.json['id']
    suspend_status = request.json['suspend']
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Pastikan kita hanya memperbarui kolom suspended
    cur.execute('''
        UPDATE "user"
        SET suspended = %s
        WHERE id = %s RETURNING id, no_hp, token, log, password, role, suspended;
    ''', (suspend_status, user_id))
    
    user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    # Pastikan nilai no_hp dan password tidak null
    if not user['no_hp'] or not user['password']:
        return jsonify({'error': 'Error updating suspended status'}), 500
    
    return jsonify(user)

# Routes for suspending/unsuspending UMKM
@app.route('/umkm/suspend', methods=['PUT'])
@admin_required
def suspend_umkm():
    data = request.json
    if not data or 'id' not in data or 'suspend' not in data:
        return jsonify({'error': 'Kekurangan data: id dan suspend status diperlukan!'}), 400

    umkm_id = data['id']
    suspend_status = data['suspend']

    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500

    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT id_user FROM umkm WHERE id = %s;', (umkm_id,))
    umkm = cur.fetchone()

    if not umkm:
        cur.close()
        conn.close()
        return jsonify({'error': 'UMKM tidak ditemukan'}), 404

    cur.execute('''
        UPDATE umkm
        SET suspended = %s
        WHERE id = %s RETURNING *;
    ''', (suspend_status, umkm_id))
    umkm = cur.fetchone()

    if suspend_status:
        cur.execute('''
            UPDATE produk
            SET suspended = %s
            WHERE id_umkm = %s;
        ''', (suspend_status, umkm_id))

    conn.commit()
    cur.close()
    conn.close()
    return jsonify(umkm)

# Routes for publishing/unpublishing products
@app.route('/produk/publish', methods=['PUT'])
@user_or_admin_required
def publish_produk():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        data = request.json
        produk_id = data['id']
        is_publik = data['is_publik']

        # Verifikasi kepemilikan produk jika bukan admin
        if g.user['role'] != 'ADMIN':
            cur.execute('''
                SELECT p.id, p.id_umkm, u.id_user FROM produk p
                JOIN umkm u ON p.id_umkm = u.id
                WHERE p.id = %s;
            ''', (produk_id,))
            produk = cur.fetchone()

            if not produk or produk['id_user'] != g.user['id']:
                return jsonify({'error': 'Anda tidak diizinkan untuk mengubah status publik produk ini'}), 403

        cur.execute('''
            UPDATE produk
            SET is_publik = %s
            WHERE id = %s RETURNING *;
        ''', (is_publik, produk_id))
        produk = cur.fetchone()
        conn.commit()
        return jsonify(produk)

    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        cur.close()
        conn.close()

# Admin @ user
@app.route('/admin/add_user', methods=['POST'])
@admin_required
def admin_add_user():
    new_user = request.json
    no_hp = new_user['no_hp']
    password = new_user['password']
    role = new_user.get('role', 'USER')  # Default role is USER

    if len(password) < 6:  # Minimal length for password
        return jsonify({'error': 'Password harus minimal 6 karakter'}), 400

    try:
        user = add_user(no_hp, password, role)
        return jsonify({'token': user['token'], 'log': user['log']}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Admin nambah user
def add_user(no_hp, password, role='USER'):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    hashed_password = generate_password_hash(password, method='sha256')

    # Dapatkan id berikutnya yang tersedia
    cur.execute('SELECT get_next_user_id();')
    next_user_id = cur.fetchone()['get_next_user_id']

    cur.execute('''
        INSERT INTO "user" (id, no_hp, log, password, role)
        VALUES (%s, %s, NOW(), %s, %s) RETURNING *;
    ''', (next_user_id, no_hp, hashed_password, role))
    user = cur.fetchone()
    conn.commit()

    token = jwt.encode({'id': user['id'], 'no_hp': no_hp, 'role': role}, app.config['SECRET_KEY'], algorithm='HS256')
    print(f"Generated token: {token}")

    cur.execute('''
        UPDATE "user" SET token = %s WHERE id = %s RETURNING log;
    ''', (token, user['id']))
    user['log'] = cur.fetchone()['log']
    conn.commit()
    cur.close()
    conn.close()
    user['token'] = token
    return user

if __name__ == '__main__':
    app.run(debug=True)