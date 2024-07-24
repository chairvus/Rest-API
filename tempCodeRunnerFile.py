
                cur.execute('''
                    UPDATE produk
                    SET is_publik = %s
                    WHERE id = %s RETURNING *;
                ''', (updated_produk['is_publik'], produk_id))
                produk = cur.fetchone()
                conn.commit()
                return jsonify(produk)
            else:
                return jsonify({'error': 'Anda hanya dapat mengubah status publik produk ini'}), 403

        elif request.method == 'DELETE':
            # Hanya user yang bisa menghapus produk
            if g.user['role'] != 'USER':
                return jsonify({'error': 'Admin tidak diizinkan untuk menghapus produk'}), 403

            produk_id = request.json['id']
            cur.execute('''
                SELECT p.id, p.id_umkm, u.id_user FROM produk p
                JOIN umkm u ON p.id_umkm = u.id
                WHERE p.id = %s;
            ''', (produk_id,))
            produk = cur.fetchone()

            if not produk or produk['id_user'] != g.user['id']:
                return jsonify({'error': 'Anda tidak diizinkan untuk menghapus produk ini'}), 403

            cur.execute('DELETE FROM produk WHERE id = %s RETURNING *;', (produk_id,))
            produk = cur.fetchone()
            conn.commit()
            return jsonify(produk)

        elif request.method == 'GET':
            cur.execute('SELECT * FROM produk;')
            produks = cur.fetchall()
            return jsonify(produks)

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
    cur = conn.cursor(cursor_factory=RealDictCursor)  # Gunakan RealDictCursor di sini
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