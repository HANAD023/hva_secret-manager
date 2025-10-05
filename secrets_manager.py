from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import csv
import os
from datetime import datetime
import secrets as secrets_module
from cryptography.fernet import Fernet
import base64



# Create blueprint
secrets = Blueprint('secrets', __name__, url_prefix='/secrets')

# CSV file path
CSV_FILE = 'secrets_data.csv'

# CSV headers
CSV_HEADERS = ['id', 'name', 'secret_value', 'description', 'category', 'created_at', 'updated_at', 'encrypted']

def init_csv():
    """Initialize CSV file if it doesn't exist"""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(CSV_HEADERS)

def generate_key_from_password(password):
    """Generate encryption key from password"""
    # Simple key derivation - in production use proper PBKDF2
    key = base64.urlsafe_b64encode(password.encode().ljust(32)[:32])
    return key

def encrypt_secret(secret_value, password):
    """Encrypt secret with password"""
    try:
        key = generate_key_from_password(password)
        f = Fernet(key)
        encrypted_value = f.encrypt(secret_value.encode())
        return base64.urlsafe_b64encode(encrypted_value).decode()
    except:
        return secret_value  # Return original if encryption fails

def decrypt_secret(encrypted_value, password):
    """Decrypt secret with password"""
    try:
        key = generate_key_from_password(password)
        f = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_value.encode())
        decrypted_value = f.decrypt(encrypted_bytes)
        return decrypted_value.decode()
    except:
        return "*** Decryption Failed ***"

def read_secrets():
    """Read all secrets from CSV"""
    init_csv()
    secrets_list = []
    try:
        with open(CSV_FILE, 'r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                secrets_list.append(row)
    except FileNotFoundError:
        pass
    return secrets_list

def write_secret(secret_data):
    """Write a new secret to CSV"""
    init_csv()
    with open(CSV_FILE, 'a', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=CSV_HEADERS)
        writer.writerow(secret_data)

def update_secret_in_csv(secret_id, updated_data):
    """Update existing secret in CSV"""
    secrets_list = read_secrets()
    updated = False
    
    for secret in secrets_list:
        if secret['id'] == secret_id:
            secret.update(updated_data)
            updated = True
            break
    
    if updated:
        # Rewrite entire CSV
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=CSV_HEADERS)
            writer.writeheader()
            writer.writerows(secrets_list)
    
    return updated

def delete_secret_from_csv(secret_id):
    """Delete secret from CSV"""
    secrets_list = read_secrets()
    original_count = len(secrets_list)
    secrets_list = [s for s in secrets_list if s['id'] != secret_id]
    
    if len(secrets_list) < original_count:
        # Rewrite CSV without deleted secret
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=CSV_HEADERS)
            writer.writeheader()
            writer.writerows(secrets_list)
        return True
    return False

@secrets.route('/')
def list():
    """List all secrets with pagination and filtering"""
    page = request.args.get('page', 1, type=int)
    filter_term = request.args.get('filter', '').strip()
    per_page = 10
    
    # Read all secrets
    all_secrets = read_secrets()
    
    # Apply filter if provided
    if filter_term:
        filtered_secrets = []
        for secret in all_secrets:
            if (filter_term.lower() in secret.get('name', '').lower() or 
                filter_term.lower() in secret.get('description', '').lower() or
                filter_term.lower() in secret.get('category', '').lower()):
                filtered_secrets.append(secret)
        all_secrets = filtered_secrets
    
    # Calculate pagination
    total_secrets = len(all_secrets)
    total_pages = (total_secrets + per_page - 1) // per_page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    secrets_page = all_secrets[start_idx:end_idx]
    
    # Decrypt secrets if password is in session
    if 'encryption_password' in session:
        password = session['encryption_password']
        for secret in secrets_page:
            if secret.get('encrypted') == 'True':
                secret['secret_value'] = decrypt_secret(secret['secret_value'], password)
    
    return render_template('secrets/list.html', 
                         secrets=secrets_page,
                         current_page=page,
                         total_pages=total_pages,
                         total_secrets=total_secrets,
                         filter_term=filter_term,
                         has_prev=page > 1,
                         has_next=page < total_pages,
                         prev_page=page - 1 if page > 1 else None,
                         next_page=page + 1 if page < total_pages else None)

@secrets.route('/add', methods=['GET', 'POST'])
def add():
    """Add new secret"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        secret_value = request.form.get('secret_value', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        use_encryption = request.form.get('use_encryption') == 'on'
        password = request.form.get('password', '').strip()
        
        # Validation
        if not name or not secret_value:
            flash('Naam en Secret waarde zijn verplicht.', 'error')
            return render_template('secrets/add.html')
        
        # Generate unique ID
        secret_id = secrets_module.token_hex(8)
        
        # Encrypt if requested
        encrypted = False
        if use_encryption and password:
            secret_value = encrypt_secret(secret_value, password)
            encrypted = True
            # Store password in session for decryption
            session['encryption_password'] = password
        
        # Create secret data
        secret_data = {
            'id': secret_id,
            'name': name,
            'secret_value': secret_value,
            'description': description,
            'category': category,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'encrypted': str(encrypted)
        }
        
        # Save to CSV
        write_secret(secret_data)
        flash('Secret succesvol toegevoegd!', 'success')
        return redirect(url_for('secrets.list'))
    
    return render_template('secrets/add.html')

@secrets.route('/edit/<secret_id>', methods=['GET', 'POST'])
def edit(secret_id):
    """Edit existing secret"""
    # Find secret
    all_secrets = read_secrets()
    secret = None
    for s in all_secrets:
        if s['id'] == secret_id:
            secret = s
            break
    
    if not secret:
        flash('Secret niet gevonden.', 'error')
        return redirect(url_for('secrets.list'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        secret_value = request.form.get('secret_value', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        use_encryption = request.form.get('use_encryption') == 'on'
        password = request.form.get('password', '').strip()
        
        # Validation
        if not name or not secret_value:
            flash('Naam en Secret waarde zijn verplicht.', 'error')
            return render_template('secrets/edit.html', secret=secret)
        
        # Handle encryption
        encrypted = False
        if use_encryption and password:
            secret_value = encrypt_secret(secret_value, password)
            encrypted = True
            session['encryption_password'] = password
        
        # Update data
        updated_data = {
            'name': name,
            'secret_value': secret_value,
            'description': description,
            'category': category,
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'encrypted': str(encrypted)
        }
        
        # Update in CSV
        if update_secret_in_csv(secret_id, updated_data):
            flash('Secret succesvol bijgewerkt!', 'success')
        else:
            flash('Fout bij het bijwerken van de secret.', 'error')
        
        return redirect(url_for('secrets.list'))
    
    # Decrypt for editing if encrypted
    if secret.get('encrypted') == 'True' and 'encryption_password' in session:
        secret['secret_value'] = decrypt_secret(secret['secret_value'], session['encryption_password'])
    
    return render_template('secrets/edit.html', secret=secret)

@secrets.route('/delete/<secret_id>', methods=['POST'])
def delete(secret_id):
    """Delete secret"""
    if delete_secret_from_csv(secret_id):
        flash('Secret succesvol verwijderd!', 'success')
    else:
        flash('Fout bij het verwijderen van de secret.', 'error')
    
    return redirect(url_for('secrets.list'))

@secrets.route('/set-password', methods=['POST'])
def set_password():
    """Set encryption password for session"""
    password = request.form.get('password', '').strip()
    if password:
        session['encryption_password'] = password
        flash('Wachtwoord ingesteld voor decryptie.', 'success')
    else:
        flash('Ongeldig wachtwoord.', 'error')
    
    return redirect(url_for('secrets.list'))