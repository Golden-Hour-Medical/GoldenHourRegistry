from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import requests
import json
from functools import wraps
import os
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import BadRequest
from flask import Response

app = Flask(__name__, template_folder='templates')

# Configure secret key for session management
app.secret_key = 'your_secret_key_here'  # Replace with a secure random key in production

# API Base URL
API_URL = "http://127.0.0.1:8000"  # Replace with your FastAPI server's URL

# Configure upload folder for firmware binaries (we'll use this for temporary storage)
UPLOAD_FOLDER = 'uploads'  # Create this folder in your project
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'bin'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Decorator to ensure that the user is logged in before accessing certain routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            flash('You need to be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = {
            'username': request.form['username'],
            'email': request.form['email'],
            'phone_number': request.form['phone_number'],
            'password': request.form['password'],
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'address': request.form['address']
        }
        try:
            response = requests.post(f'{API_URL}/users/register', json=data)
            if response.status_code == 200:
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                error_detail = response.json().get('detail', 'Registration failed')
                flash(f'Registration failed: {error_detail}', 'danger')
        except requests.exceptions.RequestException as e:
            flash(f'An error occurred: {e}', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = {
            'username': request.form['username'],
            'password': request.form['password']
        }
        try:
            response = requests.post(f'{API_URL}/token', data=data)
            if response.status_code == 200:
                token = response.json().get('access_token')
                if token:
                    session['access_token'] = token  # Store token in session
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Login failed: No token received.', 'danger')
            else:
                error_detail = response.json().get('detail', 'Login failed')
                flash(f'Login failed: {error_detail}', 'danger')
        except requests.exceptions.RequestException as e:
            flash(f'An error occurred: {e}', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    try:
        response = requests.get(f'{API_URL}/users/me', headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            # Fetch active firmwares
            firmware_response = requests.get(f'{API_URL}/firmware', headers=headers)
            if firmware_response.status_code == 200:
                firmware_data = firmware_response.json()
            else:
                firmware_data = []
            return render_template('dashboard.html', user_data=user_data, firmware_data=firmware_data)
        elif response.status_code == 401:
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        else:
            flash('Failed to retrieve user data.', 'danger')
            return redirect(url_for('login'))
    except requests.exceptions.RequestException as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('login'))

@app.route('/create-organization', methods=['GET', 'POST'])
@login_required
def create_organization():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    if request.method == 'POST':
        data = {
            'name': request.form['name'],
            'address': request.form['address']
        }
        try:
            response = requests.post(f'{API_URL}/organizations', json=data, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                flash('Organization created successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                error_detail = response.json().get('detail', 'Organization creation failed')
                flash(f'Organization creation failed: {error_detail}', 'danger')
        except requests.exceptions.RequestException as e:
            flash(f'An error occurred: {e}', 'danger')
    return render_template('create_organization.html')

@app.route('/create-device', methods=['GET', 'POST'])
@login_required
def create_device():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    # Fetch device group options (no need to fetch firmware options now)
    try:
        device_group_response = requests.get(f'{API_URL}/device-groups', headers=headers)
        if device_group_response.status_code == 200:
            device_group_options = device_group_response.json()
            print(device_group_options)
        else:
            device_group_options = []  # No groups found, empty list
    except requests.exceptions.RequestException as e:
        device_group_options = []  # Error, empty list
        flash(f'Error fetching data: {e}', 'danger')

    if request.method == 'POST':
        data = {
            'mac_address': request.form['mac_address'],
            'serial_number': request.form['serial_number'],
            'human_readable_name': request.form['human_readable_name'],
            'auto_update_enabled': request.form.get('auto_update_enabled') == 'on',  # Optional
            'device_group_id': request.form.get('device_group_id')  # Group ID from dropdown
        }
        print(data)
        try:
            response = requests.post(f'{API_URL}/devices', json=data, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                flash('Device created successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                error_detail = response.json().get('detail', 'Device creation failed')
                flash(f'Device creation failed: {error_detail}', 'danger')
        except requests.exceptions.RequestException as e:
            flash(f'An error occurred: {e}', 'danger')
    return render_template(
        'create_device.html', 
        device_group_options=device_group_options
    )

@app.route('/create-firmware', methods=['GET', 'POST'])
@login_required
def create_firmware():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    if request.method == 'POST':
        version = request.form['version']
        deployment_stage = request.form['deployment_stage']
        file = request.files.get('file')

        if file and allowed_file(file.filename):
            # Read the binary file data
            file_data = file.read()

            data = {
                'version': version,
                'deployment_stage': deployment_stage,
            }
            files = {'file': (file.filename, file_data, 'application/octet-stream')}

            try:
                response = requests.post(
                    f'{API_URL}/firmware/upload', 
                    data=data, 
                    files=files, 
                    headers=headers
                )
                if response.status_code == 200 or response.status_code == 201:
                    flash('Firmware created successfully!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    error_detail = response.json().get('detail', 'Firmware creation failed')
                    flash(f'Firmware creation failed: {error_detail}', 'danger')
            except requests.exceptions.RequestException as e:
                flash(f'An error occurred: {e}', 'danger')
        else:
            flash('Invalid file type. Only .bin files allowed.', 'danger')
    return render_template('create_firmware.html')

@app.route('/edit-firmware/<firmware_id>', methods=['GET', 'POST'])
@login_required
def edit_firmware(firmware_id):
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}
    
    # Fetch existing firmware data
    try:
        response = requests.get(f'{API_URL}/firmware/{firmware_id}', headers=headers)
        response.raise_for_status()
        firmware_data = response.json()
    except requests.exceptions.RequestException as e:
        flash(f'Failed to retrieve firmware data: {e}', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Get updated values from the form
        new_version = request.form.get('version', firmware_data['version'])
        new_file_path = request.form.get('file_path', firmware_data['file_path'])
        new_deployment_stage = request.form.get('deployment_stage', firmware_data['deployment_stage'])
        
        # Prepare the data payload
        data = {
            'version': new_version,
            'file_path': new_file_path,
            'deployment_stage': new_deployment_stage
        }
        
        # Send the PUT request to update the firmware
        try:
            response = requests.put(f'{API_URL}/firmware/{firmware_id}', json=data, headers=headers)
            if response.status_code == 200:
                flash('Firmware updated successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                error_detail = response.json().get('detail', 'Firmware update failed')
                flash(f'Firmware update failed: {error_detail}', 'danger')
        except requests.exceptions.RequestException as e:
            flash(f'An error occurred while updating firmware: {e}', 'danger')

    # Render the edit form with existing firmware data
    return render_template('edit_firmware.html', firmware_data=firmware_data)

@app.route('/logout')
@login_required
def logout():
    session.pop('access_token', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Optional: Add flash message display in templates
@app.context_processor
def inject_flashes():
    return dict(get_flashed_messages=get_flashed_messages)

def get_flashed_messages():
    return list(session.get('_flashes', []))

# ====================  New Endpoints (Proxy to FastAPI) ==================== 

@app.route('/users/me', methods=['GET'])
@login_required
def get_user_me():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    try:
        response = requests.get(f'{API_URL}/users/me', headers=headers)
        return response.json()
    except requests.exceptions.RequestException as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/organizations', methods=['GET'])
@login_required
def get_organizations():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    try:
        response = requests.get(f'{API_URL}/organizations', headers=headers)
        return response.json()
    except requests.exceptions.RequestException as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/devices', methods=['GET'])
@login_required
def get_devices():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    try:
        response = requests.get(f'{API_URL}/devices', headers=headers)
        print(response.json())
        return response.json()
    except requests.exceptions.RequestException as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('dashboard'))

# ====================  Firmware Binary Handling ==================== 
@app.route('/firmware/<version>/<filename>')
def get_firmware_binary(version, filename):
    # Forward the request to the FastAPI server
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}
    try:
        response = requests.get(f'{API_URL}/firmware/{version}/{filename}', headers=headers)
        # Check if file was found on the server
        if response.status_code == 200:
            return response.content, response.status_code, response.headers
        else:
            return 'Firmware file not found', 404
    except requests.exceptions.RequestException as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/firmware')
@login_required
def get_firmwares():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    try:
        response = requests.get(f'{API_URL}/firmware', headers=headers)
        if response.status_code == 200:
            print(response.json())
            return response.json()
        else:
            return 'Firmware data not found', 404
    except requests.exceptions.RequestException as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('dashboard'))

# ====================  Open Tourniquet Page ==================== 
@app.route('/autotq/<device_id>')
@login_required
def autotq_page(device_id):
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    try:
        # Fetch device details
        device_response = requests.get(f'{API_URL}/devices/{device_id}', headers=headers)
        if device_response.status_code == 200:
            device_data = device_response.json()
            return render_template('autotq.html', device_data=device_data)
        else:
            flash('Failed to retrieve device details.', 'danger')
            return redirect(url_for('dashboard'))
    except requests.exceptions.RequestException as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('dashboard'))
    
@app.route('/device-groups', methods=['GET', 'POST'])
@login_required
def device_groups():
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}
    if request.method == 'POST':
        name = request.form['name'] 
        firmware_update_priority = request.form['firmware_update_priority']
        data = {
            'name': name,
            'firmware_update_priority': firmware_update_priority
        }
        try:
            response = requests.post(f'{API_URL}/device-groups', json=data, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                flash('Device group created successfully!', 'success')
                return redirect(url_for('device_groups'))
            else:
                error_detail = response.json().get('detail', 'Device group creation failed')
                flash(f'Device group creation failed: {error_detail}', 'danger')
        except requests.exceptions.RequestException as e:
            flash(f'An error occurred: {e}', 'danger')
    else:
        # Fetch the list of device groups
        try:
            response = requests.get(f'{API_URL}/device-groups', headers=headers)
            print(response)
            if response.status_code == 200:
                device_groups_data = response.json()
                print(response.json())
                return render_template('device_groups.html', device_groups=device_groups_data)
            else:
                flash('Failed to fetch device group data.', 'danger')
                return redirect(url_for('dashboard'))
        except requests.exceptions.RequestException as e:
            flash(f'An error occurred: {e}', 'danger')
            return redirect(url_for('dashboard'))

    return render_template('device_groups.html')

@app.route('/check-firmware-update/<device_id>')
@login_required
def check_firmware_update(device_id):
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    try:
        # Check for firmware updates
        response = requests.get(f'{API_URL}/devices/{device_id}/firmware-update-needed', headers=headers)
        if response.status_code == 200:
            update_data = response.json()
            # Fetch the firmware version from the FastAPI server
            firmware_response = requests.get(f"{API_URL}/firmware/{update_data.get('firmware_id')}", headers=headers)
            if firmware_response.status_code == 200:
                firmware_version = firmware_response.json().get('version')
                print(firmware_version)
                return jsonify({
                    'needed': update_data.get('needed'),
                    'firmware_data': firmware_response.json()
                })
            else:
                return jsonify({'error': 'Failed to fetch firmware version'}), 400
        else:
            return jsonify({'error': 'Failed to check for firmware updates'}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/firmware/<firmware_id>/download')
@login_required
def download_firmware(firmware_id):
    """
    Handles firmware download by proxying the request to the FastAPI server
    and streaming the response back to the client.
    """
    token = session.get('access_token')
    headers = {'Authorization': f'Bearer {token}'}

    try:
        # Forward the request to the FastAPI server
        fastapi_response = requests.get(
            f'{API_URL}/firmware/{firmware_id}/download',
            headers=headers,
            stream=True
        )

        # Check if the firmware file exists
        if fastapi_response.status_code == 200:
            # Extract headers from FastAPI response
            fastapi_headers = fastapi_response.headers

            # Prepare headers for Flask response
            # Convert headers to a dictionary
            response_headers = {}
            for key, value in fastapi_headers.items():
                response_headers[key] = value

            # Create a Flask Response object, streaming the content
            return Response(
                fastapi_response.iter_content(chunk_size=8192),
                status=fastapi_response.status_code,
                headers=response_headers,
                content_type=fastapi_response.headers.get('Content-Type', 'application/octet-stream')
            )
        else:
            # Handle errors from FastAPI
            error_message = fastapi_response.json().get('detail', 'Firmware file not found.')
            flash(f'Failed to download firmware: {error_message}', 'danger')
            return redirect(url_for('autotq_page', device_id=request.args.get('device_id')))
    except requests.exceptions.RequestException as e:
        # Handle request exceptions
        flash(f'An error occurred while downloading firmware: {e}', 'danger')
        return redirect(url_for('autotq_page', device_id=request.args.get('device_id')))


if __name__ == '__main__':
    app.run(debug=True)