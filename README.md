# HackShield

A comprehensive Django-based security application that provides file encryption/decryption, malware scanning, network analysis, and secure file management capabilities.

## Features

- 🔐 **File Encryption/Decryption**: Secure file encryption using Fernet symmetric encryption
- 🛡️ **Malware Detection**: Scan files for malware signatures and suspicious patterns
- 🌐 **Network Analysis**: Network packet capture and anomaly detection
- 📊 **Security Reports**: Generate detailed security reports and scan history
- 🔍 **URL Scanning**: Scan URLs for potential security threats
- 📁 **File Management**: Secure upload, storage, and management of files

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.8+** (Python 3.11 or 3.12 recommended for better package compatibility)
- **pip** (Python package manager)
- **Git** (for cloning the repository)
- **Microsoft Visual C++ Build Tools** (for Windows - required for some packages like `cffi`, `contourpy`)
  - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/himanshukhatri192/HackShield.git
cd HackShield
```

### 2. Create a Virtual Environment (Recommended)

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

**Note:** If you encounter compilation errors on Windows (especially with `cffi` or `contourpy`), you have two options:

1. **Install Microsoft Visual C++ Build Tools** (recommended)
2. **Use Python 3.11 or 3.12** which have better pre-built wheel support

If some packages fail to install, you can install core dependencies manually:

```bash
pip install Django==5.1.7 django-cors-headers django-crispy-forms djangorestframework dj-database-url cryptography pandas scapy requests
```

### 4. Configure Database

The project uses SQLite by default. The database will be automatically created when you run migrations.

If you want to use a different database (PostgreSQL, MySQL, etc.), set the `DATABASE_URL` environment variable:

```bash
# Windows PowerShell
$env:DATABASE_URL="postgresql://user:password@localhost/dbname"

# Linux/Mac
export DATABASE_URL="postgresql://user:password@localhost/dbname"
```

### 5. Run Migrations

```bash
python manage.py migrate
```

This will create the necessary database tables.

### 6. Create a Superuser (Optional)

To access the Django admin panel:

```bash
python manage.py createsuperuser
```

Follow the prompts to create an admin account.

### 7. Collect Static Files

```bash
python manage.py collectstatic --noinput
```

## Running the Application

### Start the Development Server

```bash
python manage.py runserver
```

The application will be available at: **http://127.0.0.1:8000/**

### Access the Admin Panel

Navigate to: **http://127.0.0.1:8000/admin/**

## Project Structure

```
HackShield/
├── hackshield/          # Main Django app
│   ├── models.py        # Database models
│   ├── views.py         # View functions
│   ├── urls.py          # URL routing
│   ├── settings.py      # Django settings
│   └── utils/
│       └── encryption.py # Encryption utilities
├── main/                # Additional Django app
├── templates/           # HTML templates
├── static/             # Static files (CSS, JS, images)
├── media/              # User uploaded files
│   ├── encrypted/      # Encrypted files
│   ├── decrypted/      # Decrypted files
│   ├── keys/           # Encryption keys
│   └── uploads/        # Uploaded files
├── requirements.txt    # Python dependencies
└── manage.py          # Django management script
```

## Configuration

### Environment Variables (Optional)

Create a `.env` file in the project root for environment-specific settings:

```env
SECRET_KEY=your-secret-key-here
DEBUG=True
DATABASE_URL=sqlite:///db.sqlite3
ALLOWED_HOSTS=localhost,127.0.0.1
```

### Security Settings

The project includes security configurations in `hackshield/settings.py`:

- File upload size limit: 100MB
- CSRF protection enabled
- Secure file permissions
- Encryption chunk size: 8192 bytes

## Key Features Usage

### File Encryption

1. Navigate to the encryption page
2. Upload a file
3. The file will be encrypted and stored securely
4. Download the encrypted file and encryption key

### File Decryption

1. Navigate to the decryption page
2. Upload the encrypted file
3. Provide the encryption key
4. Download the decrypted file

### Malware Scanning

1. Upload a file for scanning
2. The system will check for known malware signatures
3. View the scan report with detailed results

### Network Analysis

1. Access the network analysis page
2. The system will capture network packets
3. Analyze network traffic for anomalies

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed from `requirements.txt`

2. **Database Errors**: Run `python manage.py migrate` to set up the database

3. **Static Files Not Loading**: Run `python manage.py collectstatic`

4. **Permission Errors**: Ensure the `media/` directory has write permissions

5. **Port Already in Use**: Change the port:
   ```bash
   python manage.py runserver 8001
   ```

### Windows-Specific Issues

- **cffi compilation error**: Install Microsoft Visual C++ Build Tools
- **scapy/libpcap warnings**: Install Npcap (https://nmap.org/npcap/) for full network capture support

## Development

### Running Tests

```bash
python manage.py test
```

### Making Migrations

After modifying models:

```bash
python manage.py makemigrations
python manage.py migrate
```

## Technologies Used

- **Backend**: Django 5.1.7
- **Database**: SQLite (default), PostgreSQL/MySQL (optional)
- **Encryption**: Cryptography (Fernet)
- **Network Analysis**: Scapy
- **Data Processing**: Pandas, NumPy
- **API**: Django REST Framework

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Support

For issues and questions, please open an issue on the GitHub repository.

## Authors

- **Himanshu Khatri** - [GitHub](https://github.com/himanshukhatri192)

---

**Note**: This is a security-focused application. Always use strong encryption keys and follow security best practices when handling sensitive data.
