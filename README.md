# HackShield

A comprehensive security platform for file encryption, malware scanning, and network anomaly detection.

## Overview

HackShield is a Django-based security application designed to provide multiple layers of protection for your files and network. It offers secure file encryption/decryption, malware scanning with signature detection, and network traffic analysis to identify potential threats.

## Features

- **User Authentication**: Secure user accounts with isolated file storage
- **File Encryption/Decryption**: 
  - Fernet symmetric encryption for secure file storage
  - Background processing for large files via Celery
  - Streaming encryption/decryption support
- **Malware Scanning**:
  - Signature-based detection
  - Heuristic analysis for suspicious file types
  - Detailed threat reports and recommendations
- **Network Anomaly Detection**:
  - Real-time network traffic monitoring
  - Statistical analysis to identify unusual patterns
  - Detailed anomaly reporting
- **REST API**: Comprehensive API for integration with other systems
- **Secure by Design**: Environment-based configuration, no hardcoded secrets

## Setup and Installation

### Prerequisites

- Python 3.8+
- PostgreSQL
- Redis (for Celery)
- Docker and Docker Compose (for containerized deployment)

### Local Development Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/hackshield.git
   cd hackshield
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```
   cp .env.example .env
   ```
   Edit the `.env` file with your specific configuration values.

5. Run migrations:
   ```
   python manage.py migrate
   ```

6. Start the development server:
   ```
   python manage.py runserver
   ```

7. In a separate terminal, start Celery worker:
   ```
   celery -A hackshield worker -l info
   ```

### Docker Deployment

1. Make sure Docker and Docker Compose are installed on your system.

2. Configure environment variables:
   ```
   cp .env.example .env
   ```
   Edit the `.env` file with your production configuration.

3. Build and start the containers:
   ```
   docker-compose up -d
   ```

4. The application should now be running at http://localhost:8000

## Environment Configuration

HackShield uses environment variables for configuration. Key variables include:

- `SECRET_KEY`: Django secret key
- `DEBUG`: Set to False in production
- `DATABASE_URL`: Database connection string
- `REDIS_URL`: Redis connection string for Celery
- `ALLOWED_HOSTS`: Comma-separated list of allowed hosts
- `MEDIA_ROOT`: Directory for file storage
- `KEYS_DIR`: Directory for encryption keys

See `.env.example` for a complete list of configuration options.

## Environment Setup

To properly configure your environment:

1. Copy the example environment file to create your own configuration:
   ```
   cp .env.example .env
   ```

2. Edit the `.env` file and ensure you set at least these critical values:
   - `SECRET_KEY`: Set a strong, unique secret key for security
   - `ALLOWED_HOSTS`: Add the hostnames your application will run on (e.g., `localhost,127.0.0.1`)

3. Start the application using either:
   - For local development: `python manage.py runserver`
   - For Docker deployment: `docker-compose up`

The application will use the values from your `.env` file to configure itself appropriately.

## API Reference

HackShield provides a RESTful API for integration with other systems:

### Authentication

- `POST /api/auth/token/`: Obtain JWT token
- `POST /api/auth/token/refresh/`: Refresh JWT token

### File Operations

- `POST /api/files/upload/`: Upload a file
- `GET /api/files/`: List uploaded files
- `GET /api/files/{id}/`: Get file details
- `DELETE /api/files/{id}/`: Delete a file

### Encryption

- `POST /api/encrypt/`: Encrypt a file
- `POST /api/decrypt/`: Decrypt a file
- `GET /api/encryption-tasks/{task_id}/`: Check encryption task status

### Malware Scanning

- `POST /api/scan/`: Scan a file for malware
- `GET /api/reports/`: List scan reports
- `GET /api/reports/{id}/`: Get detailed scan report

### Network Analysis

- `GET /api/network/anomalies/`: Get network anomaly data

For detailed API documentation, see the [API Reference](docs/api-reference.md).

## Architecture

HackShield follows a modular architecture with the following components:

- Django web application for the user interface
- Django REST Framework for the API
- Celery for background task processing
- PostgreSQL for data storage
- Redis for task queue and caching

For more details, see the [Architecture Documentation](docs/architecture.md).

## Security Considerations

- Encryption keys are stored separately from encrypted files
- User authentication is required for all sensitive operations
- Files are processed in isolated environments
- Network traffic analysis is performed locally

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
