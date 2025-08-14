# A/R Payment Tracker Web Application

This project is a web application for tracking accounts receivable (A/R) payments. It is built using FastAPI and provides features for user authentication, invoice management, and client management.

## Project Structure

```
ar_platform_web
├── src
│   ├── ar_platform.py        # FastAPI application code
│   └── static
│       └── index.html        # Main HTML page for the web application
├── requirements.txt          # List of dependencies
└── README.md                 # Project documentation
```

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd ar_platform_web
   ```

2. **Create a virtual environment:**
   ```
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   - On Windows:
     ```
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```
     source venv/bin/activate
     ```

4. **Install the required dependencies:**
   ```
   pip install -r requirements.txt
   ```

5. **Run the FastAPI application:**
   ```
   uvicorn src.ar_platform:app --host 127.0.0.1 --port 8000 --reload
   ```

6. **Access the application:**
   Open your web browser and navigate to `http://127.0.0.1:8000`.

## Usage

- Register a new account to start using the application.
- Log in to manage clients and invoices.
- Use the dashboard to view and track payments.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.