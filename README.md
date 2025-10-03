FUTURE_CS_03
Secure File Sharing System
A simple and secure file sharing web application built using Python Flask.
Files uploaded to the system are encrypted using AES-GCM before storage and decrypted when downloaded. This project demonstrates secure file handling, encryption, and basic user authentication.
________________________________________
Features
•	User authentication (login/logout)
•	Upload and download files securely
•	AES-GCM encryption for all files at rest
•	File integrity verification (AES-GCM ensures tamper detection)
•	Flash messages for upload/download status
•	Simple web interface for file management
________________________________________
Tools & Technologies
•	Backend: Python Flask
•	Frontend: HTML
•	Encryption: PyCryptodome (AES-GCM)
•	Authentication: Werkzeug (password hashing)
•	Environment Management: python-dotenv
•	Version Control: Git & GitHub
________________________________________
Create a virtual environment and activate it
python -m venv venv
Windows
venv\Scripts\activate
Install dependencies

pip install -r requirements.txt
Create a .env file in the project root:
AES_KEY=16charkeyforaes! # Must be 16/24/32 bytes FLASK_SECRET_KEY=your_flask_secret
Run the Flask app
python app.py

Open your browser at: http://127.0.0.1:5000
Usage
Login
Enter your username and password (stored in users.json).

Upload a File
Click the “Choose File” button.
Select your file and submit.
File will be encrypted and saved in the uploads/ folder.

Download a File
All uploaded files will be listed on the dashboard.
Click “Download” to get the decrypted version of the file.


Security Features
AES-GCM Encryption: All files are encrypted before saving.
Tamper Detection: AES-GCM ensures file integrity using authentication tags.
Password Hashing: User passwords are stored hashed in users.json.
Environment Variables: Sensitive keys are stored in .env, not in code.


Upload Restrictions: File size is limited to 50 MB.
File Structure secure-file-sharing/ │ ├── app.py # Main Flask application ├── requirements.txt # Python dependencies ├── .gitignore # Ignored files/folders ├── .env # Environment variables (not pushed) ├── users.json # User credentials (hashed passwords) ├── uploads/ # Encrypted files storage ├── templates/ │ ├── login.html │ ├── index.html │ └── dashboard.html
Testing & Verification
Upload .txt, .pdf, .png, or .jpg files.
Download them to ensure original content is restored.
Check the uploads/ folder — all files are encrypted and unreadable directly.

Test edge cases:
Large files (>50 MB) → rejected
Tampered .enc files → decryption fails
Only logged-in users can access upload/download features.


Future Improvements:
Assign user-specific file access (each user sees only their files)
Implement unique encryption keys per file
Add file type validation (only allow specific extensions)
Track upload/download history for auditing

