# PhishGuard Website

## Run on Windows
1. Extract the ZIP.
2. Open the `phishguard_website_project` folder.
3. Click File Explorer's address bar, type `cmd`, and press Enter.
4. Install Flask:
   `python -m pip install -r requirements.txt`
   If needed, replace `python` with `py`.
5. Start the website:
   `python app.py`
6. Open your browser and visit: `http://127.0.0.1:5000`

## Features
- Email text analysis
- URL pattern analysis (does not open URLs)
- Offline fictional phishing-awareness simulation
- Responsive dashboard

## Safety and limitations
This is a local beginner demo. The server listens only on your own computer. Do not expose Flask's development server to the internet. No emails are sent and no credentials are collected. The rule-based results may be wrong and are not a production security service.

