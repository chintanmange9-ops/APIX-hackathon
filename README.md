# RBI Hackathon Project

## Overview
This project was developed for the RBI Hackathon to manage and verify tokenized banking data. It allows users to upload PDF statements, extract transaction data, issue and verify tokens, and download results in Excel format.

## Features
- Upload PDF bank statements.
- Extract transaction data including debits, credits, balances.
- Issue and verify tokens.
- QR code generation for easy token lookup.
- Export processed data to Excel.
- Simple web interface built with Flask.
- SQLite backend for storing tokens and processed data.

## Requirements
- Python 3.11+
- Packages listed in `requirements.txt`

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/<USERNAME>/rbi-hackathon.git
   cd rbi-hackathon

## Install dependencies:

pip install -r requirements.txt

## Initialize the database:

python init_db.py

## Run the server:

python server.py

## Running the Application
Start the app:
Note: Do not forget to add Server_ip in app.py

streamlit run frontend/app.py

Project Structure


├── frontend/         # Flask app
├── data/             # Database scripts and CSV files
├── requirements.txt
├── README.md
├── server.py
Notes
SQLite database tokens.db is created automatically.

Handles multi-line transaction descriptions in PDFs.

QR codes are generated dynamically for token lookup.