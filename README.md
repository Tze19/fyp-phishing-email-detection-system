# Web-Based Phishing Email Detection System for Secure Online Communication using Machine Learning and Sandbox-assisted Analysis

## Overview
This project is a web-based phishing email detection system developed using Flask. Users upload suspicious .eml files, which are analysed using multiple detection modules.

## Main Features
- Machine-learning email classification using Linear SVM
- Email parsing and metadata extraction
- SPF, DKIM and DMARC/header analysis
- Static URL analysis
- Sandbox-assisted URL analysis using Selenium and Chromium
- Controlled static attachment analysis
- Hybrid risk assessment
- Web-based results dashboard

## System Requirements
- Python 3.x
- Docker
- Docker Compose
- Chromium/Selenium container

## Installation

1. Clone the repository
2. Create and activate a Python virtual environment
3. Install dependencies:
   pip install -r requirements.txt

## Start Selenium Sandbox
docker compose up -d

Check status:
docker compose ps

## Run the Application
source venv/bin/activate

python app.py

## Test Samples
Synthetic .eml samples are provided under the samples directory for testing legitimate, phishing, URL and attachment-analysis scenarios.

## Project Scope
The sandbox-assisted dynamic analysis is applied to URLs. Attachments undergo controlled static inspection and are not executed.

## Disclaimer
The provided samples are intended only for academic and controlled testing purposes.
