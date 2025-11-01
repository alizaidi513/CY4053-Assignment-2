# CY4053-Assignment-2
This repository contains a secure financial web application developed in Python Streamlit for the course
Course: CY4053 – Cybersecurity for FinTech
Assignment: Secure FinTech App Development & Manual Cybersecurity Testing
Semester: BS FinTech – 7th Semester (Fall 2025)
Instructor: Dr. Usama Arshad
Student: Ali Abbas

🔐 Project Overview

This mini FinTech application demonstrates the core principles of secure software development.
It is built using Python Streamlit and implements several essential cybersecurity concepts including:

Secure user registration and login using password hashing

Input validation to prevent SQL Injection and XSS

Session management and secure logout

Data confidentiality through hashing and encryption

Error handling to prevent information leakage

Optional file upload validation

Basic activity logging and data protection features

🧠 Objective

The purpose of this assignment is to develop a security-aware FinTech application and perform at least 20 manual cybersecurity tests on it to evaluate its robustness against common vulnerabilities.

🧾 Manual Testing Summary

A total of 20 manual cybersecurity test cases were performed, covering areas such as:

Authentication & Authorization

Password Strength Enforcement

SQL Injection & XSS Prevention

Data Confidentiality & Encryption

Input Validation & Error Handling

Session Management & Account Lockout

Each test was documented with expected and observed results along with screenshots (see the attached Word file).

⚙️ Technologies Used

Language: Python 3.10+

Framework: Streamlit

Libraries: bcrypt, hashlib, cryptography, pandas

Environment: Visual Studio Code (Windows)

🚀 How to Run

Open a terminal inside the project folder.

(Optional) Activate your virtual environment:

.\venv\Scripts\activate


Install dependencies:

pip install -r requirements.txt


Run the Streamlit app:

streamlit run secure_app.py


Open the local server link (e.g., http://localhost:8501
) in your browser.
