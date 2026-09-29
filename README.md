# AI-Based Cyber Deception and Threat Hunting Platform

## Project Overview

The AI-Based Cyber Deception and Threat Hunting Platform is a cybersecurity monitoring and threat detection system designed to identify suspicious security activity using cyber deception, activity monitoring, AI-based analysis, IOC detection, risk scoring, and threat hunting.

The platform collects security-relevant events, analyzes them using a machine learning model, calculates a risk score, extracts indicators of compromise, and presents the results through a centralized security dashboard.

## Objectives

- Detect suspicious security-related activity
- Monitor security events in a controlled environment
- Perform AI-based threat classification
- Extract IP addresses and domain indicators
- Calculate security risk scores
- Perform basic threat hunting and event correlation
- Generate incident reports
- Provide a centralized cybersecurity dashboard

## Key Features

- Cyber Deception Event Detection
- Local Activity Monitoring
- AI-Based Threat Classification
- IOC Detection
- Risk Score Calculation
- Threat Hunting
- Incident Reporting
- Real-Time Security Dashboard
- SQLite Event Storage
- Online Deployment

## Technology Stack

### Backend
- Python
- Flask
- SQLite

### Cybersecurity & Monitoring
- psutil
- IOC extraction using Regular Expressions
- Threat Hunting
- Risk Scoring

### Artificial Intelligence
- Scikit-learn
- Random Forest Classifier
- Joblib

### Frontend
- HTML
- CSS
- JavaScript

### Deployment
- GitHub
- Render
- Gunicorn

## System Workflow

```text
Security Activity
       ↓
Activity Collection
       ↓
Event Storage
       ↓
AI Threat Analysis
       ↓
IOC Detection
       ↓
Risk Score Calculation
       ↓
Threat Hunting
       ↓
Incident Generation
       ↓
Security Dashboard
