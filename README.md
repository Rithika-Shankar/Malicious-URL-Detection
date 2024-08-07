# Malicious URL Detection Project

## Table of Contents
1. [Introduction](#introduction)
2. [Problem Statement](#problem-statement)
3. [Solution Overview](#solution-overview)
4. [Technical Implementation](#technical-implementation)
    - [Dataset Utilization](#dataset-utilization)
    - [Feature Engineering](#feature-engineering)
    - [Model Development](#model-development)
    - [Model Training](#model-training)
    - [Web Application](#web-application)
    - [API Endpoints](#api-endpoints)
5. [Feedback Loop and Model Improvement](#feedback-loop-and-model-improvement)
6. [Conclusion](#conclusion)

## Introduction
This document provides comprehensive details about the Malicious URL Detection project developed during a hackathon. The project aims to create a robust system that analyzes URLs to detect potential phishing threats using machine learning techniques. The solution includes a web application that allows users to input URLs for analysis, view AI-generated probabilities of those URLs being malicious, and provide feedback to improve the model.

## Problem Statement
Phishing attacks are a significant cybersecurity threat, with malicious actors using deceptive URLs to trick users into revealing sensitive information. The objective of this project is to develop an AI-powered solution that can accurately assess the likelihood of a given URL being malicious, thereby helping users avoid phishing scams.

**Key Requirements:**
- Analyze URLs to determine if they are malicious.
- Provide a user-friendly interface for inputting URLs and viewing results.
- Integrate a feedback mechanism to continually improve the model's accuracy.

## Solution Overview
The solution involves developing a Flask-based web application with a REST API that leverages machine learning models to assess the probability of URLs being malicious. The system is designed to be user-friendly, secure, and continuously improving through user feedback.

**Features:**
- URL analysis using trained machine learning models.
- User feedback integration to enhance model accuracy.
- Data storage for URLs and feedback.
- Secure handling of user data and model integrity.

  ### Data flow Diagram 
  ```mermaid
  flowchart TD
    A[User Input] --> B[Web Application]
    B --> C[REST API]
    C --> D[Machine Learning Model]
    D --> E[Database]
    E --> F[Results Presentation]
    F --> G[Feedback Integration]
    G --> H[Retrain ML Model]

## Technical Implementation

### Dataset Utilization
- **Dataset:** Malicious URL Dataset from Kaggle.
- **Preprocessing:**
  - Addressing missing values and outliers.
  - Feature encoding and normalization.

### Feature Engineering
- Enhanced dataset with additional features such as domain age, registration details, and natural language processing techniques for URL analysis.

### Model Development
- Experimentation with various machine learning models:
  - LightGBM
  - XGBoost
  - Random Forest
- Implementation of cross-validation techniques.
- Evaluation using metrics like accuracy, precision, recall, and F1-score.

### Model Training
- **Scripts:**
  - `train_model.py`: For initial training of models.
  - `retrain_model.py`: For retraining models with new data.
- **Pipeline:**
  - Data loading and preprocessing.
  - Model training and evaluation.
  - Model selection based on performance metrics.

### Web Application
- **Framework:** Flask
- **Main Script:** `app.py`
- **Templates:**
  - `index.html`: Main page for URL input.
  - `result.html`: Displays analysis results.
- **Routes:**
  - `GET /`: Renders the main HTML page (`index.html`).
  - `POST /api/analyze`: Accepts URLs for analysis and returns the prediction results.

### API Endpoints

**Analyze URLs**
- **Endpoint:** `POST /api/analyze`
- **Description:** Analyzes one or more URLs to determine if they are malicious.
- **Request Body:**
  ```json
  {
    "urls": "http://example.com,http://test.com"
  }
- **Response:**
  ```json
  {
    "results": [
      {
        "url": "http://example.com",
        "prediction": "Safe",
        "probability": "0.10",
        "explanation": "No specific features indicate malicious intent.",
        "features": { ... }
      },
      {
        "url": "http://test.com",
        "prediction": "Malicious",
        "probability": "0.85",
        "explanation": "Contains suspicious patterns.",
        "features": { ... }
      }
    ]
  }

**User Management**

- **User Registration**

- **Endpoint:**

`POST /api/register`

- **Request Body:** 

  ```json
  {
    "username": "<username>",
    "email": "<email>",
    "password": "<password>"
  }

- **Response:**
  ```json
  {
    "status": "success",
    "userId": "<user_id>"
  }
- **User Logout**

- **Endpoint:**

`POST /api/logout`

- **Headers:** 

  ```json
  {
    "Authorization": "Bearer <auth_token>"
  }

- **Response:**
  ```json
  {
    "status": "success"
  }

**Model Management**

- **Upload New Model**

`POST /api/model`

- **Request Body:** 

  ```json
  {
    "modelFile": "<model_file>"
  }

- **Response:**
  ```json
  {
    "status": "success",
    "modelId": "<model_id>"
  }

- **Get Model Details:**

`GET /api/model/{modelId}`

- **Response:**
  ```json
  {
    "status": "success",
    "modelDetails": {
      "modelId": "<model_id>",
      "accuracy": "<accuracy>",
      "created_at": "<timestamp>"
    }
  }

**Analysis and Reporting**

- **Update URL Analysis:**

`PUT /api/analysis/{analysisId}`

- **Request Body:** 

  ```json
  {
    "url": "<new_url_string>"
  }

- **Response:**
  ```json
  {
    "status": "success",
    "message": "Analysis updated"
  }
- **Delete URL Analysis:**
`DELETE /api/analysis/{analysisId}`

- **Response:**
  ```json
  {
    "status": "success",
    "message": "Analysis deleted"
  }
- **Generate Analysis Report:**
  `POST /api/analysis/{analysisId}/report`
  
- **Response:**
  ```json
  {
    "status": "success",
    "reportId": "<report_id>"
  }
- **Get Analysis Report:**
  `GET /api/report/{reportId}`
- **Response:**
   ```json
  {
    "status": "success",
    "report": "<report_content>"
  }

**Administrative**

- **List All Users:**
  `GET /api/admin/users`
- **Headers:**
   ```json
  {
    "Authorization": "Bearer <admin_auth_token>"
  }
- **Response:**
  ```json
  {
    "users": [
    {
      "userId": "<user_id>",
      "username": "<username>",
      "email": "<email>"
    }
   ]
  }

- **Delete User:**
   `DELETE /api/admin/user/{userId}`
- **Headers:**
   ```json
  {
    "Authorization": "Bearer <admin_auth_token>"
  }
- **Response:**
   ```json
  {
    "status": "success",
    "message": "User deleted"
  }
- **Request Data Deletion:**
  `POST /api/user/data-deletion`
- **Headers:**
  ```json
  {
    "Authorization": "Bearer <auth_token>"
  }
- **Response:**
  ```json
  {
    "status": "success",
    "message": "Data deletion requested"
  }

## Feedback Loop and Model Improvement
**User Feedback Integration**
- **Feedback Mechanism:** Users can provide feedback on the predictions, indicating whether they agree with the model’s assessment.
- **Feedback Endpoint:**
- **Endpoint: POST**
   `/api/feedback`
- **Request Body:**
  ```json
  {
    "url": "<url>",
    "prediction": "<prediction>",
    "user_feedback": "<true/false>"
  }
- **Response:**
  ```json
  {
    "status": "success",
    "message": "Feedback received"
  }
  
**Model Retraining**
- **Retraining Process:**
  - Periodic retraining of the model using new data, including user feedback.
  - Automated pipeline for data preprocessing, model training, and evaluation.
- **Retraining Script: retrain_model.py**
  - Execution: Run script with new feedback data to update model parameters and improve accuracy.


## Conclusion

The URL analysis feature effectively distinguishes between safe and malicious URLs using a combination of key indicators. For example:

- **Safe URL:** [https://youtube.com/](https://youtube.com/) was accurately classified as safe, with a probability of 0.00, indicating no significant features of malicious behavior.
- **Malicious URL:** [http://evra-international-inc.com/index.php?option=com_content&view=article&id=8,defacement](http://evra-international-inc.com/index.php?option=com_content&view=article&id=8,defacement) was flagged as malicious with a probability of 1.00 due to several detected features, such as abnormal URL patterns and unusual counts of directory segments, HTTP protocols, question marks, and digits.

These analyses underscore the system's ability to detect potential threats by evaluating various URL characteristics and highlight the importance of user feedback in refining the model’s accuracy.

### Summary and Impact

The Malicious URL Detection project provides a practical solution for identifying potentially harmful URLs. The integration of machine learning models, user feedback, and a user-friendly web interface creates a robust system that continually improves over time. This documentation serves as a comprehensive guide for developers and stakeholders to understand, utilize, and contribute to the project effectively.

