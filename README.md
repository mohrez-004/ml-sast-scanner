# ML Vulnerability Classification (SAST Scanner)

This repository contains Machine Learning pipelines focused on training and evaluating Support Vector Machine (SVM) models to detect security vulnerabilities in source code, specifically SQL Injection (SQLi) and Cross-Site Scripting (XSS).

## Pipeline Architecture
- **Data Preprocessing:** Converts raw text and code payloads into numerical vectors using `TfidfVectorizer` to highlight critical attack signatures (e.g., `<script>` or `UNION SELECT`).
- **Model Training:** Utilizes `LinearSVC` and `SVC` with an RBF kernel to find the optimal hyperplane separating benign and malicious code patterns.
- **Evaluation:** Models are evaluated on unseen data, achieving high accuracy (~97% for SQLi and ~99.8% for XSS), measured via Precision, Recall, F1-Score, and Confusion Matrices.
- **Serialization:** Trained models and vectorizers are exported as `.pkl` files using `joblib` (`SVM_SQLi.pkl`, `SVM_XSS.pkl`, `tfidf_SQLi.pkl`, `tfidf_XSS.pkl`) for real-time static analysis.

## Project Structure
- `models/main.py`: Main inference and testing script.
- `models/*.pkl`: Pre-trained SVM classifiers and TF-IDF vectorizers for SQLi and XSS detection.

## Datasets Used
- [Cipher Dataset (Kaggle)](https://www.kaggle.com/datasets/tarunjaikumar/cipher-dataset)
- [HTTPS Traffic Classification (Kaggle)](https://www.kaggle.com/datasets/inhngcn/https-traffic-classification)
- [TLS Dataset (Kaggle)](https://www.kaggle.com/datasets/susanshly/tlsdataset)

## Usage & How to Run

To run the vulnerability scanner locally and test code snippets using the pre-trained SVM models, follow these steps:

1. **Clone the repository:**

         git clone git@github.com:mohrez-004/ml-sast-scanner.git
         cd ml-sast-scanner

3. **Install dependencies:**

       pip install scikit-learn joblib numpy

4. **Run the inference script:**

       python models/main.py
