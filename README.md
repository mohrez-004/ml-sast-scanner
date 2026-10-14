# ML Vulnerability Classification

This repository contains Machine Learning pipelines focused on training and evaluating Support Vector Machine (SVM) models to detect security vulnerabilities, specifically SQL Injection (SQLi) and Cross-Site Scripting (XSS).

## Pipeline Architecture
- **Data Preprocessing:** Converts raw text payloads into numerical vectors using `TfidfVectorizer` to highlight critical attack signatures (e.g., `<script>` or `UNION SELECT`).
- **Model Training:** Utilizes `LinearSVC` and `SVC` with an RBF kernel to find the optimal hyperplane separating benign and malicious code.
- **Evaluation:** Models are evaluated on unseen data, achieving high accuracy (~97% for SQLi and ~99.8% for XSS), measured via Precision, Recall, F1-Score, and Confusion Matrices.
- **Serialization:** Trained models and vectorizers are exported as `.pkl` files using `joblib` for live predictions in static analysis tools.

## Datasets Used
- [Cipher Dataset (Kaggle)](https://www.kaggle.com/datasets/tarunjaikumar/cipher-dataset)
- [HTTPS traffic classification (Kaggle)](https://www.kaggle.com/datasets/inhngcn/https-traffic-classification)
- [TLS Dataset (Kaggle)](https://www.kaggle.com/datasets/susanshly/tlsdataset)

## Usage & How to Run

To run the vulnerability scanner locally and test code snippets or files using the trained SVM models, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/mohrez-004/ml-sast-scanner.git](https://github.com/mohrez-004/ml-sast-scanner.git)
   cd ml-sast-scanner
