import ast
import os
import pandas as pd
import joblib
import argparse

def extract_sql_queries_from_file(file_path):
    queries = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            source = file.read()
        tree = ast.parse(source, filename=file_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"execute", "executemany", "executescript"}:
                    if node.args:
                        arg = node.args[0]
                        query = None
                        if isinstance(arg, ast.Constant):
                            query = arg.value
                        elif isinstance(arg, ast.JoinedStr):
                            query = "".join([v.value for v in arg.values if isinstance(v, ast.Constant)]) + "<f-string>"
                        elif isinstance(arg, ast.BinOp):
                            query = "<concatenated string query>"
                        elif isinstance(arg, ast.Name):
                            query = f"<variable '{arg.id}' as query>"
                        if query:
                            queries.append(query.strip())
    except Exception as e:
        print(f"[!] Error parsing {file_path} for SQLi: {e}")
    return queries

def extract_xss_sinks_from_file(file_path):
    sinks = []
    XSS_SINK_FUNCTIONS = {'HttpResponse', 'render', 'render_template', 'render_template_string', 'Markup', 'Response'}
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            source = file.read()
        tree = ast.parse(source, filename=file_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ''
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if func_name in XSS_SINK_FUNCTIONS:
                    for arg in node.args:
                        sink_code = ast.unparse(arg).strip()
                        sinks.append(sink_code)
    except Exception as e:
        print(f"[!] Error parsing {file_path} for XSS: {e}")
    return sinks

def predict_and_save(data_list, model_path, vectorizer_path, out_file, column_name):
    if not data_list:
        print(f"No {column_name} entities to process.")
        return

    df = pd.DataFrame(data_list, columns=[column_name])
    try:
        model = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)
        
        X = vectorizer.transform(df[column_name])
        df['label'] = model.predict(X)
        
        df.to_csv(out_file, index=False)
        print(f"[+] Prediction completed. Results saved to {out_file}")
    except Exception as e:
        print(f"[-] Error during prediction for {column_name}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-driven SAST Scanner for SQLi and XSS")
    parser.add_argument("source_file", help="Path to the Python source file")
    args = parser.parse_args()

    source_file = args.source_file
    if not os.path.isfile(source_file):
        print(f"Error: '{source_file}' is not a valid file.")
        exit(1)

    print(f"\nScanning file: {source_file}")
    
    # Calculate relative model paths
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    models_dir = os.path.join(base_dir, 'models')

    print("\n--- Starting SQL Injection Scan ---")
    queries_found = extract_sql_queries_from_file(source_file)
    predict_and_save(queries_found, 
                     os.path.join(models_dir, 'SVM_SQLi.pkl'), 
                     os.path.join(models_dir, 'tfidf_SQLi.pkl'), 
                     "sqli_scan_results.csv", "query")

    print("\n--- Starting Cross-Site Scripting (XSS) Scan ---")
    sinks_found = extract_xss_sinks_from_file(source_file)
    predict_and_save(sinks_found, 
                     os.path.join(models_dir, 'SVM_XSS.pkl'), 
                     os.path.join(models_dir, 'tfidf_XSS.pkl'), 
                     "xss_scan_results.csv", "sink")

    print("\n[+] Pipeline finished!")