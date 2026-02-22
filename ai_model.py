import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import socket
import whois
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import json
import os
from datetime import datetime
import logging
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CyberScanAI:
    
    def __init__(self, model_path='cyberscan_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.text_vectorizer = TfidfVectorizer(
            max_features=500,
            stop_words='english',
            ngram_range=(1, 3)
        )
        
        self.structural_features = [
            'url_length',
            'num_dots',
            'num_hyphens',
            'num_digits',
            'has_ip',
            'subdomain_count',
            'suspicious_tld',
            'path_length',
            'num_query_params',
            'special_chars_count',
            
            'has_dns',
            'has_mx',
            'num_ip_addresses',
            'num_ns_servers',
            
            'domain_age_days',
            'is_private_whois',
            'days_to_expiry',
            
            'ssl_valid',
            'ssl_days_until_expiry',
            
            'num_forms',
            'num_password_forms',
            'num_external_scripts',
            'num_external_resources',
            'scam_word_count',
            'has_brand_impersonation',
            'num_suspicious_patterns',
            'num_iframes',
            'has_meta_refresh',
            'has_redirect',
            'num_hidden_elements',
            'num_external_links'
        ]
        
        self.feature_weights = {
            'structural': 0.4,
            'text': 0.3,
            'behavioral': 0.3
        }


    def scan_website(self, url: str) -> dict:
        import dns.resolver
        result = {"level1": {}, "deep_scan": {}}
        parsed = urlparse(url)
        domain = parsed.netloc

        result["level1"]["url_analysis"] = {
            "url_length": len(url),
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_digits": sum(c.isdigit() for c in url),
            "has_ip": domain.replace(".", "").isdigit(),
            "subdomain_count": domain.count(".") - 1,
            "suspicious_tld": any(tld in domain for tld in [".online",".xyz",".top",".click"]),
            "path_length": len(parsed.path),
            "num_query_params": url.count("="),
            "special_chars_count": sum(not c.isalnum() for c in url)
        }
        
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ips = [str(r) for r in answers]
            has_dns = True
            result["level1"]["dns_analysis"] = {
                "has_dns": has_dns,
                "has_mx": has_dns,
                "ip_addresses": ips,
                "ns_servers": []
            }
        except:
            result["level1"]["dns_analysis"] = {
                "has_dns": False,
                "has_mx": False,
                "ip_addresses": [],
                "ns_servers": []
            }
            
            
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3)
                s.connect((domain, 443))
            ssl_valid = True
            cert = s.getpeercert()
            if cert and 'notAfter' in cert:
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until = (expiry - datetime.now()).days
            else:
                days_until = 30
        except:
            ssl_valid = False
            days_until = -1
        result["level1"]["ssl_analysis"] = {
            "valid": ssl_valid,
            "days_until_expiry": days_until
        }

        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age = (datetime.now() - creation).days if creation else -1
            result["level1"]["whois_analysis"] = {
                "domain_age_days": age,
                "is_private": not bool(w.name or w.org),
                "registrar": w.registrar
            }
        except:
            result["level1"]["whois_analysis"] = {
                "domain_age_days": -1,
                "is_private": False,
                "registrar": None
            }

        try:
            r = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(r.text, "html.parser")

            password_forms = soup.find_all("input", {"type": "password"})
            html = soup.get_text().lower()
            brands = ["kaspi","paypal","google","amazon","bank"]

            brand_impersonation = None
            for b in brands:
                if b in html and b not in domain.lower():
                    brand_impersonation = b
                    break  
                    
            scam_words = ["verify","urgent","login","confirm","account locked","password","credit card"]
            scam_count = sum(word in html for word in scam_words)
            
            has_redirect = len(r.history) > 0
            
            result["deep_scan"] = {
                "form_analysis": [{"has_password": True, "external_action": False, "action": ""} for _ in password_forms],
                "brand_impersonation": brand_impersonation,
                "suspicious_patterns": ["Подозрительное слово: " + word for word in scam_words if word in html][:scam_count],
                "has_redirect": has_redirect,
                "content_analysis": {
                    "scam_word_count": scam_count,
                    "num_iframes": len(soup.find_all("iframe")),
                    "num_external_links": len(soup.find_all("a", href=True)),
                    "num_hidden_elements": len(soup.find_all(style=lambda x: x and "display:none" in x)),
                    "has_meta_refresh": bool(soup.find("meta", attrs={"http-equiv":"refresh"}))
                },
                "javascript_analysis": [{"external": True, "src": s.get('src', '')} for s in soup.find_all("script", src=True)],
                "external_resources": [{"url": l.get('href', ''), "type": "link"} for l in soup.find_all("link", href=True)]
            }
            result["html_content"] = html

        except Exception as e:
            logger.error(f"Error in deep scan: {e}")
            result["deep_scan"] = {
                "form_analysis": [],
                "brand_impersonation": None,
                "suspicious_patterns": [],
                "has_redirect": False,
                "content_analysis": {
                    "scam_word_count": 0,
                    "num_iframes": 0,
                    "num_external_links": 0,
                    "num_hidden_elements": 0,
                    "has_meta_refresh": False
                },
                "javascript_analysis": [],
                "external_resources": []
            }
            result["html_content"] = ""
        return result
           
    def extract_features_from_scan(self, scan_result: dict) -> np.array:
        features = {}
        
        for feature in self.structural_features:
            features[feature] = 0
        
        try:
            level1 = scan_result.get('level1', {})
            deep_scan = scan_result.get('deep_scan', {})
            
            url_analysis = level1.get('url_analysis', {})
            features['url_length'] = url_analysis.get('url_length', 0)
            features['num_dots'] = url_analysis.get('num_dots', 0)
            features['num_hyphens'] = url_analysis.get('num_hyphens', 0)
            features['num_digits'] = url_analysis.get('num_digits', 0)
            features['has_ip'] = int(url_analysis.get('has_ip', False))
            features['subdomain_count'] = url_analysis.get('subdomain_count', 0)
            features['suspicious_tld'] = int(url_analysis.get('suspicious_tld', False))
            features['path_length'] = url_analysis.get('path_length', 0)
            features['num_query_params'] = url_analysis.get('num_query_params', 0)
            features['special_chars_count'] = url_analysis.get('special_chars_count', 0)
            
            dns_analysis = level1.get('dns_analysis', {})
            features['has_dns'] = int(dns_analysis.get('has_dns', False))
            features['has_mx'] = int(dns_analysis.get('has_mx', False))
            features['num_ip_addresses'] = len(dns_analysis.get('ip_addresses', []))
            features['num_ns_servers'] = len(dns_analysis.get('ns_servers', []))
            
            whois_analysis = level1.get('whois_analysis', {})
            features['domain_age_days'] = whois_analysis.get('domain_age_days', -1)
            features['is_private_whois'] = int(whois_analysis.get('is_private', False))
            features['days_to_expiry'] = 0  
            
            ssl_analysis = level1.get('ssl_analysis', {})
            features['ssl_valid'] = int(ssl_analysis.get('valid', False))
            features['ssl_days_until_expiry'] = ssl_analysis.get('days_until_expiry', -1)
            
            if deep_scan:
                forms = deep_scan.get('form_analysis', [])
                features['num_forms'] = len(forms)
                features['num_password_forms'] = len([f for f in forms if f.get('has_password')])
                
                scripts = deep_scan.get('javascript_analysis', [])
                features['num_external_scripts'] = len([s for s in scripts if s.get('external')])
                
                features['num_external_resources'] = len(deep_scan.get('external_resources', []))
                
                features['scam_word_count'] = deep_scan.get('content_analysis', {}).get('scam_word_count', 0)
                features['has_brand_impersonation'] = int(deep_scan.get('brand_impersonation') is not None)
                features['num_suspicious_patterns'] = len(deep_scan.get('suspicious_patterns', []))
                
                content_analysis = deep_scan.get('content_analysis', {})
                features['num_iframes'] = content_analysis.get('num_iframes', 0)
                features['has_meta_refresh'] = int(content_analysis.get('has_meta_refresh', False))
                features['has_redirect'] = int(deep_scan.get('has_redirect', False))
                features['num_hidden_elements'] = content_analysis.get('num_hidden_elements', 0)
                features['num_external_links'] = content_analysis.get('num_external_links', 0)
                
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
        
        feature_values = [features[name] for name in self.structural_features]
        
        return np.array(feature_values).reshape(1, -1)
    
    def extract_text_features(self, html_content: str) -> np.array:
        if not html_content:
            return np.zeros((1, 500))  
        
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        text = soup.get_text()
        
        try:
            text_features = self.text_vectorizer.transform([text])
            return text_features.toarray()
        except:
            return np.zeros((1, 500))
    
    def create_sample_dataset(self, num_samples=1000):
        np.random.seed(42)
        
        data = []
        labels = []
        
        for i in range(num_samples):
            features = {}
            
            if i < num_samples // 2: 
                features['domain_age_days'] = np.random.randint(365, 3650)
                features['ssl_valid'] = 1
                features['suspicious_tld'] = 0
                features['num_suspicious_patterns'] = np.random.randint(0, 2)
                features['scam_word_count'] = np.random.randint(0, 5)
                features['has_brand_impersonation'] = 0
                features['num_forms'] = np.random.randint(0, 3)
                features['num_password_forms'] = 0
                features['days_to_expiry'] = np.random.randint(100, 500)  
                label = 0
            else: 
                features['domain_age_days'] = np.random.randint(1, 90)
                features['ssl_valid'] = np.random.choice([0, 1], p=[0.7, 0.3])
                features['suspicious_tld'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['num_suspicious_patterns'] = np.random.randint(3, 10)
                features['scam_word_count'] = np.random.randint(10, 50)
                features['has_brand_impersonation'] = np.random.choice([0, 1], p=[0.4, 0.6])
                features['num_forms'] = np.random.randint(1, 5)
                features['num_password_forms'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['days_to_expiry'] = np.random.randint(1, 30)  
                label = 1
            
            for feature in self.structural_features:
                if feature not in features:
                    if 'num_' in feature or 'count' in feature:
                        features[feature] = np.random.randint(0, 10)
                    elif 'has_' in feature:
                        features[feature] = np.random.choice([0, 1])
                    else:
                        features[feature] = np.random.randn()
            
            data.append([features[name] for name in self.structural_features])
            labels.append(label)
        
        return np.array(data), np.array(labels)
    
    def train(self, scan_results=None, labels=None, use_synthetic=True):
        if scan_results and labels:
            X_list = []
            for result in scan_results:
                features = self.extract_features_from_scan(result)
                X_list.append(features.flatten())
            X = np.array(X_list)
            y = np.array(labels)
            
        elif use_synthetic:
            logger.info("Creating synthetic dataset for training...")
            X, y = self.create_sample_dataset(2000)
            
        else:
            raise ValueError("No training data provided")
        
        X_scaled = self.scaler.fit_transform(X)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        logger.info("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        y_pred = self.model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        logger.info(f"Model trained successfully!")
        logger.info(f"Accuracy: {accuracy:.3f}")
        logger.info(f"Precision: {precision:.3f}")
        logger.info(f"Recall: {recall:.3f}")
        logger.info(f"F1 Score: {f1:.3f}")
        
        feature_importance = pd.DataFrame({
            'feature': self.structural_features,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        logger.info("\nTop 10 most important features:")
        for idx, row in feature_importance.head(10).iterrows():
            logger.info(f"  {row['feature']}: {row['importance']:.3f}")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'feature_importance': feature_importance.head(10).to_dict('records')
        }
    
    def predict(self, scan_result: dict) -> dict:
        if self.model is None:
            logger.warning("Model not trained, loading default...")
            self.load_model()
            
            if self.model is None:
                return {
                    'is_malicious': False,
                    'confidence': 0,
                    'probability': 0.5,
                    'warning': 'Model not trained'
                }
        
        try:
            features = self.extract_features_from_scan(scan_result)
            features_scaled = self.scaler.transform(features)
            
            proba = self.model.predict_proba(features_scaled)[0]
            prediction = self.model.predict(features_scaled)[0]
            
            prob_malicious = float(proba[1]) if len(proba) > 1 else float(proba[0])
            confidence = float(max(proba))
            
            important_factors = self._get_important_factors(scan_result)
            
            return {
                'is_malicious': bool(prediction),
                'confidence': confidence,
                'probability_malicious': prob_malicious if len(proba) > 1 else 1 - prob_malicious,
                'probability_safe': float(proba[0]) if len(proba) > 1 else prob_malicious,
                'risk_level': self._compute_risk_level(scan_result, prob_malicious),
                'important_factors': important_factors,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'is_malicious': False,
                'confidence': 0,
                'probability': 0.5,
                'error': str(e)
            }
    
    def _compute_risk_level(self, scan_result, prob_malicious):
        factors = self._get_important_factors(scan_result)
        weight = sum({'low':0.1, 'medium':0.3, 'high':0.5, 'critical':0.7}[f['weight']] for f in factors)
        score = min(prob_malicious + weight, 1.0)
        if score < 0.3:
            return "Low"
        elif score < 0.6:
            return "Medium"
        elif score < 0.8:
            return "High"
        else:
            return "Critical"

    def _get_risk_level(self, probability: float) -> str:
        if probability < 0.3:
            return 'Low'
        elif probability < 0.6:
            return 'Medium'
        elif probability < 0.8:
            return 'High'
        else:
            return 'Critical'
    
    def _get_important_factors(self, scan_result: dict) -> list:
        factors = []
        
        try:
            level1 = scan_result.get('level1', {})
            deep_scan = scan_result.get('deep_scan', {})
            
            if level1.get('ssl_analysis', {}).get('valid') == False:
                factors.append({
                    'factor': 'no_ssl',
                    'description': 'Отсутствует валидный SSL сертификат',
                    'weight': 'high'
                })
            
            whois = level1.get('whois_analysis', {})
            domain_age = whois.get('domain_age_days')
            if domain_age and domain_age < 30:
                factors.append({
                    'factor': 'young_domain',
                    'description': f'Домен создан недавно ({domain_age} дней)',
                    'weight': 'high'
                })
            
            if deep_scan:
                if deep_scan.get('brand_impersonation'):
                    factors.append({
                        'factor': 'brand_impersonation',
                        'description': f"Имитация бренда: {deep_scan['brand_impersonation']}",
                        'weight': 'critical'
                    })
                
                forms = deep_scan.get('form_analysis', [])
                password_forms = [f for f in forms if f.get('has_password')]
                if password_forms:
                    factors.append({
                        'factor': 'password_forms',
                        'description': f"Обнаружено {len(password_forms)} форм с паролями",
                        'weight': 'high'
                    })
                
                suspicious = deep_scan.get('suspicious_patterns', [])
                if suspicious:
                    factors.append({
                        'factor': 'suspicious_patterns',
                        'description': f"Найдено {len(suspicious)} подозрительных паттернов",
                        'weight': 'medium'
                    })
                    
        except Exception as e:
            logger.error(f"Error getting important factors: {e}")
        
        return factors
    
    def predict_batch(self, scan_results: list) -> list:
        predictions = []
        for result in scan_results:
            predictions.append(self.predict(result))
        return predictions
    
    def save_model(self, path=None):
        if path is None:
            path = self.model_path
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'text_vectorizer': self.text_vectorizer,
            'structural_features': self.structural_features,
            'feature_weights': self.feature_weights,
            'timestamp': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")
    
    def load_model(self, path=None):
        if path is None:
            path = self.model_path
        
        if os.path.exists(path):
            try:
                model_data = joblib.load(path)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.text_vectorizer = model_data['text_vectorizer']
                self.structural_features = model_data.get('structural_features', self.structural_features)
                self.feature_weights = model_data.get('feature_weights', self.feature_weights)
                logger.info(f"Model loaded from {path}")
                return True
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                return False
        else:
            logger.warning(f"Model file {path} not found")
            return False
    
    def get_model_info(self) -> dict:
        info = {
            'model_type': type(self.model).__name__ if self.model else 'Not trained',
            'num_features': len(self.structural_features),
            'features': self.structural_features,
            'feature_weights': self.feature_weights
        }
        
        if self.model:
            info['n_classes'] = len(self.model.classes_)
            info['n_estimators'] = self.model.n_estimators if hasattr(self.model, 'n_estimators') else None
        
        return info

ai_model = CyberScanAI()

def analyze(url: str) -> None:
    scanner = CyberScanAI()  
    scan_result = scanner.scan_website(url)  
    prediction = ai_model.predict(scan_result)
    print(prediction)

def train_from_database(db_path='cyberscan.db'):
    import sqlite3
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    c.execute("SELECT result, is_malicious FROM scans WHERE is_malicious IS NOT NULL")
    rows = c.fetchall()
    conn.close()
    
    if len(rows) < 10:
        logger.warning(f"Not enough data in database ({len(rows)} samples), using synthetic data")
        return ai_model.train(use_synthetic=True)
    
    scan_results = []
    labels = []
    
    for result_json, label in rows:
        try:
            result = json.loads(result_json)
            scan_results.append(result)
            labels.append(label)
        except:
            continue
    
    logger.info(f"Training on {len(scan_results)} samples from database")
    return ai_model.train(scan_results, labels)

if __name__ == "__main__":
    print("=" * 50)
    print("CyberScan AI Model Test")
    print("=" * 50)
    
    model = CyberScanAI()
    
    print("\n1. Training on synthetic data...")
    metrics = model.train(use_synthetic=True)
    
    print("\n2. Saving model...")
    model.save_model()
    
    print("\n3. Testing prediction...")
    test_result = {
        'level1': {
            'ssl_analysis': {'valid': True, 'days_until_expiry': 30},
            'whois_analysis': {'domain_age_days': 100},
            'url_analysis': {'suspicious_tld': False}
        },
        'deep_scan': {
            'form_analysis': [],
            'suspicious_patterns': [],
            'brand_impersonation': None,
            'has_redirect': False,
            'content_analysis': {
                'scam_word_count': 0,
                'num_iframes': 0,
                'num_external_links': 0,
                'num_hidden_elements': 0,
                'has_meta_refresh': False
            }
        }
    }
    
    prediction = model.predict(test_result)
    print(f"Prediction: {prediction}")
    
    print("\n✅ AI Model ready!")