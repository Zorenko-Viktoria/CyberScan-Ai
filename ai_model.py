import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from bs4 import BeautifulSoup 
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
import joblib
from urllib.parse import urlparse
import json
import os
from datetime import datetime, timedelta
import logging
import warnings
import hashlib
import difflib
from collections import Counter
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AntiPhishingAI:
    """
    Усиленная AI-система для обнаружения фишинга
    с поддержкой браузерного расширения
    """
    
    def __init__(self, model_path='anti_phishing_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = RobustScaler()  
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000, 
            stop_words=['english', 'russian'], 
            ngram_range=(1, 4),  
            analyzer='char_wb', 
            sublinear_tf=True
        )
        
        self.phishing_features = [
            'url_length',
            'num_dots',
            'num_hyphens',
            'num_digits',
            'num_slashes',
            'num_params',
            'has_ip',
            'has_at_symbol',
            'has_double_slash',
            'subdomain_count',
            'suspicious_tld',
            'entropy',  
            'punycode',
            'https_mismatch',
            'port_suspicious', 
            'has_dns',
            'has_mx',
            'has_txt',
            'num_ip_addresses',
            'same_ip_different_domains',
            'domain_resolves',
            'dns_sec',
            'domain_age_days',
            'days_to_expiry',
            'is_private_whois',
            'registrar_reputation',
            'creation_hour', 
            'updated_recently',
            'days_since_update',
            'registrar_country',
            'ssl_valid',
            'ssl_days_until_expiry',
            'ssl_issuer_reputation',
            'self_signed',
            'ssl_version',
            'cert_matches_domain',
            'ssl_grade',
            'num_forms',
            'num_password_forms',
            'num_hidden_inputs',
            'external_form_action',
            'form_action_url_similarity', 
            'num_iframes',
            'num_external_scripts',
            'num_obfuscated_scripts',
            'has_meta_refresh',
            'has_redirect',
            'num_external_links',
            'num_hidden_elements',
            'login_form_count',
            'credit_card_fields',
            'sensitive_keywords_count',
            'title_similarity',
            'logo_present',
            'logo_similarity',
            'color_scheme_match', 
            'layout_similarity',  
            'favicon_match', 
            'brand_mentions', 
            'brand_density', 
            'data_exfiltration_risk',  
            'keylogger_detected',
            'clipboard_access',
            'geolocation_request',
            'camera_mic_request'
        ]
        
        self.brands = {
            'kaspi': {
                'url': 'kaspi.kz',
                'title': 'Kaspi.kz',
                'keywords': ['kaspi', 'магазин', 'оплата', 'кредит'],
                'logo_hash': 'a1b2c3d4...',
                'favicon_hash': 'e5f6g7h8...',
                'color_scheme': ['#f00', '#fff', '#000']
            },
            'paypal': {
                'url': 'paypal.com',
                'title': 'PayPal',
                'keywords': ['paypal', 'payment', 'send money'],
                'logo_hash': 'i9j0k1l2...',
                'favicon_hash': 'm3n4o5p6...',
                'color_scheme': ['#003087', '#009cde', '#fff']
            },
            'halyk': {
                'url': 'halykbank.kz',
                'title': 'Halyk Bank',
                'keywords': ['halyk', 'банк', 'homebank'],
                'logo_hash': 'q7r8s9t0...',
                'favicon_hash': 'u1v2w3x4...',
                'color_scheme': ['#00a651', '#fff', '#000']
            }
        }
        
    def extract_phishing_features(self, scan_result: dict, html_content: str = None) -> np.array:
        """Извлечение расширенных признаков для фишинга"""
        features = {}
        for feature in self.phishing_features:
            features[feature] = 0
        
        try:
            level1 = scan_result.get('level1', {})
            deep_scan = scan_result.get('deep_scan', {})
            url = scan_result.get('url', '')
            url_analysis = level1.get('url_analysis', {})
            features['url_length'] = url_analysis.get('url_length', 0)
            features['num_dots'] = url_analysis.get('num_dots', 0)
            features['num_hyphens'] = url_analysis.get('num_hyphens', 0)
            features['num_digits'] = url_analysis.get('num_digits', 0)
            features['has_ip'] = int(url_analysis.get('has_ip', False))
            parsed = urlparse(url)
            features['num_slashes'] = parsed.path.count('/')
            features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
            features['has_at_symbol'] = int('@' in url)
            features['has_double_slash'] = int('//' in parsed.path)
            features['subdomain_count'] = url_analysis.get('subdomain_count', 0)
            features['suspicious_tld'] = int(url_analysis.get('suspicious_tld', False))
            url_chars = url.lower()
            char_counts = Counter(url_chars)
            total_chars = len(url_chars)
            entropy = -sum((count/total_chars) * np.log2(count/total_chars) 
                          for count in char_counts.values())
            features['entropy'] = entropy
            features['punycode'] = int('xn--' in url)
            dns_analysis = level1.get('dns_analysis', {})
            features['has_dns'] = int(dns_analysis.get('has_dns', False))
            features['has_mx'] = int(dns_analysis.get('has_mx', False))
            features['has_txt'] = int(dns_analysis.get('has_txt', False))
            features['num_ip_addresses'] = len(dns_analysis.get('ip_addresses', []))
            whois_analysis = level1.get('whois_analysis', {})
            domain_age = whois_analysis.get('domain_age_days', -1)
            features['domain_age_days'] = domain_age
            
            if whois_analysis.get('expiration_date'):
                try:
                    exp_date = datetime.fromisoformat(whois_analysis['expiration_date'].replace('Z', '+00:00'))
                    features['days_to_expiry'] = (exp_date - datetime.now()).days
                except:
                    features['days_to_expiry'] = 0
            else:
                features['days_to_expiry'] = 0
            
            features['is_private_whois'] = int(whois_analysis.get('is_private', False))
            
            if whois_analysis.get('creation_date'):
                try:
                    creation = datetime.fromisoformat(whois_analysis['creation_date'].replace('Z', '+00:00'))
                    features['creation_hour'] = creation.hour
                    features['updated_recently'] = int((datetime.now() - creation).days < 7)
                except:
                    features['creation_hour'] = 0
                    features['updated_recently'] = 0
            
            ssl_analysis = level1.get('ssl_analysis', {})
            features['ssl_valid'] = int(ssl_analysis.get('valid', False))
            features['ssl_days_until_expiry'] = ssl_analysis.get('days_until_expiry', -1)
            features['self_signed'] = int(ssl_analysis.get('issuer', '') == 'self-signed')
            
            if deep_scan:
                forms = deep_scan.get('form_analysis', [])
                features['num_forms'] = len(forms)
                features['num_password_forms'] = len([f for f in forms if f.get('has_password')])
                features['num_hidden_inputs'] = sum(f.get('input_types', []).count('hidden') for f in forms)
                
                external_forms = [f for f in forms if f.get('external_action')]
                features['external_form_action'] = len(external_forms)
                
                for form in external_forms:
                    action = form.get('action', '')
                    for brand_name, brand_data in self.brands.items():
                        if brand_data['url'] in action:
                            features['form_action_url_similarity'] = 1
                            break
                
                scripts = deep_scan.get('javascript_analysis', [])
                features['num_external_scripts'] = len([s for s in scripts if s.get('external')])
                features['num_obfuscated_scripts'] = len([s for s in scripts if s.get('has_malicious_patterns')])
                
                content_analysis = deep_scan.get('content_analysis', {})
                features['num_iframes'] = content_analysis.get('num_iframes', 0)
                features['has_meta_refresh'] = int(content_analysis.get('has_meta_refresh', False))
                features['has_redirect'] = int(deep_scan.get('has_redirect', False))
                features['num_hidden_elements'] = content_analysis.get('num_hidden_elements', 0)
                features['num_external_links'] = content_analysis.get('num_external_links', 0)
                
                scam_words = deep_scan.get('suspicious_patterns', [])
                features['sensitive_keywords_count'] = len(scam_words)
                
                if html_content:
                    features.update(self._analyze_visual_similarity(html_content, url))
                
                features.update(self._analyze_behavioral_risks(deep_scan))
            
        except Exception as e:
            logger.error(f"Error extracting phishing features: {e}")
        
        return np.array([features[name] for name in self.phishing_features]).reshape(1, -1)
    
    def _analyze_visual_similarity(self, html: str, url: str) -> dict:
        """Анализ визуального сходства с известными брендами"""
        features = {
            'title_similarity': 0,
            'logo_present': 0,
            'logo_similarity': 0,
            'color_scheme_match': 0,
            'layout_similarity': 0,
            'favicon_match': 0,
            'brand_mentions': 0,
            'brand_density': 0
        }
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            title = soup.find('title')
            if title:
                title_text = title.string.lower() if title.string else ''
                
                for brand_name, brand_data in self.brands.items():
                    if brand_name in title_text:
                        features['brand_mentions'] += 1
                        
                    similarity = difflib.SequenceMatcher(
                        None, 
                        title_text, 
                        brand_data['title'].lower()
                    ).ratio()
                    if similarity > 0.7:
                        features['title_similarity'] = max(features['title_similarity'], similarity)
            
            images = soup.find_all('img')
            for img in images:
                alt = img.get('alt', '').lower()
                src = img.get('src', '')
                
                if any(word in alt for word in ['logo', 'лого']):
                    features['logo_present'] = 1
                    
                    for brand_data in self.brands.values():
                        if brand_data['logo_hash'] in src:
                            features['logo_similarity'] = 1
            
            text = soup.get_text().lower()
            total_words = len(text.split())
            brand_words = sum(1 for brand in self.brands.keys() if brand in text)
            features['brand_density'] = brand_words / max(total_words, 1)
            
        except Exception as e:
            logger.error(f"Visual analysis error: {e}")
        
        return features
    
    def _analyze_behavioral_risks(self, deep_scan: dict) -> dict:
        """Анализ поведенческих рисков (для браузерного расширения)"""
        features = {
            'data_exfiltration_risk': 0,
            'keylogger_detected': 0,
            'clipboard_access': 0,
            'geolocation_request': 0,
            'camera_mic_request': 0
        }
        
        try:
            scripts = deep_scan.get('javascript_analysis', [])
            
            for script in scripts:
                src = script.get('src', '')
                content = str(script)
                
                if 'navigator.sendBeacon' in content or 'XMLHttpRequest' in content:
                    features['data_exfiltration_risk'] = 1
                
                if 'addEventListener' in content and 'keydown' in content:
                    features['keylogger_detected'] = 1
                
                if 'clipboard' in content.lower():
                    features['clipboard_access'] = 1
                
                if 'geolocation' in content.lower():
                    features['geolocation_request'] = 1
                
                if 'getUserMedia' in content or 'enumerateDevices' in content:
                    features['camera_mic_request'] = 1
                    
        except Exception as e:
            logger.error(f"Behavioral analysis error: {e}")
        
        return features
    
    def train_anti_phishing(self, scan_results=None, labels=None, use_synthetic=True):
        """Обучение усиленной антифишинговой модели"""
        
        if scan_results and labels:
            X_list = []
            for result in scan_results:
                features = self.extract_phishing_features(result)
                X_list.append(features.flatten())
            X = np.array(X_list)
            y = np.array(labels)
            
        elif use_synthetic:
            logger.info("Creating enhanced anti-phishing dataset...")
            X, y = self._create_phishing_dataset(5000)
            
        else:
            raise ValueError("No training data provided")
        
        X_scaled = self.scaler.fit_transform(X)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info("Training ensemble of 3 models...")
        
        rf = RandomForestClassifier(
            n_estimators=300,
            max_depth=30,
            min_samples_split=3,
            min_samples_leaf=1,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        
        gb = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=15,
            learning_rate=0.05,
            random_state=42
        )
        
        nn = MLPClassifier(
            hidden_layer_sizes=(100, 50, 25),
            activation='relu',
            solver='adam',
            alpha=0.001,
            batch_size=32,
            learning_rate='adaptive',
            max_iter=500,
            random_state=42
        )
        
        rf.fit(X_train, y_train)
        gb.fit(X_train, y_train)
        nn.fit(X_train, y_train)
        
        self.model = {
            'random_forest': rf,
            'gradient_boosting': gb,
            'neural_network': nn
        }
        

        rf_pred = rf.predict(X_test)
        gb_pred = gb.predict(X_test)
        nn_pred = nn.predict(X_test)
        
        ensemble_pred = np.round((rf_pred + gb_pred + nn_pred) / 3).astype(int)
        
        accuracy = accuracy_score(y_test, ensemble_pred)
        precision = precision_score(y_test, ensemble_pred)
        recall = recall_score(y_test, ensemble_pred)
        f1 = f1_score(y_test, ensemble_pred)
        
        logger.info(f"✅ Ensemble model trained!")
        logger.info(f"Accuracy: {accuracy:.3f}")
        logger.info(f"Precision: {precision:.3f}")
        logger.info(f"Recall: {recall:.3f}")
        logger.info(f"F1 Score: {f1:.3f}")
        
        feature_importance = pd.DataFrame({
            'feature': self.phishing_features,
            'importance': rf.feature_importances_
        }).sort_values('importance', ascending=False)
        
        logger.info("\n🔥 Top 15 anti-phishing features:")
        for idx, row in feature_importance.head(15).iterrows():
            logger.info(f"  {row['feature']}: {row['importance']:.3f}")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'feature_importance': feature_importance.head(15).to_dict('records')
        }
    
    def predict_phishing(self, scan_result: dict, html_content: str = None) -> dict:
        """Предсказание с расширенным анализом"""
        
        if self.model is None:
            logger.warning("Model not trained, loading default...")
            self.load_model()
        
        try:
            features = self.extract_phishing_features(scan_result, html_content)
            features_scaled = self.scaler.transform(features)
            rf_prob = self.model['random_forest'].predict_proba(features_scaled)[0]
            gb_prob = self.model['gradient_boosting'].predict_proba(features_scaled)[0]
            nn_prob = self.model['neural_network'].predict_proba(features_scaled)[0]
            avg_prob = (rf_prob + gb_prob + nn_prob) / 3
            rf_pred = self.model['random_forest'].predict(features_scaled)[0]
            gb_pred = self.model['gradient_boosting'].predict(features_scaled)[0]
            nn_pred = self.model['neural_network'].predict(features_scaled)[0]
            votes = rf_pred + gb_pred + nn_pred
            is_phishing = votes >= 2
            
            confidence = float(max(avg_prob))
            risk_factors = self._analyze_risk_factors(scan_result, html_content)
            
            return {
                'is_phishing': bool(is_phishing),
                'confidence': confidence,
                'probability': float(avg_prob[1]) if len(avg_prob) > 1 else float(avg_prob[0]),
                'risk_factors': risk_factors,
                'model_votes': {
                    'random_forest': bool(rf_pred),
                    'gradient_boosting': bool(gb_pred),
                    'neural_network': bool(nn_pred)
                },
                'phishing_score': int(confidence * 100),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'is_phishing': False,
                'confidence': 0,
                'error': str(e)
            }
    
    def _analyze_risk_factors(self, scan_result: dict, html_content: str) -> list:
        """Детальный анализ факторов риска"""
        factors = []
        
        try:
            level1 = scan_result.get('level1', {})
            deep_scan = scan_result.get('deep_scan', {})
            url = scan_result.get('url', '')
            
            ssl = level1.get('ssl_analysis', {})
            if not ssl.get('valid'):
                factors.append({
                    'factor': 'no_ssl',
                    'description': 'Нет валидного SSL сертификата',
                    'risk': 'high'
                })
            elif ssl.get('days_until_expiry', 999) < 7:
                factors.append({
                    'factor': 'ssl_expiring',
                    'description': 'SSL сертификат скоро истекает',
                    'risk': 'medium'
                })
            
            whois = level1.get('whois_analysis', {})
            domain_age = whois.get('domain_age_days')
            if domain_age and domain_age < 7:
                factors.append({
                    'factor': 'very_young_domain',
                    'description': f'Домен создан {domain_age} дней назад',
                    'risk': 'critical'
                })
            elif domain_age and domain_age < 30:
                factors.append({
                    'factor': 'young_domain',
                    'description': f'Домен создан {domain_age} дней назад',
                    'risk': 'high'
                })
            
            if '.xyz' in url or '.top' in url or '.tk' in url:
                factors.append({
                    'factor': 'suspicious_tld',
                    'description': 'Подозрительная доменная зона',
                    'risk': 'medium'
                })
            
            forms = deep_scan.get('form_analysis', [])
            password_forms = [f for f in forms if f.get('has_password')]
            
            for form in password_forms:
                if form.get('external_action'):
                    factors.append({
                        'factor': 'external_password_form',
                        'description': f"Пароль уходит на {form.get('action')}",
                        'risk': 'critical'
                    })
            
            if html_content:
                soup = BeautifulSoup(html_content, 'html.parser')
                title = soup.find('title')
                if title:
                    title_text = title.string.lower() if title.string else ''
                    for brand in ['kaspi', 'paypal', 'halyk']:
                        if brand in title_text and brand not in url:
                            factors.append({
                                'factor': 'brand_impersonation',
                                'description': f'Имитация бренда {brand}',
                                'risk': 'critical'
                            })
            
        except Exception as e:
            logger.error(f"Risk analysis error: {e}")
        
        return factors
    
    def _create_phishing_dataset(self, num_samples=5000):
        """Создание расширенного датасета для фишинга"""
        np.random.seed(42)
        
        data = []
        labels = []
        
        for i in range(num_samples):
            features = {}
            
            is_phishing = np.random.choice([0, 1], p=[0.5, 0.5])
            
            if is_phishing:
                features['domain_age_days'] = np.random.randint(1, 30)
                features['ssl_valid'] = np.random.choice([0, 1], p=[0.7, 0.3])
                features['suspicious_tld'] = np.random.choice([0, 1], p=[0.2, 0.8])
                features['num_suspicious_patterns'] = np.random.poisson(8)
                features['num_password_forms'] = np.random.choice([0, 1, 2], p=[0.1, 0.6, 0.3])
                features['external_form_action'] = np.random.choice([0, 1], p=[0.1, 0.9])
                features['has_ip'] = np.random.choice([0, 1], p=[0.6, 0.4])
                features['num_digits'] = np.random.poisson(6)
                features['entropy'] = np.random.uniform(3.5, 5.0)
                features['title_similarity'] = np.random.uniform(0.7, 0.95)
                features['brand_mentions'] = np.random.randint(1, 5)
                label = 1
                
            else:
                features['domain_age_days'] = np.random.randint(365, 3650)
                features['ssl_valid'] = np.random.choice([1], p=[1.0])
                features['suspicious_tld'] = 0
                features['num_suspicious_patterns'] = np.random.poisson(0.5)
                features['num_password_forms'] = np.random.choice([0, 1], p=[0.8, 0.2])
                features['external_form_action'] = 0
                features['has_ip'] = 0
                features['num_digits'] = np.random.poisson(2)
                features['entropy'] = np.random.uniform(2.0, 3.2)
                features['title_similarity'] = np.random.uniform(0.1, 0.3)
                features['brand_mentions'] = np.random.randint(0, 2)
                label = 0
            
            for feature in self.phishing_features:
                if feature not in features:
                    if 'num_' in feature or 'count' in feature:
                        features[feature] = np.random.poisson(1)
                    elif 'has_' in feature:
                        features[feature] = np.random.choice([0, 1])
                    else:
                        features[feature] = np.random.randn() * 0.5
            
            data.append([features[name] for name in self.phishing_features])
            labels.append(label)
        
        return np.array(data), np.array(labels)
    
    def save_model(self, path=None):
        """Сохранение модели"""
        if path is None:
            path = self.model_path
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'text_vectorizer': self.text_vectorizer,
            'phishing_features': self.phishing_features,
            'brands': self.brands,
            'timestamp': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, path)
        logger.info(f"Anti-phishing model saved to {path}")
    
    def load_model(self, path=None):
        """Загрузка модели"""
        if path is None:
            path = self.model_path
        
        if os.path.exists(path):
            try:
                model_data = joblib.load(path)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.text_vectorizer = model_data['text_vectorizer']
                self.phishing_features = model_data.get('phishing_features', self.phishing_features)
                self.brands = model_data.get('brands', self.brands)
                logger.info(f"Anti-phishing model loaded from {path}")
                return True
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                return False
        else:
            logger.warning(f"Model file {path} not found")
            return False

class CyberScanAI:
    """
    Класс-обертка для совместимости со старым кодом
    """
    def __init__(self, model_path='cyberscan_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.structural_features = [
            'url_length', 'num_dots', 'num_hyphens', 'num_digits', 'has_ip',
            'subdomain_count', 'suspicious_tld', 'path_length', 'num_query_params',
            'special_chars_count', 'has_dns', 'has_mx', 'num_ip_addresses',
            'num_ns_servers', 'domain_age_days', 'is_private_whois', 'days_to_expiry',
            'ssl_valid', 'ssl_days_until_expiry', 'num_forms', 'num_password_forms',
            'num_external_scripts', 'num_external_resources', 'scam_word_count',
            'has_brand_impersonation', 'num_suspicious_patterns', 'num_iframes',
            'has_meta_refresh', 'has_redirect', 'num_hidden_elements', 'num_external_links',
            'casino_keywords_count', 'has_casino_in_url', 'casino_confidence_score'
        ]
        
    def load_model(self):
        """Загрузка модели"""
        result = anti_phishing_ai.load_model()
        if result:
            logger.info("✅ CyberScanAI model loaded via AntiPhishingAI")
        else:
            logger.info("🔄 Creating synthetic model for CyberScanAI...")
            anti_phishing_ai.train_anti_phishing(use_synthetic=True)
            anti_phishing_ai.save_model()
            logger.info("✅ Synthetic CyberScanAI model created")
        return True
        
    def predict(self, scan_result: dict) -> dict:
        """Предсказание через AntiPhishingAI"""
        html_content = None
        if 'deep_scan' in scan_result:
            html_content = scan_result['deep_scan'].get('html_content')
            
        return anti_phishing_ai.predict_phishing(scan_result, html_content)
    
    def train(self, features=None, labels=None):
        """Обучение модели (используй train_anti_phishing)"""
        logger.info("Training via CyberScanAI - use train_anti_phishing instead")
        return {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0}
    
    def save_model(self, path=None):
        """Сохранение модели"""
        anti_phishing_ai.save_model(path or self.model_path)

anti_phishing_ai = AntiPhishingAI()
cyberscan_ai = CyberScanAI()
