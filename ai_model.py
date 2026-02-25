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
            'num_external_links',
            
            'casino_keywords_count',
            'has_casino_in_url',
            'casino_confidence_score'
        ]
        
        self.feature_weights = {
            'structural': 0.3,
            'text': 0.3,
            'behavioral': 0.4
        }
        

        self.casino_keywords = [
            'казино', 'casino', 'вулкан', 'vulkan', 'pin up', 'пин ап',
            'joycasino', 'joy casino', 'mostbet', '1xbet', '1xslots',
            'слоты', 'slots', 'рулетка', 'roulette', 'блэкджек', 'blackjack',
            'покер', 'poker', 'бонус за регистрацию', 'бездепозитный бонус',
            'фриспины', 'free spins', 'джекпот', 'jackpot', 'казино онлайн',
            'online casino', 'best casino', 'top casino', 'casino online',
            'vulkan casino', 'вулкан казино', 'игровые автоматы', 'игровые аппараты'
        ]
        
        self.casino_brands = [
            'vulkan', 'вулкан', 'joycasino', 'joy casino', '1xbet', 'mostbet',
            'pinup', 'pin up', 'azino', 'азино', 'казино', 'casino'
        ]


    def extract_features_from_scan(self, scan_result: dict) -> np.array:
        """Извлечение признаков из результата сканирования"""
        features = {}
        
        for feature in self.structural_features:
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
            
            if whois_analysis.get('expiration_date'):
                try:
                    exp_date = datetime.fromisoformat(whois_analysis['expiration_date'].replace('Z', '+00:00'))
                    features['days_to_expiry'] = (exp_date - datetime.now()).days
                except:
                    features['days_to_expiry'] = 0
            else:
                features['days_to_expiry'] = 0
            
            ssl_analysis = level1.get('ssl_analysis', {})
            features['ssl_valid'] = int(ssl_analysis.get('valid', False))
            features['ssl_days_until_expiry'] = ssl_analysis.get('days_until_expiry', -1)
            
            url_lower = url.lower()
            features['has_casino_in_url'] = int(any(brand in url_lower for brand in self.casino_brands))
            
            casino_keywords_count = 0
            
            if deep_scan:
                forms = deep_scan.get('form_analysis', [])
                features['num_forms'] = len(forms)
                features['num_password_forms'] = len([f for f in forms if f.get('has_password')])
                
                scripts = deep_scan.get('javascript_analysis', [])
                features['num_external_scripts'] = len([s for s in scripts if s.get('external')])
                
                features['num_external_resources'] = len(deep_scan.get('external_resources', []))
                
                content_analysis = deep_scan.get('content_analysis', {})
                features['scam_word_count'] = content_analysis.get('scam_word_count', 0)
                
                features['has_brand_impersonation'] = int(deep_scan.get('brand_impersonation') is not None)
                features['num_suspicious_patterns'] = len(deep_scan.get('suspicious_patterns', []))
                
                features['num_iframes'] = content_analysis.get('num_iframes', 0)
                features['has_meta_refresh'] = int(content_analysis.get('has_meta_refresh', False))
                features['has_redirect'] = int(deep_scan.get('has_redirect', False))
                features['num_hidden_elements'] = content_analysis.get('num_hidden_elements', 0)
                features['num_external_links'] = content_analysis.get('num_external_links', 0)
                
                casino_analysis = deep_scan.get('casino_analysis', {})
                if casino_analysis.get('is_casino'):
                    casino_keywords_count = len(casino_analysis.get('indicators', []))
                    
                    confidence = casino_analysis.get('confidence', 'low')
                    if confidence == 'high':
                        features['casino_confidence_score'] = 3
                    elif confidence == 'medium':
                        features['casino_confidence_score'] = 2
                    else:
                        features['casino_confidence_score'] = 1
            
            features['casino_keywords_count'] = casino_keywords_count
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
        
        feature_values = [features[name] for name in self.structural_features]
        
        return np.array(feature_values).reshape(1, -1)
    
    def extract_text_features(self, html_content: str) -> np.array:
        """Извлечение текстовых признаков"""
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
        """Создание синтетического датасета для обучения с учетом казино"""
        np.random.seed(42)
        
        data = []
        labels = []
        
        for i in range(num_samples):
            features = {}
            
            site_type = np.random.choice(['safe', 'suspicious', 'malicious', 'casino'], p=[0.3, 0.3, 0.2, 0.2])
            
            features['casino_keywords_count'] = 0
            features['has_casino_in_url'] = 0
            features['casino_confidence_score'] = 0
            
            if site_type == 'safe':
                features['domain_age_days'] = np.random.randint(365, 3650)
                features['ssl_valid'] = 1
                features['suspicious_tld'] = 0
                features['num_suspicious_patterns'] = np.random.poisson(0.5)
                features['scam_word_count'] = np.random.poisson(2)
                features['has_brand_impersonation'] = 0
                features['num_forms'] = np.random.poisson(1)
                features['num_password_forms'] = 0
                features['days_to_expiry'] = np.random.randint(100, 500)
                features['has_ip'] = 0
                features['num_digits'] = np.random.poisson(2)
                features['num_external_scripts'] = np.random.poisson(3)
                features['num_external_resources'] = np.random.poisson(5)
                features['num_iframes'] = 0
                features['has_meta_refresh'] = 0
                features['has_redirect'] = 0
                features['num_hidden_elements'] = np.random.poisson(1)
                features['num_external_links'] = np.random.poisson(10)
                label = 0
                
            elif site_type == 'suspicious':
                features['domain_age_days'] = np.random.randint(30, 180)
                features['ssl_valid'] = np.random.choice([0, 1], p=[0.4, 0.6])
                features['suspicious_tld'] = np.random.choice([0, 1], p=[0.6, 0.4])
                features['num_suspicious_patterns'] = np.random.poisson(3)
                features['scam_word_count'] = np.random.poisson(8)
                features['has_brand_impersonation'] = np.random.choice([0, 1], p=[0.7, 0.3])
                features['num_forms'] = np.random.poisson(2)
                features['num_password_forms'] = np.random.choice([0, 1], p=[0.5, 0.5])
                features['days_to_expiry'] = np.random.randint(30, 100)
                features['has_ip'] = np.random.choice([0, 1], p=[0.9, 0.1])
                features['num_digits'] = np.random.poisson(4)
                features['num_external_scripts'] = np.random.poisson(6)
                features['num_external_resources'] = np.random.poisson(10)
                features['num_iframes'] = np.random.poisson(1)
                features['has_meta_refresh'] = np.random.choice([0, 1], p=[0.8, 0.2])
                features['has_redirect'] = np.random.choice([0, 1], p=[0.7, 0.3])
                features['num_hidden_elements'] = np.random.poisson(3)
                features['num_external_links'] = np.random.poisson(20)
                label = 1
                
            elif site_type == 'casino':
                features['domain_age_days'] = np.random.randint(1, 60)
                features['ssl_valid'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['suspicious_tld'] = np.random.choice([0, 1], p=[0.4, 0.6])
                features['num_suspicious_patterns'] = np.random.poisson(5)
                features['scam_word_count'] = np.random.poisson(15)
                features['has_brand_impersonation'] = np.random.choice([0, 1], p=[0.5, 0.5])
                features['num_forms'] = np.random.poisson(3)
                features['num_password_forms'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['days_to_expiry'] = np.random.randint(1, 60)
                features['has_ip'] = np.random.choice([0, 1], p=[0.8, 0.2])
                features['num_digits'] = np.random.poisson(5)
                features['num_external_scripts'] = np.random.poisson(8)
                features['num_external_resources'] = np.random.poisson(12)
                features['num_iframes'] = np.random.poisson(2)
                features['has_meta_refresh'] = np.random.choice([0, 1], p=[0.6, 0.4])
                features['has_redirect'] = np.random.choice([0, 1], p=[0.6, 0.4])
                features['num_hidden_elements'] = np.random.poisson(4)
                features['num_external_links'] = np.random.poisson(25)
                
                features['casino_keywords_count'] = np.random.randint(3, 15)
                features['has_casino_in_url'] = np.random.choice([0, 1], p=[0.2, 0.8])
                features['casino_confidence_score'] = np.random.choice([1, 2, 3], p=[0.2, 0.3, 0.5])
                label = 1
                
            else: 
                features['domain_age_days'] = np.random.randint(1, 30)
                features['ssl_valid'] = np.random.choice([0, 1], p=[0.8, 0.2])
                features['suspicious_tld'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['num_suspicious_patterns'] = np.random.poisson(8)
                features['scam_word_count'] = np.random.poisson(20)
                features['has_brand_impersonation'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['num_forms'] = np.random.poisson(3)
                features['num_password_forms'] = np.random.choice([0, 1], p=[0.2, 0.8])
                features['days_to_expiry'] = np.random.randint(1, 30)
                features['has_ip'] = np.random.choice([0, 1], p=[0.7, 0.3])
                features['num_digits'] = np.random.poisson(6)
                features['num_external_scripts'] = np.random.poisson(10)
                features['num_external_resources'] = np.random.poisson(15)
                features['num_iframes'] = np.random.poisson(3)
                features['has_meta_refresh'] = np.random.choice([0, 1], p=[0.5, 0.5])
                features['has_redirect'] = np.random.choice([0, 1], p=[0.5, 0.5])
                features['num_hidden_elements'] = np.random.poisson(5)
                features['num_external_links'] = np.random.poisson(30)
                features['casino_keywords_count'] = np.random.poisson(1)
                features['has_casino_in_url'] = np.random.choice([0, 1], p=[0.7, 0.3])
                features['casino_confidence_score'] = np.random.choice([0, 1], p=[0.7, 0.3])
                label = 1
            
            for feature in self.structural_features:
                if feature not in features:
                    if 'num_' in feature or 'count' in feature:
                        features[feature] = np.random.poisson(1)
                    elif 'has_' in feature:
                        features[feature] = np.random.choice([0, 1])
                    else:
                        features[feature] = np.random.randn() * 0.5
            
            data.append([features[name] for name in self.structural_features])
            labels.append(label)
        
        return np.array(data), np.array(labels)
    
    def train(self, scan_results=None, labels=None, use_synthetic=True):
        """Обучение модели"""
        if scan_results and labels:
            X_list = []
            for result in scan_results:
                features = self.extract_features_from_scan(result)
                X_list.append(features.flatten())
            X = np.array(X_list)
            y = np.array(labels)
            
        elif use_synthetic:
            logger.info("Creating enhanced synthetic dataset with casino detection...")
            X, y = self.create_sample_dataset(3000) 
            
        else:
            raise ValueError("No training data provided")
        
        X_scaled = self.scaler.fit_transform(X)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        logger.info("Training Random Forest model with casino detection...")
        self.model = RandomForestClassifier(
            n_estimators=250,  
            max_depth=25,
            min_samples_split=4,
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
        
        logger.info("\nTop 15 most important features:")
        for idx, row in feature_importance.head(15).iterrows():
            importance_pct = row['importance'] * 100
            logger.info(f"  {row['feature']}: {importance_pct:.1f}%")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'feature_importance': feature_importance.head(15).to_dict('records')
        }
    
    def predict(self, scan_result: dict) -> dict:
        """Предсказание для одного результата сканирования"""
        if self.model is None:
            logger.warning("Model not trained, loading default...")
            self.load_model()
            
            if self.model is None:
                return {
                    'is_malicious': False,
                    'confidence': 0,
                    'probability_malicious': 0.5,
                    'probability_safe': 0.5,
                    'risk_level': 'Unknown',
                    'important_factors': [],
                    'warning': 'Model not trained'
                }
        
        try:
            features = self.extract_features_from_scan(scan_result)
            features_scaled = self.scaler.transform(features)
            
            proba = self.model.predict_proba(features_scaled)[0]
            prediction = self.model.predict(features_scaled)[0]
            
            if len(proba) > 1:
                prob_malicious = float(proba[1])
                prob_safe = float(proba[0])
            else:
                prob_malicious = float(proba[0])
                prob_safe = 1 - prob_malicious
            
            confidence = float(max(proba))
            
            important_factors = self._get_important_factors(scan_result)
            
            return {
                'is_malicious': bool(prediction),
                'confidence': confidence,
                'probability_malicious': prob_malicious,
                'probability_safe': prob_safe,
                'risk_level': self._compute_risk_level(scan_result, prob_malicious),
                'important_factors': important_factors,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'is_malicious': False,
                'confidence': 0,
                'probability_malicious': 0.5,
                'probability_safe': 0.5,
                'risk_level': 'Error',
                'important_factors': [],
                'error': str(e)
            }
    
    def _compute_risk_level(self, scan_result, prob_malicious):
        """Вычисление уровня риска"""
        factors = self._get_important_factors(scan_result)
        
        weight_map = {'low': 0.1, 'medium': 0.2, 'high': 0.3, 'critical': 0.4}
        total_weight = sum(weight_map.get(f.get('weight', 'low'), 0.1) for f in factors)
        
        deep_scan = scan_result.get('deep_scan', {})
        casino_analysis = deep_scan.get('casino_analysis', {})
        if casino_analysis.get('is_casino'):
            casino_conf = casino_analysis.get('confidence', 'low')
            if casino_conf == 'high':
                total_weight += 0.3
            elif casino_conf == 'medium':
                total_weight += 0.2
            else:
                total_weight += 0.1
        
        score = min(prob_malicious + total_weight, 1.0)
        
        if score < 0.2:
            return "Very Low"
        elif score < 0.4:
            return "Low"
        elif score < 0.6:
            return "Medium"
        elif score < 0.8:
            return "High"
        else:
            return "Critical"

    def _get_important_factors(self, scan_result: dict) -> list:
        """Получение важных факторов для объяснения"""
        factors = []
        
        try:
            level1 = scan_result.get('level1', {})
            deep_scan = scan_result.get('deep_scan', {})
            
            # SSL проверка
            ssl = level1.get('ssl_analysis', {})
            if not ssl.get('valid'):
                factors.append({
                    'factor': 'no_ssl',
                    'description': 'Отсутствует валидный SSL сертификат',
                    'weight': 'high'
                })
            elif ssl.get('days_until_expiry', 999) < 7:
                factors.append({
                    'factor': 'ssl_expiring',
                    'description': 'SSL сертификат скоро истекает',
                    'weight': 'medium'
                })
            
            # WHOIS анализ
            whois = level1.get('whois_analysis', {})
            domain_age = whois.get('domain_age_days')
            if domain_age:
                if domain_age < 7:
                    factors.append({
                        'factor': 'very_young_domain',
                        'description': f'Домен создан {domain_age} дней назад (очень свежий)',
                        'weight': 'critical'
                    })
                elif domain_age < 30:
                    factors.append({
                        'factor': 'young_domain',
                        'description': f'Домен создан {domain_age} дней назад',
                        'weight': 'high'
                    })
                elif domain_age < 90:
                    factors.append({
                        'factor': 'relatively_new_domain',
                        'description': f'Домену меньше 3 месяцев ({domain_age} дней)',
                        'weight': 'medium'
                    })
            
            # Приватный WHOIS
            if whois.get('is_private'):
                factors.append({
                    'factor': 'private_whois',
                    'description': 'Приватная регистрация WHOIS',
                    'weight': 'low'
                })
            
            # DNS анализ
            dns = level1.get('dns_analysis', {})
            if not dns.get('has_dns'):
                factors.append({
                    'factor': 'no_dns',
                    'description': 'Домен не резолвится',
                    'weight': 'critical'
                })
            elif not dns.get('has_mx'):
                factors.append({
                    'factor': 'no_mx',
                    'description': 'Нет MX записей',
                    'weight': 'medium'
                })
            
            # URL анализ
            url_analysis = level1.get('url_analysis', {})
            if url_analysis.get('has_ip'):
                factors.append({
                    'factor': 'ip_in_url',
                    'description': 'URL содержит IP-адрес вместо домена',
                    'weight': 'high'
                })
            if url_analysis.get('suspicious_tld'):
                factors.append({
                    'factor': 'suspicious_tld',
                    'description': 'Подозрительная доменная зона',
                    'weight': 'high'
                })
            if url_analysis.get('url_length', 0) > 100:
                factors.append({
                    'factor': 'long_url',
                    'description': 'Необычно длинный URL',
                    'weight': 'medium'
                })
            
            # Глубокий анализ
            if deep_scan:
                # Имитация бренда
                if deep_scan.get('brand_impersonation'):
                    factors.append({
                        'factor': 'brand_impersonation',
                        'description': f"Имитация бренда: {deep_scan['brand_impersonation']}",
                        'weight': 'critical'
                    })
                
                # Формы
                forms = deep_scan.get('form_analysis', [])
                password_forms = [f for f in forms if f.get('has_password')]
                if password_forms:
                    external_forms = [f for f in password_forms if f.get('external_action')]
                    if external_forms:
                        factors.append({
                            'factor': 'external_password_forms',
                            'description': f"Формы с паролями отправляются на внешние домены",
                            'weight': 'critical'
                        })
                    else:
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
                
                casino_analysis = deep_scan.get('casino_analysis', {})
                if casino_analysis.get('is_casino'):
                    casino_conf = casino_analysis.get('confidence', 'low')
                    indicators = casino_analysis.get('indicators', [])
                    
                    if casino_conf == 'high':
                        weight = 'critical'
                        desc = f"🎰 ОНЛАЙН-КАЗИНО (высокая уверенность)"
                    elif casino_conf == 'medium':
                        weight = 'high'
                        desc = f"🎰 Подозрение на онлайн-казино"
                    else:
                        weight = 'medium'
                        desc = f"🎰 Возможные признаки казино"
                    
                    if indicators:
                        desc += f": {', '.join(indicators[:3])}"
                    
                    factors.append({
                        'factor': 'casino_detected',
                        'description': desc,
                        'weight': weight
                    })
                
                url = scan_result.get('url', '').lower()
                for brand in self.casino_brands:
                    if brand in url and brand not in [f.get('description', '') for f in factors]:
                        factors.append({
                            'factor': 'casino_in_url',
                            'description': f"URL содержит признак казино: '{brand}'",
                            'weight': 'medium'
                        })
                        break
                    
        except Exception as e:
            logger.error(f"Error getting important factors: {e}")
        
        if not factors:
            factors.append({
                'factor': 'normal_site',
                'description': 'Сайт не содержит явных признаков угрозы',
                'weight': 'low'
            })
        
        return factors
    
    def predict_batch(self, scan_results: list) -> list:
        """Пакетное предсказание"""
        predictions = []
        for result in scan_results:
            predictions.append(self.predict(result))
        return predictions
    
    def save_model(self, path=None):
        """Сохранение модели"""
        if path is None:
            path = self.model_path
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'text_vectorizer': self.text_vectorizer,
            'structural_features': self.structural_features,
            'feature_weights': self.feature_weights,
            'casino_keywords': self.casino_keywords,
            'casino_brands': self.casino_brands,
            'timestamp': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")
    
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
                self.structural_features = model_data.get('structural_features', self.structural_features)
                self.feature_weights = model_data.get('feature_weights', self.feature_weights)
                self.casino_keywords = model_data.get('casino_keywords', self.casino_keywords)
                self.casino_brands = model_data.get('casino_brands', self.casino_brands)
                logger.info(f"Model loaded from {path}")
                return True
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                return False
        else:
            logger.warning(f"Model file {path} not found")
            return False
    
    def get_model_info(self) -> dict:
        """Информация о модели"""
        info = {
            'model_type': type(self.model).__name__ if self.model else 'Not trained',
            'num_features': len(self.structural_features),
            'features': self.structural_features[:10],
            'feature_weights': self.feature_weights,
            'casino_detection_enabled': True,
            'casino_keywords_count': len(self.casino_keywords)
        }
        
        if self.model:
            info['n_classes'] = len(self.model.classes_)
            info['n_estimators'] = self.model.n_estimators if hasattr(self.model, 'n_estimators') else None
        
        return info

ai_model = CyberScanAI()

def analyze(url: str) -> None:
    """Анализ одного URL (для тестирования)"""
    from collector import scan_url_async
    import asyncio
    
    scan_result = asyncio.run(scan_url_async(url))
    prediction = ai_model.predict(scan_result)
    print(json.dumps(prediction, indent=2, ensure_ascii=False))

def train_from_database(db_path='cyberscan.db'):
    """Обучение из базы данных"""
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
    print("=" * 60)
    print("CyberScan AI Model with Casino Detection")
    print("=" * 60)
    
    model = CyberScanAI()
    
    print("\n1. Training on enhanced synthetic data with casino detection...")
    metrics = model.train(use_synthetic=True)
    
    print("\n2. Saving model...")
    model.save_model()
    
    print("\n3. Testing prediction on safe site...")
    test_result_safe = {
        'url': 'https://google.com',
        'level1': {
            'ssl_analysis': {'valid': True, 'days_until_expiry': 30},
            'whois_analysis': {'domain_age_days': 8500, 'expiration_date': (datetime.now().replace(year=datetime.now().year + 1)).isoformat()},
            'url_analysis': {'suspicious_tld': False, 'has_ip': False, 'url_length': 22},
            'dns_analysis': {'has_dns': True, 'has_mx': True, 'ip_addresses': ['1.1.1.1']}
        },
        'deep_scan': {
            'form_analysis': [],
            'suspicious_patterns': [],
            'brand_impersonation': None,
            'has_redirect': False,
            'casino_analysis': {'is_casino': False},
            'content_analysis': {
                'scam_word_count': 0,
                'num_iframes': 0,
                'num_external_links': 5,
                'num_hidden_elements': 0,
                'has_meta_refresh': False
            }
        }
    }
    
    prediction_safe = model.predict(test_result_safe)
    print(f"Safe site prediction: {json.dumps(prediction_safe, indent=2, ensure_ascii=False)}")
    
    print("\n4. Testing prediction on casino site...")
    test_result_casino = {
        'url': 'http://vulkan-casino-777.com',
        'level1': {
            'ssl_analysis': {'valid': False, 'days_until_expiry': -1},
            'whois_analysis': {'domain_age_days': 5, 'is_private': True},
            'url_analysis': {'suspicious_tld': True, 'has_ip': False, 'url_length': 35},
            'dns_analysis': {'has_dns': True, 'has_mx': False, 'ip_addresses': []}
        },
        'deep_scan': {
            'form_analysis': [{'has_password': True, 'external_action': True}],
            'suspicious_patterns': ['Подозрительное слово: casino', 'Подозрительное слово: бонус'],
            'brand_impersonation': None,
            'has_redirect': True,
            'casino_analysis': {
                'is_casino': True, 
                'confidence': 'high', 
                'indicators': ['vulkan', 'казино', 'бонус', 'слоты', 'джекпот']
            },
            'content_analysis': {
                'scam_word_count': 25,
                'num_iframes': 3,
                'num_external_links': 30,
                'num_hidden_elements': 5,
                'has_meta_refresh': True
            }
        }
    }
    
    prediction_casino = model.predict(test_result_casino)
    print(f"Casino site prediction: {json.dumps(prediction_casino, indent=2, ensure_ascii=False)}")

    print("\n5. Model info:")
    info = model.get_model_info()
    print(json.dumps(info, indent=2, default=str))
    
    print("\n✅ Enhanced AI Model with Casino Detection ready!") 
