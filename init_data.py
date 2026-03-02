import sqlite3
import json
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_illegal_sites():
    """Первичное заполнение базы нелегальных сайтов"""
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS illegal_sites
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT NOT NULL,
                  domain TEXT NOT NULL,
                  category TEXT NOT NULL,
                  source TEXT,
                  risk_score INTEGER DEFAULT 0,
                  first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1,
                  details TEXT,
                  UNIQUE(domain))''')
    
    sample_sites = [
        # Фишинговые
        ('http://paypal-verification-center.com', 'paypal-verification-center.com', 'phishing', 85),
        ('http://apple-id-login.net', 'apple-id-login.net', 'phishing', 90),
        ('http://secure-account-verify.com', 'secure-account-verify.com', 'phishing', 88),
        ('http://bank-of-america-security.com', 'bank-of-america-security.com', 'phishing', 92),
        ('http://amazon-prime-update.net', 'amazon-prime-update.net', 'phishing', 87),
        
        # Казино
        ('http://vulkan-777.com', 'vulkan-777.com', 'casino', 95),
        ('http://joycasino-bonus.top', 'joycasino-bonus.top', 'casino', 94),
        ('http://1xbet-zerkalo.ru', '1xbet-zerkalo.ru', 'casino', 96),
        ('http://pinup-casino.website', 'pinup-casino.website', 'casino', 93),
        ('http://casino-bez-depozita.ru', 'casino-bez-depozita.ru', 'casino', 91),
        ('http://vulkan-platinum.com', 'vulkan-platinum.com', 'casino', 92),
        ('http://azino777.online', 'azino777.online', 'casino', 95),
        
        # Финансовые пирамиды
        ('http://double-your-money.ga', 'double-your-money.ga', 'pyramid', 89),
        ('http://guaranteed-profit.online', 'guaranteed-profit.online', 'pyramid', 88),
        ('http://passive-income.work', 'passive-income.work', 'pyramid', 87),
        ('http://get-rich-quick.trade', 'get-rich-quick.trade', 'pyramid', 90),
        ('http://invest-now.cc', 'invest-now.cc', 'pyramid', 86),
        
        # Вредоносные
        ('http://crypto-bonus.xyz', 'crypto-bonus.xyz', 'crypto_scam', 95),
        ('http://win-iphone.cf', 'win-iphone.cf', 'malware', 94),
        ('http://super-prize.tk', 'super-prize.tk', 'phishing', 92),
        ('http://free-bitcoin.ml', 'free-bitcoin.ml', 'crypto_scam', 96),
        ('http://airdrop-eth.ga', 'airdrop-eth.ga', 'crypto_scam', 93)
    ]
    
    added = 0
    for url, domain, category, risk in sample_sites:
        try:
            c.execute('''INSERT OR IGNORE INTO illegal_sites 
                        (url, domain, category, risk_score, details)
                        VALUES (?, ?, ?, ?, ?)''',
                     (url, domain, category, risk, 
                      json.dumps({
                          'source': 'initial_seed',
                          'confidence': 'high',
                          'detected_at': datetime.now().isoformat()
                      })))
            added += 1
        except Exception as e:
            logger.error(f"Error adding {domain}: {e}")
    
    conn.commit()
    conn.close()
    logger.info(f"✅ Добавлено {added} образцов нелегальных сайтов")

def add_safe_samples():
    """Добавление безопасных сайтов для обучения"""
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    safe_sites = [
        'google.com', 'github.com', 'wikipedia.org', 'youtube.com',
        'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
        'telegram.org', 'whatsapp.com', 'zoom.us', 'spotify.com',
        'adobe.com', 'oracle.com', 'ibm.com', 'salesforce.com',
        'dropbox.com', 'slack.com', 'medium.com', 'quora.com'
    ]
    
    added = 0
    for domain in safe_sites:
        try:
            c.execute('''INSERT OR IGNORE INTO illegal_sites 
                        (url, domain, category, risk_score, details)
                        VALUES (?, ?, ?, ?, ?)''',
                     (f"https://{domain}", domain, 'safe', 5,
                      json.dumps({
                          'source': 'known_safe',
                          'confidence': 'high',
                          'type': 'legitimate'
                      })))
            added += 1
        except Exception as e:
            logger.error(f"Error adding {domain}: {e}")
    
    conn.commit()
    conn.close()
    logger.info(f"✅ Добавлено {added} безопасных сайтов")

def create_training_data():
    """Создание обучающих данных в формате для AI"""
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT NOT NULL,
                  result TEXT NOT NULL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  risk_score INTEGER,
                  is_malicious BOOLEAN)''')
    
    c.execute("SELECT domain, category FROM illegal_sites")
    sites = c.fetchall()
    
    for domain, category in sites:
        is_malicious = 1 if category != 'safe' else 0
        result = {
            'url': f"http://{domain}",
            'level1': {
                'risk_score': 70 if is_malicious else 10,
                'url_analysis': {
                    'url_length': len(domain),
                    'num_dots': domain.count('.'),
                    'num_hyphens': domain.count('-'),
                    'num_digits': sum(c.isdigit() for c in domain),
                    'has_ip': False,
                    'subdomain_count': domain.count('.') - 1,
                    'suspicious_tld': any(tld in domain for tld in ['.xyz', '.top', '.tk', '.ru'])
                }
            },
            'deep_scan': {
                'suspicious_patterns': ['Образец для обучения'] if is_malicious else []
            }
        }
        
        c.execute('''INSERT INTO scans (url, result, risk_score, is_malicious)
                     VALUES (?, ?, ?, ?)''',
                  (f"http://{domain}", json.dumps(result), 
                   70 if is_malicious else 10, is_malicious))
    
    conn.commit()
    conn.close()
    logger.info(f"✅ Создано обучающих примеров: {len(sites)}")

if __name__ == "__main__":
    logger.info("="*50)
    logger.info("🚀 Инициализация данных для обучения")
    logger.info("="*50)
    
    init_illegal_sites()
    add_safe_samples()
    create_training_data()
    
    logger.info("✅ Готово! Теперь можно запустить обучение")