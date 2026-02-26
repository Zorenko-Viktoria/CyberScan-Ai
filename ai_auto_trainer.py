import asyncio
import sqlite3
import json
import logging
from datetime import datetime, timedelta
import numpy as np
from typing import List, Dict, Optional
import time

from ai_model import anti_phishing_ai
from collector import scan_url_async

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AIAutoTrainer:
    """
    Автоматический тренировщик AI модели на данных мониторинга
    """
    
    def __init__(self, db_path='cyberscan.db'):
        self.db_path = db_path
        self.last_train_time = None
        self.training_interval = timedelta(hours=24)  
        self.min_samples_for_train = 200  
        self.is_training = False
        
    async def collect_training_data(self, limit: int = 2000) -> tuple:
        """
        Сбор данных для обучения из БД мониторинга
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("""
            SELECT domain, category, risk_score, first_seen, details 
            FROM illegal_sites 
            WHERE details IS NOT NULL AND details != '{}'
            ORDER BY last_seen DESC
            LIMIT ?
        """, (limit,))
        
        rows = c.fetchall()
        conn.close()
        
        logger.info(f"📊 Collected {len(rows)} sites with details from monitor DB")
        
        scan_results = []
        labels = []
        
        safe_sites = [
            'google.com', 'github.com', 'wikipedia.org', 'youtube.com',
            'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
            'telegram.org', 'whatsapp.com', 'zoom.us', 'spotify.com',
            'adobe.com', 'oracle.com', 'ibm.com', 'salesforce.com',
            'dropbox.com', 'slack.com', 'medium.com', 'quora.com'
        ]
        
        for domain in safe_sites:
            scan_results.append({
                'url': f"https://{domain}",
                'level1': {
                    'risk_score': 10,
                    'url_analysis': {
                        'url_length': len(domain),
                        'num_dots': domain.count('.'),
                        'num_hyphens': domain.count('-'),
                        'num_digits': sum(c.isdigit() for c in domain),
                        'has_ip': False,
                        'subdomain_count': domain.count('.') - 1,
                        'suspicious_tld': False
                    }
                },
                'deep_scan': {
                    'form_analysis': [],
                    'suspicious_patterns': [],
                    'brand_impersonation': None
                }
            })
            labels.append(0) 
        
        for row in rows:
            domain, category, risk_score, first_seen, details_json = row
            
            scan_result = {
                'url': f"http://{domain}",
                'level1': {
                    'risk_score': risk_score,
                    'url_analysis': {
                        'url_length': len(domain),
                        'num_dots': domain.count('.'),
                        'num_hyphens': domain.count('-'),
                        'num_digits': sum(c.isdigit() for c in domain),
                        'has_ip': any(c.isdigit() for c in domain.split('.')),
                        'subdomain_count': domain.count('.') - 1,
                        'suspicious_tld': any(tld in domain for tld in ['.xyz', '.top', '.tk', '.ru'])
                    }
                },
                'deep_scan': json.loads(details_json) if details_json else {}
            }
           
            if category in ['phishing', 'casino', 'pyramid'] or risk_score > 60:
                label = 1 
            else:
                label = 0  
            
            scan_results.append(scan_result)
            labels.append(label)
        
        return scan_results, labels
    
    async def collect_new_sites_for_scanning(self, limit: int = 200):
        """
        Сбор новых сайтов для глубокого сканирования
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("""
            SELECT domain FROM illegal_sites 
            WHERE (details IS NULL OR details = '{}')
            ORDER BY first_seen DESC
            LIMIT ?
        """, (limit,))
        
        domains = [row[0] for row in c.fetchall()]
        conn.close()
        
        if not domains:
            return [], []
        
        logger.info(f"🔍 Deep scanning {len(domains)} new sites for training...")
        
        scan_results = []
        labels = []
        
        for domain in domains:
            try:
                scan_result = await scan_url_async(f"http://{domain}")
                deep_scan = scan_result.get('deep_scan', {})
                
                is_suspicious = (
                    len(deep_scan.get('form_analysis', [])) > 0 or
                    len(deep_scan.get('suspicious_patterns', [])) > 2 or
                    deep_scan.get('brand_impersonation') is not None or
                    deep_scan.get('casino_analysis', {}).get('is_casino', False)
                )
                
                scan_results.append(scan_result)
                labels.append(1 if is_suspicious else 0)
                
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                c.execute("""
                    UPDATE illegal_sites 
                    SET details = ? 
                    WHERE domain = ?
                """, (json.dumps(deep_scan), domain))
                conn.commit()
                conn.close()
                
                logger.debug(f"✅ Scanned {domain}")
                
            except Exception as e:
                logger.error(f"Error scanning {domain}: {e}")
        
        logger.info(f"✅ Deep scanned {len(scan_results)} sites")
        return scan_results, labels
    
    async def auto_train(self, force: bool = False) -> Optional[dict]:
        """
        Автоматическое обучение (запускается по расписанию)
        """
        if self.is_training:
            logger.info("⏳ Training already in progress, skipping...")
            return None
        
        now = datetime.now()
        if not force and self.last_train_time:
            if now - self.last_train_time < self.training_interval:
                logger.info(f"⏰ Next training in {self.training_interval - (now - self.last_train_time)}")
                return None
        
        self.is_training = True
        start_time = time.time()
        
        try:
            logger.info("="*60)
            logger.info("🚀 AUTO AI TRAINING STARTED")
            logger.info("="*60)
            
            existing_results, existing_labels = await self.collect_training_data(limit=2000)
            
            unique_labels = set(existing_labels)
            logger.info(f"📊 Classes in data: {unique_labels}")
            
            if len(unique_labels) < 2:
                logger.warning(f"⚠️ Only one class found: {unique_labels}. Adding synthetic safe sites...")
                
                for i in range(100):
                    existing_results.append({
                        'url': f"https://safe-site-{i}.com",
                        'level1': {
                            'risk_score': 10,
                            'url_analysis': {
                                'url_length': 20,
                                'num_dots': 2,
                                'num_hyphens': 0,
                                'num_digits': 0,
                                'has_ip': False,
                                'subdomain_count': 0,
                                'suspicious_tld': False
                            }
                        },
                        'deep_scan': {}
                    })
                    existing_labels.append(0)
            
            new_results, new_labels = await self.collect_new_sites_for_scanning(limit=200)
            
            all_results = existing_results + new_results
            all_labels = existing_labels + new_labels
            
            final_unique = set(all_labels)
            logger.info(f"📊 Final classes: {final_unique}")
            
            if len(final_unique) < 2:
                logger.error(f"❌ Still only one class after adding data: {final_unique}")
                return None
            
            if len(all_results) < self.min_samples_for_train:
                logger.warning(f"⚠️ Not enough samples: {len(all_results)} < {self.min_samples_for_train}")
                return None
            
            logger.info(f"📊 Training on {len(all_results)} samples ({len(new_results)} new)")
            logger.info(f"   Class distribution: 0:{all_labels.count(0)}, 1:{all_labels.count(1)}")
            
            metrics = anti_phishing_ai.train_anti_phishing(
                scan_results=all_results,
                labels=all_labels,
                use_synthetic=False
            )
            
            anti_phishing_ai.save_model()
            
            self._save_training_metadata(len(all_results), metrics)
            
            elapsed = time.time() - start_time
            logger.info(f"✅ AUTO TRAINING COMPLETE in {elapsed:.1f}s")
            logger.info(f"   Accuracy: {metrics['accuracy']:.3f}")
            logger.info(f"   Samples: {len(all_results)}")
            
            self.last_train_time = now
            return metrics
            
        except Exception as e:
            logger.error(f"❌ Auto training error: {e}")
            return None
        finally:
            self.is_training = False
    
    def _save_training_metadata(self, num_samples: int, metrics: dict):
        """Сохранение метаданных обучения"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS ai_training_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                training_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                num_samples INTEGER,
                accuracy REAL,
                precision REAL,
                recall REAL,
                f1_score REAL,
                model_path TEXT
            )
        """)
        
        c.execute("""
            INSERT INTO ai_training_history 
            (num_samples, accuracy, precision, recall, f1_score, model_path)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            num_samples,
            metrics.get('accuracy', 0),
            metrics.get('precision', 0),
            metrics.get('recall', 0),
            metrics.get('f1', 0),
            anti_phishing_ai.model_path
        ))
        
        conn.commit()
        conn.close()
        logger.info(f"💾 Training metadata saved")
    
    def get_training_stats(self) -> dict:
        """Статистика обучения"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("""
            SELECT training_date, num_samples, accuracy 
            FROM ai_training_history 
            ORDER BY training_date DESC 
            LIMIT 1
        """)
        last = c.fetchone()
        
        c.execute("""
            SELECT 
                COUNT(*) as total,
                AVG(num_samples) as avg_samples,
                AVG(accuracy) as avg_acc,
                MAX(accuracy) as max_acc
            FROM ai_training_history
        """)
        stats = c.fetchone()
        
        conn.close()
        
        return {
            'last_training': last[0] if last else None,
            'last_samples': last[1] if last else 0,
            'last_accuracy': last[2] if last else 0,
            'total_trainings': stats[0] if stats else 0,
            'avg_samples': int(stats[1]) if stats and stats[1] else 0,
            'avg_accuracy': stats[2] if stats and stats[2] else 0,
            'max_accuracy': stats[3] if stats and stats[3] else 0,
            'next_training': (self.last_train_time + self.training_interval).isoformat() if self.last_train_time else None
        }

ai_trainer = AIAutoTrainer()