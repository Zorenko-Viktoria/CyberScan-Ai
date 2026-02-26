import asyncio
import sqlite3
import json
import logging
from datetime import datetime, timedelta
import numpy as np
from typing import List, Dict, Optional
import time
import os
from collections import defaultdict
import threading
from queue import Queue

from ai_model import CyberScanAI
from collector import scan_url_async

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AIAutoTrainer:
    """
    Автоматическое обучение AI модели на реальных данных
    Объединяет AI модель и автоматический сбор данных
    """
    
    def __init__(self, db_path='cyberscan.db', model_path='cyberscan_model.pkl'):
        self.db_path = db_path
        self.model_path = model_path
        self.ai_model = CyberScanAI(model_path)
        
        
        self.last_train_time = None
        self.training_interval = timedelta(hours=24) 
        self.min_samples_for_train = 200 
        self.is_training = False
        
        self.training_stats = {
            'total_trainings': 0,
            'last_accuracy': 0,
            'total_samples': 0,
            'errors': []
        }
        
        
        self._load_existing_model()
    
    def _load_existing_model(self):
        """Загрузка существующей модели"""
        if os.path.exists(self.model_path):
            try:
                self.ai_model.load_model()
                logger.info(f"✅ Модель загружена из {self.model_path}")
            except Exception as e:
                logger.warning(f"⚠️ Не удалось загрузить модель: {e}")
    
    async def collect_training_data(self, limit: int = 1000) -> tuple:
        """
        Сбор данных для обучения из БД
        Возвращает (scan_results, labels)
        """
        logger.info(f"📊 Сбор данных для обучения (макс: {limit})")
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
      
        c.execute("""
            SELECT domain, category, risk_score, details, first_seen
            FROM illegal_sites 
            WHERE details IS NOT NULL AND details != '{}' AND details != ''
            ORDER BY last_seen DESC
            LIMIT ?
        """, (limit,))
        
        malicious_rows = c.fetchall()
        
     
        c.execute("""
            SELECT url, result FROM scans 
            WHERE is_malicious = 0 
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        safe_rows = c.fetchall()
        
       
        c.execute("""
            SELECT url, result FROM scans 
            WHERE is_malicious IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit * 2,))
        
        user_scans = c.fetchall()
        
        conn.close()
        
        scan_results = []
        labels = []
        

        for domain, category, risk_score, details_json, first_seen in malicious_rows:
            try:
                details = json.loads(details_json) if details_json else {}
                scan_result = {
                    'url': f"http://{domain}",
                    'level1': {
                        'risk_score': risk_score,
                        'whois_analysis': {'domain_age_days': self._calculate_age(first_seen)},
                        'url_analysis': self._extract_url_features(domain)
                    },
                    'deep_scan': details
                }
                scan_results.append(scan_result)
              
                is_malicious = 1 if category in ['phishing', 'casino', 'malware', 'pyramid'] or risk_score > 60 else 0
                labels.append(is_malicious)
            except Exception as e:
                logger.debug(f"Ошибка обработки опасного сайта: {e}")
        
       
        for url, result_json in safe_rows:
            try:
                scan_result = json.loads(result_json) if result_json else {'url': url}
                scan_results.append(scan_result)
                labels.append(0)
            except Exception as e:
                logger.debug(f"Ошибка обработки безопасного сайта: {e}")
        
        
        url_seen = set()
        for url, result_json in user_scans:
            if url in url_seen:
                continue
            url_seen.add(url)
            
            try:
                scan_result = json.loads(result_json) if result_json else {'url': url}
                
                is_malicious = 1 if 'is_malicious' in scan_result and scan_result['is_malicious'] else 0
                scan_results.append(scan_result)
                labels.append(is_malicious)
            except Exception as e:
                logger.debug(f"Ошибка обработки пользовательского скана: {e}")
        
        logger.info(f"📊 Собрано данных: {len(scan_results)} образцов")
        logger.info(f"   Опасных: {sum(labels)} | Безопасных: {len(labels) - sum(labels)}")
        
        return scan_results, labels
    
    def _calculate_age(self, date_str) -> int:
        """Расчет возраста домена в днях"""
        try:
            if isinstance(date_str, str):
                date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                return (datetime.now() - date).days
        except:
            pass
        return np.random.randint(30, 365) 
    
    def _extract_url_features(self, domain: str) -> dict:
        """Извлечение базовых признаков URL"""
        return {
            'url_length': len(domain),
            'num_dots': domain.count('.'),
            'num_hyphens': domain.count('-'),
            'num_digits': sum(c.isdigit() for c in domain),
            'has_ip': 0,
            'subdomain_count': len(domain.split('.')) - 2,
            'suspicious_tld': domain.endswith(('.xyz', '.top', '.club', '.online'))
        }
    
    async def auto_train(self, force: bool = False) -> Optional[dict]:
        """
        Автоматическое обучение модели
        Запускается раз в training_interval
        """
    
        if self.is_training:
            logger.warning("⚠️ Обучение уже выполняется")
            return None
        
   
        now = datetime.now()
        if not force and self.last_train_time:
            if now - self.last_train_time < self.training_interval:
                time_left = self.training_interval - (now - self.last_train_time)
                logger.info(f"⏳ Следующее обучение через {time_left}")
                return None
        
        self.is_training = True
        start_time = time.time()
        
        try:
            logger.info("="*60)
            logger.info("🚀 ЗАПУСК АВТОМАТИЧЕСКОГО ОБУЧЕНИЯ")
            logger.info("="*60)
            
           
            scan_results, labels = await self.collect_training_data(limit=2000)
            
            if len(scan_results) < self.min_samples_for_train:
                logger.warning(f"⚠️ Недостаточно данных: {len(scan_results)} < {self.min_samples_for_train}")
                
               
                if len(scan_results) > 50:
                    logger.info("➕ Добавляем синтетические данные...")
                    synthetic_ratio = max(0.5, 1 - len(scan_results) / self.min_samples_for_train)
                    metrics = self.ai_model.train(
                        scan_results=scan_results,
                        labels=labels,
                        use_synthetic=True,
                        synthetic_ratio=synthetic_ratio
                    )
                else:
                   
                    logger.info("🔄 Используем только синтетические данные")
                    metrics = self.ai_model.train(use_synthetic=True)
            else:
               
                logger.info(f"✅ Обучаем на {len(scan_results)} реальных образцах")
                metrics = self.ai_model.train(
                    scan_results=scan_results,
                    labels=labels,
                    use_synthetic=False
                )
            
            
            self.ai_model.save_model()
            
            
            training_time = time.time() - start_time
            self.last_train_time = now
            self.training_stats['total_trainings'] += 1
            self.training_stats['last_accuracy'] = metrics.get('accuracy', 0)
            self.training_stats['total_samples'] += len(scan_results)
            
            logger.info("="*60)
            logger.info(f"✅ ОБУЧЕНИЕ ЗАВЕРШЕНО за {training_time:.1f}с")
            logger.info(f"📊 Точность: {metrics.get('accuracy', 0):.3f}")
            logger.info(f"📈 Всего обучений: {self.training_stats['total_trainings']}")
            logger.info("="*60)
            
            return {
                **metrics,
                'training_time': training_time,
                'samples_used': len(scan_results),
                'training_time': now.isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Ошибка обучения: {e}")
            self.training_stats['errors'].append({
                'time': now.isoformat(),
                'error': str(e)
            })
            return None
            
        finally:
            self.is_training = False
    
    async def incremental_update(self, new_scan_result: dict, label: int):
        """
        Инкрементальное обновление модели новым образцом
        """
      
        logger.debug(f"📝 Новый образец для обучения: {new_scan_result.get('url')} -> {label}")
        
     
        if self.last_train_time:
            time_since_train = datetime.now() - self.last_train_time
            if time_since_train > self.training_interval / 2:
              
                asyncio.create_task(self.auto_train())
    
    def get_training_status(self) -> dict:
        """Статус обучения"""
        status = {
            'is_training': self.is_training,
            'last_train': self.last_train_time.isoformat() if self.last_train_time else None,
            'next_train': (self.last_train_time + self.training_interval).isoformat() if self.last_train_time else None,
            'training_interval_hours': self.training_interval.total_seconds() / 3600,
            'min_samples': self.min_samples_for_train,
            'stats': self.training_stats,
            'model_info': self.ai_model.get_model_info()
        }
        return status
    
    async def force_train(self) -> dict:
        """Принудительное обучение"""
        logger.info("⚡ Принудительное обучение")
        return await self.auto_train(force=True)



class BackgroundTrainer:
    """Фоновый тренер для периодического обучения"""
    
    def __init__(self, trainer: AIAutoTrainer, check_interval: int = 3600):
        self.trainer = trainer
        self.check_interval = check_interval  
        self.running = False
        self.thread = None
    
    def start(self):
        """Запуск фонового обучения"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info(f"🔄 Фоновый тренер запущен (проверка каждые {self.check_interval}с)")
    
    def stop(self):
        """Остановка фонового обучения"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("⏹️ Фоновый тренер остановлен")
    
    def _run(self):
        """Основной цикл фонового обучения"""
        import asyncio
        
        while self.running:
            try:
               
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
        
                loop.run_until_complete(self.trainer.auto_train())
                
                loop.close()
                
            except Exception as e:
                logger.error(f"Ошибка в фоновом тренере: {e}")
            
           
            time.sleep(self.check_interval)



ai_trainer = AIAutoTrainer()
background_trainer = BackgroundTrainer(ai_trainer)


async def auto_train_background():
    """Запуск автоматического обучения в фоне (asyncio версия)"""
    logger.info("🔄 Автоматическое обучение запущено")
    
    while True:
        try:
            await ai_trainer.auto_train()
            
            
            await asyncio.sleep(1800)
            
        except Exception as e:
            logger.error(f"Ошибка в фоновом обучении: {e}")
            await asyncio.sleep(300)  



def init_auto_trainer():
    """Инициализация авто-тренера при старте"""
   
    ai_trainer._load_existing_model()
    
    
    background_trainer.start()
    
    logger.info("✅ Авто-тренер инициализирован")



if __name__ == "__main__":
    print("="*60)
    print("🤖 AI AUTO TRAINER")
    print("="*60)
    
    trainer = AIAutoTrainer()
    
   
    print("\n📊 Статус до обучения:")
    status = trainer.get_training_status()
    print(json.dumps(status, indent=2, default=str))
    
    
    print("\n🚀 Запуск обучения...")
    metrics = asyncio.run(trainer.force_train())
    
    if metrics:
        print("\n✅ Результаты обучения:")
        print(f"   Точность: {metrics.get('accuracy', 0):.3f}")
        print(f"   Precision: {metrics.get('precision', 0):.3f}")
        print(f"   Recall: {metrics.get('recall', 0):.3f}")
        print(f"   F1: {metrics.get('f1', 0):.3f}")
    
 
    print("\n📊 Статус после обучения:")
    status = trainer.get_training_status()
    print(json.dumps(status, indent=2, default=str))
    
    print("\n✅ Авто-тренер готов!")
