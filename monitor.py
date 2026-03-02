import asyncio
import aiohttp
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import sqlite3
import json
import logging
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse
import csv
from io import StringIO
from collections import defaultdict
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CyberScanMonitor:
    """Автоматический мониторинг и отслеживание нелегальных сайтов"""
    
    def __init__(self, db_path='cyberscan.db'):
        self.db_path = db_path
        
        self.max_domains_per_cycle = 1000  
        self.parallel_workers = 20         
        self.cache_ttl = timedelta(minutes=5)  
        self.cache = {}
        self.session = None
        
        self.sources = [

            {
                'name': 'openphish',
                'url': 'https://openphish.com/feed.txt',
                'type': 'phishing',
                'parser': 'plain_list',
                'priority': 1,
                'cache_ttl': 60  
            },
            {
                'name': 'urlhaus',
                'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
                'type': 'malware',
                'parser': 'csv',
                'priority': 1,
                'cache_ttl': 60
            },
            {
                'name': 'phishing_database',
                'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
                'type': 'phishing',
                'parser': 'plain_list',
                'priority': 1,
                'cache_ttl': 300
            },
            

            {
                'name': 'stevenblack_gambling',
                'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts',
                'type': 'casino',
                'parser': 'hosts_file',
                'priority': 1,
                'cache_ttl': 300
            },
            {
                'name': 'stopgambling',
                'url': 'https://raw.githubusercontent.com/StopGambling/domain-list/main/domains.txt',
                'type': 'casino',
                'parser': 'plain_list',
                'priority': 1,
                'cache_ttl': 300
            },
            {
                'name': 'ut1_gambling',
                'url': 'https://dsi.ut-capitole.fr/blacklists/download/gambling.tar.gz',
                'type': 'casino',
                'parser': 'tar_gz',
                'priority': 2,
                'cache_ttl': 3600
            },
            {
                'name': 'oisd_gambling',
                'url': 'https://big.oisd.nl/',
                'type': 'casino',
                'parser': 'domain_list',
                'priority': 1,
                'cache_ttl': 300
            },
            

            {
                'name': 'feodo_tracker',
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
                'type': 'malware',
                'parser': 'csv',
                'priority': 2,
                'cache_ttl': 3600
            },
            {
                'name': 'ssl_blacklist',
                'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
                'type': 'malware',
                'parser': 'csv',
                'priority': 2,
                'cache_ttl': 3600
            },
            

            {
                'name': 'pirate_blocklist',
                'url': 'https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt',
                'type': 'piracy',
                'parser': 'plain_list',
                'priority': 2,
                'cache_ttl': 3600
            },
            

            {
                'name': 'krebs_rss',
                'url': 'https://krebsonsecurity.com/feed/',
                'type': 'security_news',
                'parser': 'rss',
                'priority': 3,
                'cache_ttl': 600
            },
            {
                'name': 'bleepingcomputer_rss',
                'url': 'https://www.bleepingcomputer.com/feed/',
                'type': 'security_news',
                'parser': 'rss',
                'priority': 3,
                'cache_ttl': 600
            }
        ]
        
        self.categories = {
            'casino': {
                'keywords': ['casino', 'казино', 'vulkan', '1xbet', 'joycasino', 'pinup', 'bet', 'poker', 'slot'],
                'weight': 0.9
            },
            'phishing': {
                'keywords': ['login', 'verify', 'account', 'secure', 'bank', 'paypal', 'apple', 'microsoft'],
                'weight': 1.0
            },
            'pyramid': {
                'keywords': ['invest', 'profit', 'return', 'guaranteed', 'double', 'bonus', 'mlm'],
                'weight': 0.85
            },
            'malware': {
                'keywords': ['update', 'flash', 'plugin', 'codec', 'crack', 'keygen'],
                'weight': 0.9
            },
            'piracy': {
                'keywords': ['torrent', 'magnet', 'thepiratebay', 'rutor', 'nnmclub', 'kino'],
                'weight': 0.7
            },
            'adult': {
                'keywords': ['porn', 'xxx', 'sex', 'adult', 'onlyfans'],
                'weight': 0.6
            }
        }
        
        self.init_monitor_db()
    
    def init_monitor_db(self):
        """Инициализация базы данных"""
        conn = sqlite3.connect(self.db_path)
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
        

        c.execute('''CREATE TABLE IF NOT EXISTS source_stats
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  source_name TEXT,
                  scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                  domains_count INTEGER,
                  source_type TEXT,
                  response_time REAL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS fetch_cache
                 (url TEXT PRIMARY KEY,
                  data TEXT,
                  fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        

        c.execute('CREATE INDEX IF NOT EXISTS idx_illegal_domain ON illegal_sites(domain)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_illegal_category ON illegal_sites(category)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_illegal_last_seen ON illegal_sites(last_seen)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_cache_fetched ON fetch_cache(fetched_at)')
        
        conn.commit()
        conn.close()
        logger.info("✅ Monitor database initialized")

    def get_statistics(self) -> Dict:
        """Получение статистики по нелегальным сайтам"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        stats = {
            'total': 0,
            'by_category': {},
            'new_today': 0,
            'active_last_hour': 0
        }
        
        c.execute("SELECT COUNT(*) FROM illegal_sites")
        stats['total'] = c.fetchone()[0]
        
        c.execute("SELECT category, COUNT(*) FROM illegal_sites GROUP BY category")
        for row in c.fetchall():
            stats['by_category'][row[0]] = row[1]
        
        c.execute("SELECT COUNT(*) FROM illegal_sites WHERE date(first_seen) = date('now')")
        stats['new_today'] = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM illegal_sites WHERE last_seen > datetime('now', '-1 hour')")
        stats['active_last_hour'] = c.fetchone()[0]
        
        conn.close()
        return stats

    def get_illegal_sites(self, category: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Получение списка нелегальных сайтов"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        query = "SELECT * FROM illegal_sites"
        params = []
        
        if category:
            query += " WHERE category = ?"
            params.append(category)
        
        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, params)
        
        sites = []
        for row in c.fetchall():
            sites.append({
                'id': row[0],
                'url': row[1],
                'domain': row[2],
                'category': row[3],
                'source': row[4],
                'risk_score': row[5],
                'first_seen': row[6],
                'last_seen': row[7],
                'is_active': bool(row[8]),
                'details': json.loads(row[9]) if row[9] else {}
            })
        
        conn.close()
        return sites

    
    async def parse_plain_list(self, content: str) -> List[str]:
        """Парсинг простого списка доменов"""
        domains = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if ' ' in line:
                    line = line.split()[0]
                line = line.replace('http://', '').replace('https://', '').split('/')[0]
                if line and '.' in line and len(line) < 100:
                    domains.append(line.lower())
        return list(set(domains))
    
    async def parse_csv(self, content: str) -> List[str]:
        """Парсинг CSV"""
        domains = []
        try:
            f = StringIO(content)
            reader = csv.reader(f)
            for row in reader:
                if row and len(row) > 0:
                    for col in row[:3]:
                        if 'http' in col:
                            domain = col.replace('http://', '').replace('https://', '').split('/')[0]
                            if domain and '.' in domain:
                                domains.append(domain.lower())
                            break
                        elif '.' in col and len(col) < 100 and ' ' not in col:
                            domains.append(col.lower())
                            break
        except:
            pass
        return list(set(domains))
    
    async def parse_hosts_file(self, content: str) -> List[str]:
        """Парсинг hosts файлов"""
        domains = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ['0.0.0.0', '127.0.0.1']:
                    domain = parts[1].strip()
                    if domain and '.' in domain:
                        domains.append(domain.lower())
        return list(set(domains))
    
    async def parse_tar_gz(self, content: bytes) -> List[str]:
        """Парсинг tar.gz архивов"""
        import tarfile
        import io
        domains = []
        try:
            tar = tarfile.open(fileobj=io.BytesIO(content))
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith('.txt'):
                    f = tar.extractfile(member)
                    if f:
                        file_content = f.read().decode('utf-8', errors='ignore')
                        for line in file_content.split('\n'):
                            line = line.strip()
                            if line and '.' in line and not line.startswith('#'):
                                domains.append(line.lower())
        except:
            pass
        return list(set(domains))
    
    async def parse_rss(self, content: str) -> List[str]:
        """Парсинг RSS фидов"""
        domains = []
        try:
            soup = BeautifulSoup(content, 'xml')
            for link in soup.find_all('link'):
                if link.text and 'http' in link.text:
                    domain = link.text.replace('http://', '').replace('https://', '').split('/')[0]
                    if domain and '.' in domain:
                        domains.append(domain.lower())
        except:
            pass
        return list(set(domains))
 
    
    async def get_cached_or_fetch(self, source: Dict) -> List[str]:
        """Получение данных с кэшированием"""
        cache_key = f"{source['name']}_{source['url']}"
        cache_ttl = source.get('cache_ttl', 300)  
        
        if cache_key in self.cache:
            cached_time, cached_data = self.cache[cache_key]
            if (datetime.now() - cached_time).total_seconds() < cache_ttl:
                logger.info(f"📦 Cache HIT: {source['name']}")
                return cached_data
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT data, fetched_at FROM fetch_cache WHERE url = ?", (source['url'],))
        row = c.fetchone()
        
        if row:
            fetched_at = datetime.fromisoformat(row[1])
            if (datetime.now() - fetched_at).total_seconds() < cache_ttl:
                logger.info(f"💾 Database Cache HIT: {source['name']}")
                data = json.loads(row[0])
                conn.close()
                return data
        
        logger.info(f"🌐 Fetching: {source['name']}")
        start_time = time.time()
        domains = await self._fetch_source_real(source)
        response_time = time.time() - start_time
        
        self.cache[cache_key] = (datetime.now(), domains)
        
        c.execute("INSERT OR REPLACE INTO fetch_cache (url, data, fetched_at) VALUES (?, ?, ?)",
                 (source['url'], json.dumps(domains), datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Fetched {source['name']}: {len(domains)} domains in {response_time:.2f}s")
        return domains
    
    async def _fetch_source_real(self, source: Dict) -> List[str]:
        """Реальная загрузка данных из источника"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; CyberScanMonitor/1.0)'}
            
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(source['url'], timeout=30, ssl=False) as response:
                    if response.status == 200:
                        if source['parser'] == 'plain_list':
                            content = await response.text()
                            return await self.parse_plain_list(content)
                        elif source['parser'] == 'csv':
                            content = await response.text()
                            return await self.parse_csv(content)
                        elif source['parser'] == 'hosts_file':
                            content = await response.text()
                            return await self.parse_hosts_file(content)
                        elif source['parser'] == 'tar_gz':
                            content = await response.read()
                            return await self.parse_tar_gz(content)
                        elif source['parser'] == 'rss':
                            content = await response.text()
                            return await self.parse_rss(content)
                        elif source['parser'] == 'domain_list':
                            content = await response.text()
                            return await self.parse_plain_list(content)
                        else:
                            content = await response.text()
                            return await self.parse_plain_list(content)
                    else:
                        logger.warning(f"⚠️ {source['name']} returned {response.status}")
                        return []
        except Exception as e:
            logger.warning(f"⚠️ Error {source['name']}: {e}")
            return []
    
    def _determine_category_from_domain(self, domain: str) -> str:
        """Определение категории по домену"""
        domain_lower = domain.lower()
        
        for category, data in self.categories.items():
            for keyword in data['keywords']:
                if keyword in domain_lower:
                    return category
        
        return 'suspicious'
    
    
    async def process_domain_batch(self, domains: List[str]) -> Dict:
        """Пакетная обработка доменов"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        categories_found = set()
        new_sites = 0
        updated_sites = 0
        
        for domain in domains:
            try:
                c.execute("SELECT id FROM illegal_sites WHERE domain = ?", (domain,))
                existing = c.fetchone()
                
                if existing:
                    c.execute("UPDATE illegal_sites SET last_seen = datetime('now') WHERE domain = ?", (domain,))
                    updated_sites += 1
                else:
                    category = self._determine_category_from_domain(domain)
                    c.execute('''INSERT INTO illegal_sites 
                                (url, domain, category, risk_score, last_seen, details)
                                VALUES (?, ?, ?, ?, datetime('now'), ?)''',
                            (f"http://{domain}", domain, category, 
                             70, json.dumps({'source': 'monitor', 'auto_detected': True})))
                    new_sites += 1
                    categories_found.add(category)
                    
            except Exception as e:
                logger.error(f"Error processing {domain}: {e}")
        
        conn.commit()
        conn.close()
        
        return {
            'new': new_sites,
            'updated': updated_sites,
            'categories': categories_found
        }
    
    async def worker(self, queue: asyncio.Queue, results: List):
        """Воркер для параллельной обработки"""
        while True:
            try:
                batch = await queue.get()
                if batch is None:
                    break
                
                result = await self.process_domain_batch(batch)
                results.append(result)
                
            except Exception as e:
                logger.error(f"Worker error: {e}")
            finally:
                queue.task_done()
    
    
    async def quick_scan(self):
        """Быстрое сканирование (каждую минуту) - только приоритетные источники"""
        logger.info("="*50)
        logger.info("🚀 БЫСТРЫЙ ЦИКЛ СКАНИРОВАНИЯ")
        logger.info("="*50)
        
        all_domains = []
        sources_stats = {}
        
        priority_sources = [s for s in self.sources if s['priority'] == 1]
        
        for source in priority_sources:
            domains = await self.get_cached_or_fetch(source)
            
            if domains:
                unique_count = len(set(domains))
                all_domains.extend(domains)
                
                sources_stats[source['name']] = {
                    'count': unique_count,
                    'type': source['type']
                }
                
                logger.info(f"✓ {source['name']}: {unique_count} доменов")
        
        all_domains = list(set(all_domains))
        logger.info(f"📊 ВСЕГО УНИКАЛЬНЫХ: {len(all_domains)}")
        
        sites_to_process = all_domains[:self.max_domains_per_cycle]
        
        batch_size = 50
        batches = [sites_to_process[i:i+batch_size] for i in range(0, len(sites_to_process), batch_size)]
        

        queue = asyncio.Queue()
        results = []
        
        for batch in batches:
            await queue.put(batch)
        
        workers = []
        for _ in range(min(self.parallel_workers, len(batches))):
            task = asyncio.create_task(self.worker(queue, results))
            workers.append(task)
        
        await queue.join()
        
        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers)
        

        total_new = sum(r['new'] for r in results)
        total_updated = sum(r['updated'] for r in results)
        all_categories = set()
        for r in results:
            all_categories.update(r['categories'])
        
        logger.info("="*50)
        logger.info(f"✅ БЫСТРЫЙ ЦИКЛ ЗАВЕРШЕН:")
        logger.info(f"📌 Новых: {total_new}")
        logger.info(f"🔄 Обновлено: {total_updated}")
        logger.info(f"🏷️ Категории: {all_categories}")
        logger.info("="*50)
        
        return {
            'new': total_new,
            'updated': total_updated,
            'categories': list(all_categories)
        }
    
    async def full_scan(self):
        """Полное сканирование (каждый час) - все источники"""
        logger.info("="*50)
        logger.info("🔬 ПОЛНЫЙ ЦИКЛ СКАНИРОВАНИЯ")
        logger.info("="*50)
        
        all_domains = []
        sources_stats = {}
        
        for source in self.sources:
            domains = await self.get_cached_or_fetch(source)
            
            if domains:
                unique_count = len(set(domains))
                all_domains.extend(domains)
                
                sources_stats[source['name']] = {
                    'count': unique_count,
                    'type': source['type']
                }
                
                logger.info(f"✓ {source['name']}: {unique_count} доменов")
        
        all_domains = list(set(all_domains))
        logger.info(f"📊 ВСЕГО УНИКАЛЬНЫХ: {len(all_domains)}")
        

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for source_name, stats in sources_stats.items():
            c.execute('''INSERT INTO source_stats (source_name, domains_count, source_type)
                         VALUES (?, ?, ?)''',
                      (source_name, stats['count'], stats['type']))
        conn.commit()
        conn.close()
        

        sites_to_process = all_domains[:5000]
        

        batch_size = 50
        batches = [sites_to_process[i:i+batch_size] for i in range(0, len(sites_to_process), batch_size)]
        

        queue = asyncio.Queue()
        results = []
        
        for batch in batches:
            await queue.put(batch)
        
        workers = []
        for _ in range(min(self.parallel_workers, len(batches))):
            task = asyncio.create_task(self.worker(queue, results))
            workers.append(task)
        
        await queue.join()
        
        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers)
        

        total_new = sum(r['new'] for r in results)
        total_updated = sum(r['updated'] for r in results)
        all_categories = set()
        for r in results:
            all_categories.update(r['categories'])
        
        logger.info("="*50)
        logger.info(f"✅ ПОЛНЫЙ ЦИКЛ ЗАВЕРШЕН:")
        logger.info(f"📌 Новых: {total_new}")
        logger.info(f"🔄 Обновлено: {total_updated}")
        logger.info(f"🏷️ Категории: {all_categories}")
        logger.info("="*50)
    
    
    async def start_realtime_monitoring(self):
        """Запуск мониторинга в реальном времени"""
        logger.info("🚀 РЕАЛЬНОЕ ВРЕМЯ: МОНИТОРИНГ ЗАПУЩЕН")
        logger.info("⚡ Быстрый цикл: каждую минуту")
        logger.info("🔬 Полный цикл: каждый час")
        
        quick_counter = 0
        
        while True:
            try:
                start_time = time.time()
                

                await self.quick_scan()
                
                quick_counter += 1
                
                if quick_counter >= 60: 
                    await self.full_scan()
                    quick_counter = 0
                
                elapsed = time.time() - start_time
                wait_time = max(60 - elapsed, 1) 
                
                logger.info(f"⏱️ Цикл выполнен за {elapsed:.2f}с. Следующий через {wait_time:.0f}с")
                await asyncio.sleep(wait_time)
                
            except Exception as e:
                logger.error(f"❌ Ошибка в цикле: {e}")
                await asyncio.sleep(10)  

monitor = CyberScanMonitor()

async def start_monitor_background():
    """Запуск монитора в фоне"""
    logger.info("🔄 Фоновый мониторинг в реальном времени активирован")
    await monitor.start_realtime_monitoring()
