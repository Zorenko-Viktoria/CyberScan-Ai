import asyncio
import aiohttp
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import sqlite3
import json
import logging
from typing import List, Dict, Optional, Set, Tuple
import re
from urllib.parse import urlparse
import csv
from io import StringIO
from collections import defaultdict
import time
import hashlib
import zlib
from contextlib import asynccontextmanager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CyberScanMonitor:
    """Автоматический мониторинг и отслеживание нелегальных сайтов"""
    
    def __init__(self, db_path='cyberscan.db'):
        self.db_path = db_path
        
        
        self.max_domains_per_cycle = 750  # Компромисс между 500 и 1000
        self.parallel_workers = 15        # Компромисс между 10 и 20
        self.cache_ttl = timedelta(minutes=7)  # 7 минут кэш
        self.cache = {}
        self.session = None
        self.connection_pool = None
        
        
        self.stats = {
            'total_fetched': 0,
            'total_errors': 0,
            'avg_response_time': 0,
            'sources_performance': {},
            'start_time': datetime.now()
        }
        
      
        self.sources = [
            
            {
                'name': 'openphish',
                'url': 'https://openphish.com/feed.txt',
                'type': 'phishing',
                'parser': 'plain_list',
                'priority': 1,
                'cache_ttl': 300,  
                'enabled': True,
                'timeout': 30
            },
            {
                'name': 'urlhaus',
                'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
                'type': 'malware',
                'parser': 'csv',
                'priority': 1,
                'cache_ttl': 300,
                'enabled': True,
                'timeout': 30
            },
            {
                'name': 'phishing_database',
                'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
                'type': 'phishing',
                'parser': 'plain_list',
                'priority': 1,
                'cache_ttl': 3600,  
                'enabled': True,
                'timeout': 60
            },
            
            
            {
                'name': 'stevenblack_gambling',
                'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts',
                'type': 'casino',
                'parser': 'hosts_file',
                'priority': 1,
                'cache_ttl': 3600,
                'enabled': True,
                'timeout': 30
            },
            {
                'name': 'stopgambling',
                'url': 'https://raw.githubusercontent.com/StopGambling/domain-list/main/domains.txt',
                'type': 'casino',
                'parser': 'plain_list',
                'priority': 1,
                'cache_ttl': 3600,
                'enabled': True,
                'timeout': 30
            },
            {
                'name': 'oisd_gambling',
                'url': 'https://big.oisd.nl/',
                'type': 'casino',
                'parser': 'plain_list',
                'priority': 1,
                'cache_ttl': 3600,
                'enabled': True,
                'timeout': 60
            },
            
            
            {
                'name': 'ut1_gambling',
                'url': 'https://dsi.ut-capitole.fr/blacklists/download/gambling.tar.gz',
                'type': 'casino',
                'parser': 'tar_gz',
                'priority': 2,
                'cache_ttl': 86400,  
                'enabled': True,
                'timeout': 120
            },
            {
                'name': 'feodo_tracker',
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
                'type': 'malware',
                'parser': 'csv',
                'priority': 2,
                'cache_ttl': 86400,
                'enabled': True,
                'timeout': 30
            },
            {
                'name': 'ssl_blacklist',
                'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
                'type': 'malware',
                'parser': 'csv',
                'priority': 2,
                'cache_ttl': 86400,
                'enabled': True,
                'timeout': 30
            },
            {
                'name': 'pirate_blocklist',
                'url': 'https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt',
                'type': 'piracy',
                'parser': 'plain_list',
                'priority': 2,
                'cache_ttl': 86400,
                'enabled': True,
                'timeout': 30
            },
            
           
            {
                'name': 'krebs_rss',
                'url': 'https://krebsonsecurity.com/feed/',
                'type': 'security_news',
                'parser': 'rss',
                'priority': 3,
                'cache_ttl': 3600,
                'enabled': True,
                'timeout': 30
            },
            {
                'name': 'bleepingcomputer_rss',
                'url': 'https://www.bleepingcomputer.com/feed/',
                'type': 'security_news',
                'parser': 'rss',
                'priority': 3,
                'cache_ttl': 3600,
                'enabled': True,
                'timeout': 30
            }
        ]
        
        
        self.categories = {
            'casino': {
                'keywords': ['casino', 'казино', 'vulkan', '1xbet', 'joycasino', 'pinup', 'bet', 'poker', 'slot', 'gambling'],
                'weight': 0.9,
                'risk_base': 85
            },
            'phishing': {
                'keywords': ['login', 'verify', 'account', 'secure', 'bank', 'paypal', 'apple', 'microsoft', 'amazon'],
                'weight': 1.0,
                'risk_base': 95
            },
            'pyramid': {
                'keywords': ['invest', 'profit', 'return', 'guaranteed', 'double', 'bonus', 'mlm', 'forex', 'binary'],
                'weight': 0.85,
                'risk_base': 80
            },
            'malware': {
                'keywords': ['update', 'flash', 'plugin', 'codec', 'crack', 'keygen', 'download'],
                'weight': 0.9,
                'risk_base': 90
            },
            'piracy': {
                'keywords': ['torrent', 'magnet', 'thepiratebay', 'rutor', 'nnmclub', 'kino', 'film', 'series'],
                'weight': 0.7,
                'risk_base': 70
            },
            'adult': {
                'keywords': ['porn', 'xxx', 'sex', 'adult', 'onlyfans', 'cam'],
                'weight': 0.6,
                'risk_base': 60
            },
            'suspicious': {
                'keywords': [],
                'weight': 0.5,
                'risk_base': 50
            }
        }
        
        self.init_monitor_db()
    
    def init_monitor_db(self):
        """Инициализация базы данных с оптимизированной структурой"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        
        c.execute('''CREATE TABLE IF NOT EXISTS illegal_sites
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT NOT NULL,
                  domain TEXT NOT NULL UNIQUE,
                  category TEXT NOT NULL,
                  source TEXT,
                  risk_score INTEGER DEFAULT 50,
                  first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1,
                  details TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS source_stats
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  source_name TEXT,
                  scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                  domains_count INTEGER,
                  source_type TEXT,
                  response_time REAL,
                  success BOOLEAN DEFAULT 1)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS fetch_cache
                 (url TEXT PRIMARY KEY,
                  data TEXT,
                  fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                  data_hash TEXT,
                  expires_at DATETIME)''')
        
        
        c.execute('CREATE INDEX IF NOT EXISTS idx_domain_category ON illegal_sites(domain, category)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_last_seen_category ON illegal_sites(last_seen, category)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_cache_expires ON fetch_cache(expires_at)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_source_date ON source_stats(scan_date)')
        
        conn.commit()
        conn.close()
        logger.info("✅ Оптимизированная база данных инициализирована")
    
    @asynccontextmanager
    async def get_session(self):
        """Получение HTTP сессии с пулом соединений"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            connector = aiohttp.TCPConnector(limit=100, ttl_dns_cache=300)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; CyberScanMonitor/2.0)'}
            )
        try:
            yield self.session
        finally:
            pass
    
    def get_statistics(self) -> Dict:
        """Получение расширенной статистики"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        stats = {
            'total': 0,
            'by_category': {},
            'new_today': 0,
            'active_last_hour': 0,
            'by_source': {},
            'avg_risk': 0,
            'uptime': str(datetime.now() - self.stats['start_time']).split('.')[0]
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
        
       
        c.execute("SELECT AVG(risk_score) FROM illegal_sites")
        stats['avg_risk'] = round(c.fetchone()[0] or 0, 2)
        
      
        c.execute("""
            SELECT source_name, COUNT(*), AVG(domains_count) 
            FROM source_stats 
            WHERE scan_date > datetime('now', '-1 day')
            GROUP BY source_name
        """)
        for row in c.fetchall():
            stats['by_source'][row[0]] = {
                'scans': row[1],
                'avg_domains': round(row[2] or 0)
            }
        
        conn.close()
        
        stats['performance'] = {
            'total_fetched': self.stats['total_fetched'],
            'total_errors': self.stats['total_errors'],
            'avg_response_time': round(self.stats['avg_response_time'], 2)
        }
        
        return stats
    
    def get_illegal_sites(self, category: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Получение списка нелегальных сайтов с оптимизацией"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row 
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
            site = dict(row)
            if site['details']:
                site['details'] = json.loads(site['details'])
            sites.append(site)
        
        conn.close()
        return sites
    
    async def parse_plain_list(self, content: str) -> List[str]:
        """Быстрый парсинг простого списка"""
        domains = set()
        for line in content.split('\n'):
            line = line.strip().lower()
            if line and not line.startswith('#'):
               
                line = re.sub(r'^https?://', '', line)
                line = line.split('/')[0].split()[0]
                if '.' in line and len(line) < 100 and not line.startswith('0.0.0.0'):
                    domains.add(line)
        return list(domains)
    
    async def parse_csv(self, content: str) -> List[str]:
        """Быстрый парсинг CSV"""
        domains = set()
        try:
            f = StringIO(content)
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                for col in row[:3]:  
                    col = col.lower().strip()
                    if 'http' in col:
                        domain = re.sub(r'^https?://', '', col).split('/')[0]
                        if '.' in domain:
                            domains.add(domain)
                    elif '.' in col and len(col) < 100 and ' ' not in col:
                        domains.add(col)
        except Exception as e:
            logger.debug(f"CSV parsing error: {e}")
        return list(domains)
    
    async def parse_hosts_file(self, content: str) -> List[str]:
        """Быстрый парсинг hosts файлов"""
        domains = set()
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ['0.0.0.0', '127.0.0.1']:
                    domain = parts[1].strip().lower()
                    if '.' in domain:
                        domains.add(domain)
        return list(domains)
    
    async def parse_tar_gz(self, content: bytes) -> List[str]:
        """Парсинг tar.gz архивов с ограничением"""
        import tarfile
        import io
        domains = set()
        try:
            with tarfile.open(fileobj=io.BytesIO(content)) as tar:
               
                for i, member in enumerate(tar.getmembers()):
                    if i >= 5:  
                        break
                    if member.isfile() and member.size < 10_000_000:  
                        f = tar.extractfile(member)
                        if f:
                            file_content = f.read(1_000_000).decode('utf-8', errors='ignore') 
                            for line in file_content.split('\n')[:10000]:  
                                line = line.strip().lower()
                                if line and '.' in line and not line.startswith('#'):
                                    domains.add(line)
        except Exception as e:
            logger.debug(f"Tar.gz parsing error: {e}")
        return list(domains)
    
    async def parse_rss(self, content: str) -> List[str]:
        """Парсинг RSS фидов"""
        domains = set()
        try:
            soup = BeautifulSoup(content, 'xml')
            for link in soup.find_all('link')[:100]:  
                if link.text and 'http' in link.text:
                    domain = re.sub(r'^https?://', '', link.text).split('/')[0]
                    if '.' in domain:
                        domains.add(domain)
        except Exception as e:
            logger.debug(f"RSS parsing error: {e}")
        return list(domains)
    
    async def get_cached_or_fetch(self, source: Dict) -> List[str]:
        """Оптимизированное кэширование"""
        cache_key = hashlib.md5(f"{source['name']}_{source['url']}".encode()).hexdigest()
        cache_ttl = source.get('cache_ttl', 300)
        
        
        if cache_key in self.cache:
            cached_time, cached_data = self.cache[cache_key]
            if (datetime.now() - cached_time).total_seconds() < cache_ttl:
                logger.info(f"📦 RAM Cache HIT: {source['name']}")
                return cached_data
        
       
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "SELECT data, fetched_at FROM fetch_cache WHERE url = ? AND expires_at > datetime('now')", 
            (source['url'],)
        )
        row = c.fetchone()
        
        if row:
            logger.info(f"💾 DB Cache HIT: {source['name']}")
            data = json.loads(zlib.decompress(row[0]).decode()) if row[0] else []
            conn.close()
            self.cache[cache_key] = (datetime.now(), data)
            return data
        
        
        logger.info(f"🌐 Fetching: {source['name']}")
        start_time = time.time()
        
        try:
            domains = await self._fetch_source_real(source)
            response_time = time.time() - start_time
            
           
            self.stats['total_fetched'] += 1
            self.stats['avg_response_time'] = (
                (self.stats['avg_response_time'] * (self.stats['total_fetched'] - 1) + response_time) 
                / self.stats['total_fetched']
            )
            
          
            compressed = zlib.compress(json.dumps(domains).encode())
            expires_at = (datetime.now() + timedelta(seconds=cache_ttl)).isoformat()
            
            c.execute(
                "INSERT OR REPLACE INTO fetch_cache (url, data, fetched_at, expires_at) VALUES (?, ?, ?, ?)",
                (source['url'], compressed, datetime.now().isoformat(), expires_at)
            )
            conn.commit()
            
            self.cache[cache_key] = (datetime.now(), domains)
            
            logger.info(f"✅ Fetched {source['name']}: {len(domains)} domains in {response_time:.2f}s")
            
        except Exception as e:
            self.stats['total_errors'] += 1
            logger.error(f"❌ Error fetching {source['name']}: {e}")
            domains = []
            response_time = time.time() - start_time
            
       
            c.execute(
                "INSERT INTO source_stats (source_name, domains_count, source_type, response_time, success) VALUES (?, ?, ?, ?, ?)",
                (source['name'], 0, source['type'], response_time, 0)
            )
            conn.commit()
        
        conn.close()
        return domains
    
    async def _fetch_source_real(self, source: Dict) -> List[str]:
        """Загрузка данных с обработкой таймаутов"""
        async with self.get_session() as session:
            try:
                async with session.get(
                    source['url'], 
                    timeout=source.get('timeout', 30),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        
                    
                        parser_map = {
                            'plain_list': lambda: self.parse_plain_list,
                            'csv': lambda: self.parse_csv,
                            'hosts_file': lambda: self.parse_hosts_file,
                            'tar_gz': lambda: self.parse_tar_gz,
                            'rss': lambda: self.parse_rss,
                            'domain_list': lambda: self.parse_plain_list
                        }
                        
                        parser = parser_map.get(source['parser'], self.parse_plain_list)()
                        
                        if source['parser'] == 'tar_gz':
                            content = await response.read()
                        else:
                            content = await response.text()
                        
                        return await parser(content)
                    else:
                        logger.warning(f"⚠️ {source['name']} returned {response.status}")
                        return []
            except asyncio.TimeoutError:
                logger.warning(f"⏰ Timeout for {source['name']}")
                return []
    
    def _determine_category_from_domain(self, domain: str) -> Tuple[str, int]:
        """Определение категории и риска по домену"""
        domain_lower = domain.lower()
        
        for category, data in self.categories.items():
            for keyword in data['keywords']:
                if keyword in domain_lower:
              
                    risk = data['risk_base']
                    if keyword in ['login', 'verify', 'secure']:
                        risk = 98 
                    return category, risk
        
        return 'suspicious', 50
    
    async def batch_insert_domains(self, domains: List[str]) -> Dict:
       
        if not domains:
            return {'new': 0, 'updated': 0, 'categories': set()}
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
      
        placeholders = ','.join(['?'] * len(domains))
        c.execute(f"SELECT domain FROM illegal_sites WHERE domain IN ({placeholders})", domains)
        existing = {row[0] for row in c.fetchall()}
        
        
        new_domains = []
        categories_found = set()
        
        for domain in domains:
            if domain not in existing:
                category, risk = self._determine_category_from_domain(domain)
                new_domains.append((
                    f"http://{domain}", 
                    domain, 
                    category, 
                    risk, 
                    datetime.now().isoformat(),
                    json.dumps({'source': 'monitor', 'auto_detected': True})
                ))
                categories_found.add(category)
        
       
        if new_domains:
            c.executemany('''
                INSERT INTO illegal_sites (url, domain, category, risk_score, last_seen, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', new_domains)
        
       
        if existing:
            c.execute(f"""
                UPDATE illegal_sites 
                SET last_seen = datetime('now'), is_active = 1 
                WHERE domain IN ({placeholders})
            """, list(existing))
        
        conn.commit()
        conn.close()
        
        return {
            'new': len(new_domains),
            'updated': len(existing),
            'categories': categories_found
        }
    
    async def quick_scan(self):
       
        logger.info("="*60)
        logger.info("🚀 БЫСТРЫЙ ЦИКЛ СКАНИРОВАНИЯ")
        logger.info("="*60)
        
        all_domains = set()
        sources_stats = {}
        
      
        priority_sources = [s for s in self.sources if s['priority'] == 1 and s.get('enabled', True)]
        
        for source in priority_sources:
            domains = await self.get_cached_or_fetch(source)
            
            if domains:
                all_domains.update(domains)
                sources_stats[source['name']] = {
                    'count': len(domains),
                    'type': source['type']
                }
                logger.info(f"✓ {source['name']}: {len(domains)} доменов")
        
        logger.info(f"📊 Всего уникальных: {len(all_domains)}")
        
     
        domains_to_process = list(all_domains)[:self.max_domains_per_cycle]
        
        if domains_to_process:
            result = await self.batch_insert_domains(domains_to_process)
            
           
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            for source_name, stats in sources_stats.items():
                c.execute(
                    "INSERT INTO source_stats (source_name, domains_count, source_type, success) VALUES (?, ?, ?, ?)",
                    (source_name, stats['count'], stats['type'], 1)
                )
            conn.commit()
            conn.close()
            
            logger.info(f"✅ Новых: {result['new']}, Обновлено: {result['updated']}")
            logger.info(f"🏷️ Категории: {result['categories']}")
            
            return result
        else:
            logger.warning("⚠️ Нет данных для обработки")
            return {'new': 0, 'updated': 0, 'categories': set()}
    
    async def full_scan(self):
        """Полное сканирование (каждый час)"""
        logger.info("="*60)
        logger.info("🔬 ПОЛНЫЙ ЦИКЛ СКАНИРОВАНИЯ")
        logger.info("="*60)
        
        all_domains = set()
        sources_stats = {}
        
       
        for source in self.sources:
            if not source.get('enabled', True):
                continue
                
            domains = await self.get_cached_or_fetch(source)
            
            if domains:
                all_domains.update(domains)
                sources_stats[source['name']] = {
                    'count': len(domains),
                    'type': source['type']
                }
                logger.info(f"✓ {source['name']}: {len(domains)} доменов")
        
        logger.info(f"📊 Всего уникальных: {len(all_domains)}")
        
       
        domains_to_process = list(all_domains)[:5000]
        
        if domains_to_process:
            result = await self.batch_insert_domains(domains_to_process)
            
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            for source_name, stats in sources_stats.items():
                c.execute(
                    "INSERT INTO source_stats (source_name, domains_count, source_type, success) VALUES (?, ?, ?, ?)",
                    (source_name, stats['count'], stats['type'], 1)
                )
            conn.commit()
            conn.close()
            
            logger.info(f"✅ Новых: {result['new']}, Обновлено: {result['updated']}")
            logger.info(f"🏷️ Категории: {result['categories']}")
        else:
            logger.warning("⚠️ Нет данных для обработки")
    
    async def start_realtime_monitoring(self):
       
        logger.info("="*60)
        logger.info("🚀 ОПТИМИЗИРОВАННЫЙ МОНИТОРИНГ ЗАПУЩЕН")
        logger.info("⚡ Быстрый цикл: каждые 5 минут")
        logger.info("🔬 Полный цикл: каждый час")
        logger.info("="*60)
        
        quick_counter = 0
        error_count = 0
        
        while True:
            try:
                start_time = time.time()
                
              
                await self.quick_scan()
                quick_counter += 1
                
           
                if quick_counter >= 12:  
                    await self.full_scan()
                    quick_counter = 0
                
                elapsed = time.time() - start_time
                error_count = 0  
                
                
                wait_time = max(300 - elapsed, 10) 
                logger.info(f"⏱️ Цикл за {elapsed:.1f}с. Следующий через {wait_time:.0f}с")
                
                await asyncio.sleep(wait_time)
                
            except Exception as e:
                error_count += 1
                logger.error(f"❌ Ошибка в цикле: {e}")
                
              
                wait_time = min(60 * error_count, 300)
                logger.info(f"⏳ Пауза {wait_time}с перед восстановлением")
                await asyncio.sleep(wait_time)
    
    async def cleanup(self):
        """Очистка ресурсов"""
        if self.session and not self.session.closed:
            await self.session.close()
        logger.info("🧹 Ресурсы очищены")


monitor = CyberScanMonitor()

async def start_monitor_background():
    """Запуск монитора в фоне"""
    logger.info("🔄 Фоновый мониторинг активирован")
    try:
        await monitor.start_realtime_monitoring()
    except KeyboardInterrupt:
        logger.info("👋 Мониторинг остановлен")
        await monitor.cleanup()
    except Exception as e:
        logger.error(f"💥 Критическая ошибка: {e}")
        await monitor.cleanup()


if __name__ == "__main__":
    asyncio.run(start_monitor_background())
