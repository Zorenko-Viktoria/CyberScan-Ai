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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CyberScanMonitor:
    """Автоматический мониторинг и отслеживание нелегальных сайтов"""
    
    def __init__(self, db_path='cyberscan.db'):
        self.db_path = db_path
        
        self.sources = [
            # Фишинг
            {
                'name': 'openphish',
                'url': 'https://openphish.com/feed.txt',
                'type': 'phishing',
                'parser': 'plain_list',
                'priority': 1
            },
            {
                'name': 'urlhaus',
                'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
                'type': 'malware',
                'parser': 'csv',
                'priority': 1
            },
            {
                'name': 'phishing_database',
                'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
                'type': 'phishing',
                'parser': 'plain_list',
                'priority': 1
            },
            
            # Казино
            {
                'name': 'stevenblack_gambling',
                'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts',
                'type': 'casino',
                'parser': 'hosts_file',
                'priority': 1
            },
            {
                'name': 'stopgambling',
                'url': 'https://raw.githubusercontent.com/StopGambling/domain-list/main/domains.txt',
                'type': 'casino',
                'parser': 'plain_list',
                'priority': 1
            },
            {
                'name': 'ut1_gambling',
                'url': 'https://dsi.ut-capitole.fr/blacklists/download/gambling.tar.gz',
                'type': 'casino',
                'parser': 'tar_gz',
                'priority': 1
            },
            {
                'name': 'oisd_gambling',
                'url': 'https://big.oisd.nl/',
                'type': 'casino',
                'parser': 'domain_list',
                'priority': 1
            },
            
            # Мошенничество
            {
                'name': 'feodo_tracker',
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
                'type': 'malware',
                'parser': 'csv',
                'priority': 2
            },
            {
                'name': 'ssl_blacklist',
                'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
                'type': 'malware',
                'parser': 'csv',
                'priority': 2
            },
            
            # Пиратство
            {
                'name': 'pirate_blocklist',
                'url': 'https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt',
                'type': 'piracy',
                'parser': 'plain_list',
                'priority': 1
            },
            {
                'name': 'stevenblack_porn',
                'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts',
                'type': 'adult',
                'parser': 'hosts_file',
                'priority': 2
            },
            
            # RSS фиды
            {
                'name': 'krebs_rss',
                'url': 'https://krebsonsecurity.com/feed/',
                'type': 'security_news',
                'parser': 'rss',
                'priority': 2
            },
            {
                'name': 'bleepingcomputer_rss',
                'url': 'https://www.bleepingcomputer.com/feed/',
                'type': 'security_news',
                'parser': 'rss',
                'priority': 2
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
                  source_type TEXT)''')
    
        conn.commit()
        conn.close()
        logger.info("Monitor database initialized")

    def get_statistics(self) -> Dict:
        """Получение статистики по нелегальным сайтам"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        stats = {
            'total': 0,
            'by_category': {}
        }
        
        c.execute("SELECT COUNT(*) FROM illegal_sites")
        stats['total'] = c.fetchone()[0]
        
        c.execute("SELECT category, COUNT(*) FROM illegal_sites GROUP BY category")
        for row in c.fetchall():
            stats['by_category'][row[0]] = row[1]
        
        conn.close()
        logger.info(f"Statistics: {stats}")
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
        logger.info(f"Retrieved {len(sites)} illegal sites")
        return sites

    async def parse_json_phishtank(self, content: str) -> List[str]:
        """Парсинг JSON от PhishTank"""
        try:
            data = json.loads(content)
            domains = []
            for item in data:
                if 'url' in item:
                    url = item['url']
                    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
                    if domain and '.' in domain:
                        domains.append(domain)
            return domains
        except:
            return []
    
    async def parse_csv_phishing(self, content: str) -> List[str]:
        """Парсинг CSV фишинговых баз"""
        domains = []
        try:
            f = StringIO(content)
            reader = csv.reader(f)
            for row in reader:
                if row and len(row) > 0:
                    domain = row[0].strip()
                    if domain and '.' in domain and not domain.startswith('#'):
                        domains.append(domain)
        except:
            pass
        return domains
    
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
                        domains.append(domain)
        return domains
    
    async def parse_adblock_plus(self, content: str) -> List[str]:
        """Парсинг AdBlock Plus фильтров"""
        domains = []
        for line in content.split('\n'):
            line = line.strip()
            if line and '||' in line and '^' in line:
                domain = line.split('||')[1].split('^')[0]
                if domain and '.' in domain:
                    domains.append(domain)
        return domains
    
    async def parse_json_cryptoscam(self, content: str) -> List[str]:
        """Парсинг CryptoScamDB"""
        try:
            data = json.loads(content)
            domains = []
            for item in data:
                if 'url' in item:
                    url = item['url']
                    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
                    if domain:
                        domains.append(domain)
                if 'domain' in item:
                    domains.append(item['domain'])
            return domains
        except:
            return []
    
    async def parse_rss(self, content: str) -> List[str]:
        """Парсинг RSS фидов"""
        domains = []
        try:
            soup = BeautifulSoup(content, 'xml')
            for item in soup.find_all('item'):
                for link in item.find_all('link'):
                    if link.text and 'http' in link.text:
                        domain = link.text.replace('http://', '').replace('https://', '').split('/')[0]
                        if domain and '.' in domain:
                            domains.append(domain)
        except:
            pass
        return domains
    
    async def parse_telegram(self, content: str) -> List[str]:
        """Парсинг Telegram каналов"""
        domains = []
        try:
            soup = BeautifulSoup(content, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                if 'http' in href and 't.me' not in href:
                    domain = href.replace('http://', '').replace('https://', '').split('/')[0]
                    if domain and '.' in domain:
                        domains.append(domain)
            
            text = soup.get_text()
            domain_pattern = r'[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}'
            found = re.findall(domain_pattern, text)
            domains.extend(found)
        except:
            pass
        return list(set(domains))
    
    async def parse_spamhaus(self, content: str) -> List[str]:
        """Парсинг Spamhaus DBL"""
        domains = []
        for line in content.split('\n'):
            if line and 'domain' in line.lower():
                parts = line.split()
                for part in parts:
                    if '.' in part and not part.startswith('#'):
                        domain = part.strip(';,').strip()
                        if domain.count('.') >= 1:
                            domains.append(domain)
        return domains
    
    async def parse_tar_gz(self, content: bytes) -> List[str]:
        """Парсинг tar.gz архивов"""
        import tarfile
        import io
        domains = []
        try:
            tar = tarfile.open(fileobj=io.BytesIO(content))
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        file_content = f.read().decode('utf-8')
                        for line in file_content.split('\n'):
                            if line and '.' in line and not line.startswith('#'):
                                domains.append(line.strip())
        except:
            pass
        return domains
    
    
    async def fetch_source(self, source: Dict) -> List[str]:
        """Загрузка данных из источника с обработкой разных форматов"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; CyberScanMonitor/1.0)'
            }
            
            if 'api_key' in source:
                headers['Authorization'] = f"Bearer {source['api_key']}"
            
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(source['url'], timeout=60, ssl=False) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        
                        if 'application/json' in content_type or source['parser'].startswith('json'):
                            content = await response.text()
                            return await self.parse_json_source(content, source)
                        elif 'text/csv' in content_type or source['parser'] == 'csv':
                            content = await response.text()
                            return await self.parse_csv_source(content, source)
                        elif 'application/x-tar' in content_type or source['parser'] == 'tar_gz':
                            content = await response.read()
                            return await self.parse_tar_gz(content)
                        else:
                            content = await response.text()
                            return await self.parse_text_source(content, source)
                    else:
                        logger.error(f"Failed {source['name']}: {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error {source['name']}: {e}")
            return []
    
    async def parse_json_source(self, content: str, source: Dict) -> List[str]:
        """Универсальный JSON парсер"""
        try:
            data = json.loads(content)
            domains = []
            
            if source['parser'] == 'json_phishtank':
                for item in data:
                    if 'url' in item:
                        url = item['url']
                        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
                        domains.append(domain)
            elif source['parser'] == 'json_cryptoscam':
                for item in data:
                    if 'url' in item:
                        domains.append(item['url'])
                    if 'domain' in item:
                        domains.append(item['domain'])
            elif source['parser'] == 'json_api':
                if isinstance(data, dict):
                    if 'data' in data:
                        for item in data['data']:
                            if 'url' in item:
                                domains.append(item['url'])
                            if 'domain' in item:
                                domains.append(item['domain'])
                    if 'results' in data:
                        for item in data['results']:
                            if 'url' in item:
                                domains.append(item['url'])
            
            return [d for d in domains if d and '.' in d]
        except:
            return []
    
    async def parse_csv_source(self, content: str, source: Dict) -> List[str]:
        """Универсальный CSV парсер"""
        domains = []
        try:
            f = StringIO(content)
            reader = csv.reader(f)
            for row in reader:
                if row:
                    for col in row:
                        if 'http' in col:
                            domain = col.replace('http://', '').replace('https://', '').split('/')[0]
                            if domain and '.' in domain:
                                domains.append(domain)
                            break
                        elif '.' in col and len(col) < 100 and ' ' not in col:
                            if col.strip() and not col.startswith('#'):
                                domains.append(col.strip())
                            break
        except:
            pass
        return list(set(domains))
    
    async def parse_text_source(self, content: str, source: Dict) -> List[str]:
        """Универсальный текстовый парсер"""
        domains = []
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if '#' in line:
                    line = line.split('#')[0].strip()
                
                if line:
                    if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                        parts = line.split()
                        if len(parts) >= 2:
                            domain = parts[1].strip()
                            if domain and '.' in domain:
                                domains.append(domain)
                    elif ' ' in line:
                        domain = line.split()[0].strip()
                        if domain and '.' in domain:
                            domains.append(domain)
                    else:
                        if line and '.' in line:
                            domains.append(line)
        
        return list(set(domains))
    
    async def run_monitor_cycle(self):
        """Полный цикл мониторинга со всеми источниками"""
        logger.info("="*50)
        logger.info("ЗАПУСК ПОЛНОГО ЦИКЛА МОНИТОРИНГА")
        logger.info("="*50)
        
        all_domains = []
        sources_stats = {}
        
        for source in self.sources:
            try:
                domains = await self.fetch_source(source)
                
                if domains:
                    unique_count = len(set(domains))
                    all_domains.extend(domains)
                    
                    sources_stats[source['name']] = {
                        'total': len(domains),
                        'unique': unique_count,
                        'type': source['type']
                    }
                    
                    logger.info(f"✓ {source['name']}: {unique_count} доменов")
                else:
                    logger.warning(f"✗ {source['name']}: 0 доменов")
                    
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"✗ {source['name']} error: {e}")
        
        all_domains = list(set(all_domains))
        
        logger.info("="*50)
        logger.info(f"ВСЕГО УНИКАЛЬНЫХ ДОМЕНОВ: {len(all_domains)}")
        logger.info("="*50)
        
        await self.save_domains_to_db(all_domains, sources_stats)
        
        sites_to_scan = all_domains[:5000]
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        categories_found = set()
        new_sites_count = 0
        
        for i, domain in enumerate(sites_to_scan):
            if i % 20 == 0:
                logger.info(f"Прогресс: {i}/{len(sites_to_scan)}")
            
            c.execute("SELECT id FROM illegal_sites WHERE domain = ?", (domain,))
            existing = c.fetchone()
            
            if existing:
                c.execute("UPDATE illegal_sites SET last_seen = datetime('now') WHERE domain = ?", (domain,))
            else:
                category = self._determine_category_from_domain(domain)
                
                c.execute('''INSERT INTO illegal_sites 
                            (url, domain, category, risk_score, last_seen, details)
                            VALUES (?, ?, ?, ?, datetime('now'), ?)''',
                        (f"http://{domain}", domain, category, 
                        70, json.dumps({'source': 'monitor', 'auto_detected': True})))
                new_sites_count += 1
                categories_found.add(category)
        
        conn.commit()
        conn.close()
        
        logger.info("="*50)
        logger.info(f"ЦИКЛ ЗАВЕРШЕН:")
        logger.info(f"Новых сайтов: {new_sites_count}")
        logger.info(f"Категории: {categories_found}")
        logger.info("="*50)
    
    def _determine_category_from_domain(self, domain: str) -> str:
        """Определение категории по домену"""
        domain_lower = domain.lower()
        
        for category, data in self.categories.items():
            for keyword in data['keywords']:
                if keyword in domain_lower:
                    return category
        
        return 'suspicious'
    
    async def save_domains_to_db(self, domains: List[str], sources_stats: Dict):
        """Сохраняет домены в базу данных"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS source_stats
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      source_name TEXT,
                      scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                      domains_count INTEGER,
                      source_type TEXT)''')
        
        for source_name, stats in sources_stats.items():
            c.execute('''INSERT INTO source_stats (source_name, domains_count, source_type)
                         VALUES (?, ?, ?)''',
                      (source_name, stats['unique'], stats['type']))
        
        conn.commit()
        conn.close()
    
    async def start_monitoring(self, interval_hours: int = 6):
        """Запуск постоянного мониторинга (каждые 6 часов)"""
        logger.info(f"🚀 МОНИТОРИНГ ЗАПУЩЕН (интервал: {interval_hours} часов)")
        
        while True:
            try:
                await self.run_monitor_cycle()
                logger.info(f"✅ Цикл завершен. Следующий через {interval_hours} часов")
                await asyncio.sleep(interval_hours * 3600)
            except Exception as e:
                logger.error(f"❌ Ошибка в цикле: {e}")
                await asyncio.sleep(3600)

monitor = CyberScanMonitor()
async def start_monitor_background():
    """Запуск монитора в фоне"""
    logger.info("🔄 Фоновый мониторинг активирован")
    asyncio.create_task(monitor.start_monitoring(interval_hours=6))