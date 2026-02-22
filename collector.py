import asyncio
import aiohttp
import ssl
import socket
import whois
from bs4 import BeautifulSoup
import tldextract
from datetime import datetime
from urllib.parse import urlparse, urljoin
import re
import json
import dns.resolver
import dns.exception
from typing import Dict, List, Optional
import logging
from fake_useragent import UserAgent
import certifi
import hashlib
from concurrent.futures import ThreadPoolExecutor
import functools
import difflib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CyberScanCollector:

    def _domain_similarity(self, domain):
        suspicious = []
        for brand in self.brand_keywords:
            ratio = difflib.SequenceMatcher(None, domain, brand).ratio()
            if ratio > 0.8 and brand not in domain:
                suspicious.append(brand)
        return suspicious

    async def _detect_login_phishing(self, soup, url):
        result = {
            "is_login_page": False,
            "brand_detected": None,
            "suspicious_login": False
        }
        text = soup.get_text().lower()

        login_keywords = [
            "login", "sign in", "account", "verify",
            "security check", "password", "authentication"
        ]

        if any(k in text for k in login_keywords):
            result["is_login_page"] = True

        for brand in self.brand_keywords:
            if brand in text:
                result["brand_detected"] = brand
                domain_part = tldextract.extract(url).domain
                if brand not in domain_part:
                    result["suspicious_login"] = True
                    break  
        return result
    
    def __init__(self, max_concurrent=50, timeout=10):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.ua = UserAgent()
        self.session = None
        self.connector = None
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        
        self.scam_keywords = [
            'bonus', 'win money', 'guaranteed profit', 'crypto', 'free spins',
            'lottery', 'prize', 'congratulations', 'winner', 'bitcoin',
            'ethereum', 'withdraw', 'deposit', 'invest', 'mining', 'cloud mining',
            'passive income', 'get rich', 'double your money', 'no risk', '100% profit',
            'urgent', 'limited time', 'exclusive offer', 'verify now', 'account suspended',
            'unusual activity', 'login attempt', 'secure your account'
        ]
        
        self.brand_keywords = [
            'paypal', 'apple', 'amazon', 'microsoft', 'google', 'netflix',
            'facebook', 'instagram', 'twitter', 'linkedin', 'whatsapp',
            'telegram', 'binance', 'coinbase', 'blockchain', 'bank of america',
            'wells fargo', 'chase', 'citibank', 'hsbc', 'barclays'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.work', '.date',
            '.men', '.loan', '.download', '.review', '.stream', '.trade'
        ]
        
        self.malicious_patterns = [
            r'<script[^>]*>.*?eval\(.*?\)',
            r'document\.write\(.*?fromCharCode',
            r'window\.location\s*=\s*["\']https?:\/\/[^"\']*\.(ru|cn|tk)',
            r'<iframe[^>]*src=["\']https?:\/\/[^"\']*\.(ru|cn|tk)',
            r'atob\(["\'][A-Za-z0-9+/=]+["\']\)',
            r'String\.fromCharCode\(.*?\)',
            r'\\x[0-9a-f]{2}'
        ]
        
    async def __aenter__(self):
        await self._init_session()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        
    async def _init_session(self):
        if not self.session:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            
            self.connector = aiohttp.TCPConnector(
                limit=self.max_concurrent,
                limit_per_host=10,
                ssl=ssl_context,
                force_close=True,
                enable_cleanup_closed=True
            )
            
            timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=5,
                sock_read=self.timeout
            )
            
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=timeout,
                headers={'User-Agent': self.ua.random}
            )
            
    async def close(self):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
        self.thread_pool.shutdown(wait=False)
        
    def _run_sync(self, func, *args, **kwargs):
        return self.thread_pool.submit(func, *args, **kwargs).result()
    
    async def _analyze_url_structure(self, url: str, parsed) -> Dict:
        domain_info = tldextract.extract(url)
        
        analysis = {
            'url_length': len(url),
            'has_ip': bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc)),
            'num_dots': parsed.netloc.count('.'),
            'num_hyphens': parsed.netloc.count('-'),
            'num_digits': sum(c.isdigit() for c in parsed.netloc),
            'has_at_symbol': '@' in url,
            'has_double_slash': '//' in parsed.path,
            'subdomain_count': len(domain_info.subdomain.split('.')) if domain_info.subdomain else 0,
            'path_length': len(parsed.path),
            'num_query_params': len(parsed.query.split('&')) if parsed.query else 0,
            'special_chars_count': len(re.findall(r'[%@&\?=]', url)),
            'suspicious_tld': domain_info.suffix.lower() in [tld.replace('.', '') for tld in self.suspicious_tlds]
        }
        
        return analysis
        
    async def _analyze_dns(self, domain: str) -> Dict:
        analysis = {
            'has_dns': False,
            'ip_addresses': [],
            'has_mx': False,
            'has_txt': False,
            'ns_servers': []
        }
        
        try:
            answers = dns.resolver.resolve(domain, 'A')
            analysis['has_dns'] = True
            analysis['ip_addresses'] = [str(r) for r in answers]
            
            try:
                mx = dns.resolver.resolve(domain, 'MX')
                analysis['has_mx'] = len(mx) > 0
            except:
                pass
                
            try:
                txt = dns.resolver.resolve(domain, 'TXT')
                analysis['has_txt'] = len(txt) > 0
            except:
                pass
                
            try:
                ns = dns.resolver.resolve(domain, 'NS')
                analysis['ns_servers'] = [str(r) for r in ns]
            except:
                pass
                
        except Exception as e:
            logger.debug(f"DNS error for {domain}: {e}")
            
        return analysis
        
    async def _analyze_whois(self, domain: str) -> Dict:
        analysis = {
            'domain_age_days': None,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'is_private': False
        }
        
        try:
            w = await asyncio.get_event_loop().run_in_executor(
                self.thread_pool, 
                functools.partial(whois.whois, domain)
            )
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                    
                if isinstance(creation_date, datetime):
                    analysis['creation_date'] = creation_date.isoformat()
                    analysis['domain_age_days'] = (datetime.now() - creation_date).days
                    
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    exp_date = w.expiration_date[0]
                else:
                    exp_date = w.expiration_date
                    
                if isinstance(exp_date, datetime):
                    analysis['expiration_date'] = exp_date.isoformat()
                    
            if w.registrar:
                analysis['registrar'] = w.registrar
                
            analysis['is_private'] = not bool(w.name or w.org)
                
        except Exception as e:
            logger.debug(f"WHOIS error for {domain}: {e}")
            
        return analysis
        
    async def _analyze_ssl(self, domain: str) -> Dict:
        analysis = {
            'valid': False,
            'issuer': None,
            'issuer_name': None,
            'subject': None,
            'expiry_date': None,
            'days_until_expiry': None,
            'version': None
        }
        
        try:
            context = ssl.create_default_context()
            
            reader, writer = await asyncio.open_connection(
                domain, 443,
                ssl=context,
                server_hostname=domain
            )
            
            sock = writer.get_extra_info('ssl_object')
            cert = sock.getpeercert()
            
            if cert:
                analysis['valid'] = True
                issuer_dict = dict(x[0] for x in cert['issuer'])
                analysis['issuer'] = issuer_dict
                
                if 'organizationName' in issuer_dict:
                    analysis['issuer_name'] = issuer_dict['organizationName']
                elif 'commonName' in issuer_dict:
                    analysis['issuer_name'] = issuer_dict['commonName']
                else:
                    analysis['issuer_name'] = str(issuer_dict)
                    
                analysis['subject'] = dict(x[0] for x in cert['subject'])
                analysis['version'] = cert.get('version')
                
                if 'notAfter' in cert:
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    analysis['expiry_date'] = expiry.isoformat()
                    analysis['days_until_expiry'] = (expiry - datetime.now()).days
                    
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"SSL error for {domain}: {e}")
            
        return analysis
        
    async def _analyze_form(self, form, base_url: str) -> Dict:
        analysis = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').upper(),
            'has_password': False,
            'has_credit_card': False,
            'input_count': 0,
            'input_types': [],
            'external_action': False,
            'action_url': None
        }
        
        action = form.get('action', '')
        if action:
            if action.startswith('http'):
                analysis['action_url'] = action
                action_domain = tldextract.extract(action).domain
                base_domain = tldextract.extract(base_url).domain
                analysis['external_action'] = action_domain != base_domain
            else:
                analysis['action_url'] = urljoin(base_url, action)
                
        for inp in form.find_all(['input', 'textarea', 'select']):
            analysis['input_count'] += 1
            input_type = inp.get('type', 'text')
            analysis['input_types'].append(input_type)
            
            if input_type == 'password':
                analysis['has_password'] = True
                
            name = inp.get('name', '').lower()
            if any(word in name for word in ['card', 'cvv', 'ccv', 'credit', 'pan']):
                analysis['has_credit_card'] = True
                
        return analysis
        
    async def _analyze_script(self, script, base_url: str) -> Optional[Dict]:
        script_src = script.get('src', '')
        
        analysis = {
            'src': script_src,
            'external': False,
            'has_malicious_patterns': False,
            'patterns_found': []
        }
        
        if script_src:
            if script_src.startswith('http'):
                analysis['external'] = True
            else:
                analysis['src'] = urljoin(base_url, script_src)
                
        if script.string:
            content = script.string
            for pattern in self.malicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis['has_malicious_patterns'] = True
                    analysis['patterns_found'].append(pattern)
                    
        return analysis if (script_src or script.string) else None
        
    async def quick_scan(self, url: str) -> Dict:
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'level1': {},
            'needs_deep_scan': False,
            'risk_score': 0
        }
        
        try:
            parsed = urlparse(url)
            domain_info = tldextract.extract(url)
            full_domain = f"{domain_info.domain}.{domain_info.suffix}".lower()
            
            await self._init_session()
            
            response_time = 0
            page_size = 0
            redirect_count = 0
            html = ""
            
            try:
                start_time = datetime.now()
                async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                    end_time = datetime.now()
                    response_time = (end_time - start_time).total_seconds()
                    redirect_count = len(response.history)
                    html = await response.text()
                    page_size = len(html)
            except Exception as e:
                logger.debug(f"Error getting page for {url}: {e}")
            
            level1 = {
                'url_analysis': await self._analyze_url_structure(url, parsed),
                'dns_analysis': await self._analyze_dns(full_domain),
                'whois_analysis': await self._analyze_whois(full_domain),
                'ssl_analysis': await self._analyze_ssl(full_domain),
                'response_time': response_time,
                'page_size': page_size,
                'redirect_count': redirect_count,
                'risk_flags': []
            }
            
            risk_score = 0
            
            similar = self._domain_similarity(domain_info.domain)
            if similar:
                level1['risk_flags'].append(
                    f"Домен похож на бренд: {', '.join(similar)}"
                )
                risk_score += 20

            if level1['url_analysis']['has_ip']:
                level1['risk_flags'].append('URL содержит IP вместо домена')
                risk_score += 30
                
            if level1['url_analysis']['suspicious_tld']:
                level1['risk_flags'].append(f"Подозрительный TLD: {domain_info.suffix}")
                risk_score += 15
                
            if level1['url_analysis']['url_length'] > 100:
                level1['risk_flags'].append('Необычно длинный URL')
                risk_score += 10
                
            if level1['url_analysis']['special_chars_count'] > 5:
                level1['risk_flags'].append('Много специальных символов в URL')
                risk_score += 10
                
            if not level1['dns_analysis']['has_dns']:
                level1['risk_flags'].append('Домен не резолвится')
                risk_score += 40
                
            if not level1['dns_analysis']['has_mx']:
                level1['risk_flags'].append('Нет MX записей (подозрительно для легитимного сайта)')
                risk_score += 5
                
            if level1['whois_analysis']['domain_age_days'] is not None:
                if level1['whois_analysis']['domain_age_days'] < 7:
                    level1['risk_flags'].append('Домен создан менее 7 дней назад')
                    risk_score += 40
                elif level1['whois_analysis']['domain_age_days'] < 30:
                    level1['risk_flags'].append('Домен создан менее 30 дней назад')
                    risk_score += 25
                elif level1['whois_analysis']['domain_age_days'] < 90:
                    level1['risk_flags'].append('Домен создан менее 90 дней назад')
                    risk_score += 10
                    
            if level1['whois_analysis']['is_private']:
                level1['risk_flags'].append('Приватная регистрация WHOIS')
                risk_score += 5
                
            if not level1['ssl_analysis']['valid']:
                level1['risk_flags'].append('Нет валидного SSL сертификата')
                risk_score += 30
            else:
                expiry_days = level1['ssl_analysis']['days_until_expiry']
                if expiry_days is not None and expiry_days < 7:
                    risk_score += 10
                    level1['risk_flags'].append('SSL сертификат скоро истекает')
                    
            level1['risk_score'] = risk_score
            result['level1'] = level1
            
            result['needs_deep_scan'] = risk_score > 30
            
        except Exception as e:
            logger.error(f"Error in quick_scan for {url}: {e}")
            result['level1']['error'] = str(e)
            result['level1']['risk_flags'] = [f"Ошибка сканирования: {str(e)}"]
            
        return result
        
    async def deep_scan(self, url: str) -> Dict:
        await self._init_session()
        result = {
            'url': url,
            'content_analysis': {},
            'form_analysis': [],
            'javascript_analysis': [],
            'external_resources': [],
            'suspicious_patterns': [],
            'brand_impersonation': None,
            'brand_confidence': 'low',
            'risk_score': 0,
            'has_redirect': False  
        }
        
        try:
            async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                redirects = [str(r.url) for r in response.history]
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                result['has_redirect'] = len(redirects) > 0  
                
                if len(redirects) > 2:
                    result['suspicious_patterns'].append(
                        f"Множественные редиректы ({len(redirects)})"
                    )

                login_analysis = await self._detect_login_phishing(soup, url)
                result["login_analysis"] = login_analysis
                if login_analysis["suspicious_login"]:
                    result["suspicious_patterns"].append(
                        f"Фишинговая страница входа ({login_analysis['brand_detected']})"
                    )
                
                title = soup.find('title')
                if title:
                    title_text = title.string.lower() if title.string else ''
                    result['content_analysis']['title'] = title_text
                    
                    for brand in self.brand_keywords:
                        if brand in title_text:
                            brand_domain = tldextract.extract(url).domain
                            if brand not in brand_domain:
                                result['brand_impersonation'] = brand
                                result['brand_confidence'] = 'high'
                                result['suspicious_patterns'].append(f"Имитация бренда: {brand}")
                                break 
                                
                forms = soup.find_all('form')
                for form in forms:
                    form_data = await self._analyze_form(form, url)
                    result['form_analysis'].append(form_data)
                    
                    if form_data['has_password']:
                        result['suspicious_patterns'].append('Обнаружена форма с паролем')
                        
                    if form_data['external_action']:
                        result['suspicious_patterns'].append('Форма отправляется на внешний домен')
                        
                    if form_data['has_credit_card']:
                        result['suspicious_patterns'].append('Форма собирает данные карты')
                        
                scripts = soup.find_all('script')
                for script in scripts:
                    script_data = await self._analyze_script(script, url)
                    if script_data:
                        result['javascript_analysis'].append(script_data)
                        
                        if script_data['has_malicious_patterns']:
                            result['suspicious_patterns'].append('Обнаружен подозрительный JavaScript')
                            
                for tag in soup.find_all(['link', 'script', 'img', 'iframe']):
                    src = tag.get('src', tag.get('href', ''))
                    if src and src.startswith(('http://', 'https://')):
                        ext_domain = tldextract.extract(src).domain
                        main_domain = tldextract.extract(url).domain
                        
                        if ext_domain != main_domain:
                            result['external_resources'].append({
                                'url': src,
                                'type': tag.name,
                                'domain': ext_domain
                            })
                            
                text_content = soup.get_text().lower()
                scam_count = sum(text_content.count(word) for word in self.scam_keywords)
                result['content_analysis']['scam_word_count'] = scam_count
                
                if scam_count > 5:
                    result['suspicious_patterns'].append(f'Много мошеннических слов ({scam_count})')
                    
                risk_score = 0
                risk_score += len(result['form_analysis']) * 5
                risk_score += len(result['suspicious_patterns']) * 10
                risk_score += len([f for f in result['form_analysis'] if f['has_password']]) * 20
                risk_score += len(result['external_resources']) * 2
                
                result['risk_score'] = min(100, risk_score)
                
        except asyncio.TimeoutError:
            logger.warning(f"Timeout loading {url}")
            result['suspicious_patterns'].append('Таймаут загрузки (возможно, сайт не отвечает)')
            
        except Exception as e:
            logger.error(f"Error in deep_scan for {url}: {e}")
            result['error'] = str(e)
            result['suspicious_patterns'].append(f"Ошибка глубокого сканирования: {str(e)}")
            
        return result
        
    async def batch_scan(self, urls: List[str], deep_scan_threshold: int = 30) -> List[Dict]:
        results = []
        
        quick_tasks = [self.quick_scan(url) for url in urls]
        quick_results = await asyncio.gather(*quick_tasks, return_exceptions=True)
        
        deep_scan_tasks = []
        scan_results = []  
        
        for i, result in enumerate(quick_results):
            if isinstance(result, Exception):
                logger.error(f"Quick scan failed for {urls[i]}: {result}")
                results.append({'url': urls[i], 'error': str(result)})
            else:
                scan_results.append(result)
                if result.get('needs_deep_scan', False):
                    deep_scan_tasks.append(self.deep_scan(urls[i]))
                    
        if deep_scan_tasks:
            deep_results = await asyncio.gather(*deep_scan_tasks, return_exceptions=True)
            
            deep_idx = 0
            for result in scan_results:
                if result.get('needs_deep_scan', False) and deep_idx < len(deep_results):
                    deep_result = deep_results[deep_idx]
                    if not isinstance(deep_result, Exception):
                        result['deep_scan'] = deep_result
                    deep_idx += 1
                results.append(result)
        else:
            results.extend(scan_results)
                    
        return results
        
    def extract_features_for_ml(self, scan_result: Dict) -> Dict:
        features = {}
        
        level1 = scan_result.get('level1', {})
        
        url_analysis = level1.get('url_analysis', {})
        features['url_length'] = url_analysis.get('url_length', 0)
        features['has_ip'] = int(url_analysis.get('has_ip', False))
        features['num_dots'] = url_analysis.get('num_dots', 0)
        features['num_hyphens'] = url_analysis.get('num_hyphens', 0)
        features['num_digits'] = url_analysis.get('num_digits', 0)
        features['subdomain_count'] = url_analysis.get('subdomain_count', 0)
        features['suspicious_tld'] = int(url_analysis.get('suspicious_tld', False))
        
        dns_analysis = level1.get('dns_analysis', {})
        features['has_dns'] = int(dns_analysis.get('has_dns', False))
        features['has_mx'] = int(dns_analysis.get('has_mx', False))
        features['num_ip_addresses'] = len(dns_analysis.get('ip_addresses', []))
        
        whois_analysis = level1.get('whois_analysis', {})
        features['domain_age_days'] = whois_analysis.get('domain_age_days', -1)
        features['is_private_whois'] = int(whois_analysis.get('is_private', False))
        
        ssl_analysis = level1.get('ssl_analysis', {})
        features['ssl_valid'] = int(ssl_analysis.get('valid', False))
        features['ssl_days_until_expiry'] = ssl_analysis.get('days_until_expiry', -1)
        
        deep_scan = scan_result.get('deep_scan', {})
        if deep_scan:
            features['num_forms'] = len(deep_scan.get('form_analysis', []))
            features['num_password_forms'] = len([f for f in deep_scan.get('form_analysis', []) if f.get('has_password')])
            features['num_external_scripts'] = len([s for s in deep_scan.get('javascript_analysis', []) if s.get('external')])
            features['num_external_resources'] = len(deep_scan.get('external_resources', []))
            features['scam_word_count'] = deep_scan.get('content_analysis', {}).get('scam_word_count', 0)
            features['has_brand_impersonation'] = int(deep_scan.get('brand_impersonation') is not None)
            features['num_suspicious_patterns'] = len(deep_scan.get('suspicious_patterns', []))
        else:
            features['num_forms'] = 0
            features['num_password_forms'] = 0
            features['num_external_scripts'] = 0
            features['num_external_resources'] = 0
            features['scam_word_count'] = 0
            features['has_brand_impersonation'] = 0
            features['num_suspicious_patterns'] = 0
            
        return features

async def scan_url_async(url: str) -> Dict:
    async with CyberScanCollector() as collector:
        quick_result = await collector.quick_scan(url)
        if quick_result.get('needs_deep_scan', False):
            try:
                deep_result = await collector.deep_scan(url)
                quick_result['deep_scan'] = deep_result
            except Exception as e:
                logger.error(f"Deep scan failed: {e}")
        return quick_result

async def batch_scan_async(urls: List[str]) -> List[Dict]:
    async with CyberScanCollector() as collector:
        return await collector.batch_scan(urls)

def scan_url_sync(url: str) -> Dict:
    return asyncio.run(scan_url_async(url))

def batch_scan_sync(urls: List[str]) -> List[Dict]:
    return asyncio.run(batch_scan_async(urls))