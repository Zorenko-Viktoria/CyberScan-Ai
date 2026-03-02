import asyncio
import aiohttp
import ssl
import socket
import whois
from bs4 import BeautifulSoup
import tldextract
from datetime import datetime
from urllib.parse import urlparse, urljoin, urldefrag
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
from collections import Counter
import math

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
            "suspicious_login": False,
            "login_forms": []
        }
        text = soup.get_text().lower()

        login_keywords = [
            "login", "sign in", "account", "verify",
            "security check", "password", "authentication",
            "войти", "вход", "аккаунт", "пароль", "подтвердить"
        ]

        if any(k in text for k in login_keywords):
            result["is_login_page"] = True

        forms = soup.find_all('form')
        for form in forms:
            form_text = form.get_text().lower()
            if any(k in form_text for k in ['password', 'пароль', 'login']):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get'),
                    'has_password': bool(form.find('input', {'type': 'password'}))
                }
                result["login_forms"].append(form_data)

        for brand in self.brand_keywords:
            if brand in text:
                result["brand_detected"] = brand
                domain_part = tldextract.extract(url).domain
                if brand not in domain_part:
                    result["suspicious_login"] = True
                    break
        return result

    async def _detect_casino(self, soup, url):
        """Определение признаков онлайн-казино"""
        result = {
            "is_casino": False,
            "confidence": "low",
            "indicators": [],
            "gambling_terms": [],
            "bonus_offers": []
        }
        
        text = soup.get_text().lower()
        html = str(soup).lower()

        casino_keywords = [
            'казино', 'casino', 'вулкан', 'vulkan', 'pin up', 'пин ап',
            'joycasino', 'joy casino', 'mostbet', '1xbet', '1xslots',
            'слоты', 'slots', 'рулетка', 'roulette', 'блэкджек', 'blackjack',
            'покер', 'poker', 'бонус за регистрацию', 'бездепозитный бонус',
            'фриспины', 'free spins', 'джекпот', 'jackpot'
        ]
        
        gambling_terms = [
            'ставка', 'bet', 'выигрыш', 'win', 'проигрыш', 'lose',
            'кэф', 'odds', 'тотализатор', 'lottery', 'лотерея'
        ]
        
        bonus_terms = [
            'бонус', 'bonus', 'промокод', 'promocode', 'халява', 'free',
            'подарок', 'gift', 'приветственный', 'welcome'
        ]
        
        found_keywords = []
        found_gambling = []
        found_bonus = []
        
        for keyword in casino_keywords:
            if keyword in text or keyword in html:
                found_keywords.append(keyword)
                
        for term in gambling_terms:
            if term in text:
                found_gambling.append(term)
                
        for term in bonus_terms:
            if term in text:
                found_bonus.append(term)

        if found_keywords:
            result["indicators"] = found_keywords[:5]
            result["gambling_terms"] = found_gambling[:5]
            result["bonus_offers"] = found_bonus[:5]
            
            if len(found_keywords) >= 5:
                result["confidence"] = "high"
                result["is_casino"] = True
            elif len(found_keywords) >= 3:
                result["confidence"] = "medium"
                result["is_casino"] = True
            elif len(found_keywords) >= 1:
                result["confidence"] = "low"
                result["is_casino"] = True

        url_lower = url.lower()
        url_indicators = ['casino', 'казино', 'vulkan', '1x', 'pinu', 'bet', 'slot']
        for ind in url_indicators:
            if ind in url_lower:
                result["indicators"].append(f"URL содержит '{ind}'")
                result["is_casino"] = True
                if result["confidence"] == "low":
                    result["confidence"] = "medium"
        
        return result

    async def _detect_crypto_scam(self, soup, url):
        """Определение крипто-мошенничества"""
        result = {
            "is_crypto_scam": False,
            "confidence": "low",
            "indicators": [],
            "crypto_terms": [],
            "investment_claims": []
        }
        
        text = soup.get_text().lower()
        
        crypto_keywords = [
            'bitcoin', 'btc', 'ethereum', 'eth', 'crypto', 'крипта',
            'blockchain', 'blockchain', 'token', 'ico', 'airdrop',
            'майнинг', 'mining', 'пул', 'pool', 'ферма', 'farm'
        ]
        
        scam_phrases = [
            'double your bitcoin', 'удвоим биткоин', 'guaranteed profit',
            'гарантированная прибыль', 'passive income', 'пассивный доход',
            'investment opportunity', 'инвестиционная возможность',
            'limited offer', 'ограниченное предложение', 'join now',
            'присоединяйся', 'early bird', 'ранние пташки'
        ]
        
        found_crypto = []
        found_scam = []
        
        for word in crypto_keywords:
            if word in text:
                found_crypto.append(word)
                
        for phrase in scam_phrases:
            if phrase in text:
                found_scam.append(phrase)
        
        if found_crypto:
            result["crypto_terms"] = found_crypto[:5]
            
        if found_scam:
            result["investment_claims"] = found_scam[:5]
            
        if len(found_crypto) >= 3 and len(found_scam) >= 2:
            result["is_crypto_scam"] = True
            result["confidence"] = "high"
        elif len(found_crypto) >= 2 and len(found_scam) >= 1:
            result["is_crypto_scam"] = True
            result["confidence"] = "medium"
        elif len(found_crypto) >= 3:
            result["is_crypto_scam"] = True
            result["confidence"] = "low"
            
        return result

    async def _analyze_meta_tags(self, soup, url):
        """Анализ мета-тегов страницы"""
        result = {
            'title': None,
            'description': None,
            'keywords': None,
            'author': None,
            'viewport': None,
            'robots': None,
            'canonical': None,
            'og_tags': {},
            'twitter_tags': {}
        }
        
        title = soup.find('title')
        if title:
            result['title'] = title.string.strip() if title.string else None
            
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            result['description'] = meta_desc.get('content', '')
            
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        if meta_keywords:
            result['keywords'] = meta_keywords.get('content', '')
            
        for og_tag in soup.find_all('meta', property=re.compile(r'^og:')):
            result['og_tags'][og_tag.get('property')] = og_tag.get('content', '')
            
        for twitter_tag in soup.find_all('meta', attrs={'name': re.compile(r'^twitter:')}):
            result['twitter_tags'][twitter_tag.get('name')] = twitter_tag.get('content', '')
            
        return result

    async def _analyze_links(self, soup, base_url):
        """Детальный анализ всех ссылок на странице"""
        result = {
            'internal_links': [],
            'external_links': [],
            'broken_links': [],
            'mailto_links': [],
            'tel_links': [],
            'javascript_links': [],
            'total_links': 0,
            'unique_domains': set()
        }
        
        base_domain = tldextract.extract(base_url).domain
        
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            result['total_links'] += 1
            
            if href.startswith('mailto:'):
                result['mailto_links'].append(href)
            elif href.startswith('tel:'):
                result['tel_links'].append(href)
            elif href.startswith('javascript:'):
                result['javascript_links'].append(href)
            else:
                full_url = urljoin(base_url, href)
                domain = tldextract.extract(full_url).domain
                result['unique_domains'].add(domain)
                
                if domain == base_domain:
                    result['internal_links'].append(full_url)
                else:
                    result['external_links'].append(full_url)
                    
        result['unique_domains'] = list(result['unique_domains'])
        return result

    async def _analyze_page_structure(self, soup):
        """Анализ HTML структуры страницы"""
        result = {
            'has_header': False,
            'has_footer': False,
            'has_navigation': False,
            'has_sidebar': False,
            'has_main_content': False,
            'div_count': 0,
            'section_count': 0,
            'article_count': 0,
            'header_count': 0,
            'footer_count': 0,
            'nav_count': 0,
            'aside_count': 0,
            'main_count': 0,
            'table_count': 0,
            'list_count': 0,
            'heading_distribution': {}
        }
        
        result['has_header'] = bool(soup.find('header'))
        result['has_footer'] = bool(soup.find('footer'))
        result['has_navigation'] = bool(soup.find('nav'))
        result['has_sidebar'] = bool(soup.find('aside'))
        result['has_main_content'] = bool(soup.find('main'))
        
        result['div_count'] = len(soup.find_all('div'))
        result['section_count'] = len(soup.find_all('section'))
        result['article_count'] = len(soup.find_all('article'))
        result['header_count'] = len(soup.find_all('header'))
        result['footer_count'] = len(soup.find_all('footer'))
        result['nav_count'] = len(soup.find_all('nav'))
        result['aside_count'] = len(soup.find_all('aside'))
        result['main_count'] = len(soup.find_all('main'))
        result['table_count'] = len(soup.find_all('table'))
        result['list_count'] = len(soup.find_all(['ul', 'ol']))
        
        for i in range(1, 7):
            tag = f'h{i}'
            result['heading_distribution'][tag] = len(soup.find_all(tag))
            
        return result

    async def _detect_hidden_content(self, soup):
        """Поиск скрытого контента (для фишинга)"""
        result = {
            'hidden_elements': [],
            'display_none': [],
            'visibility_hidden': [],
            'opacity_zero': [],
            'position_absolute_offscreen': [],
            'hidden_inputs': []
        }
        
        for element in soup.find_all(style=re.compile(r'display:\s*none')):
            result['display_none'].append(str(element.name))
            
        for element in soup.find_all(style=re.compile(r'visibility:\s*hidden')):
            result['visibility_hidden'].append(str(element.name))
            
        for element in soup.find_all(style=re.compile(r'opacity:\s*0')):
            result['opacity_zero'].append(str(element.name))
            
        for inp in soup.find_all('input', {'type': 'hidden'}):
            result['hidden_inputs'].append({
                'name': inp.get('name', ''),
                'value': inp.get('value', '')[:50] 
            })
            
        result['hidden_elements'] = (len(result['display_none']) + 
                                    len(result['visibility_hidden']) + 
                                    len(result['opacity_zero']))
        
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
            'wells fargo', 'chase', 'citibank', 'hsbc', 'barclays',
            'kaspi', 'halyk', 'sberbank', 'alfabank'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.work', '.date',
            '.men', '.loan', '.download', '.review', '.stream', '.trade',
            '.bid', '.win', '.club', '.online', '.site', '.website'
        ]
        
        self.malicious_patterns = [
            r'<script[^>]*>.*?eval\(.*?\)',
            r'document\.write\(.*?fromCharCode',
            r'window\.location\s*=\s*["\']https?:\/\/[^"\']*\.(ru|cn|tk)',
            r'<iframe[^>]*src=["\']https?:\/\/[^"\']*\.(ru|cn|tk)',
            r'atob\(["\'][A-Za-z0-9+/=]+["\']\)',
            r'String\.fromCharCode\(.*?\)',
            r'\\x[0-9a-f]{2}',
            r'\\u[0-9a-f]{4}'
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
            'suspicious_tld': domain_info.suffix.lower() in [tld.replace('.', '') for tld in self.suspicious_tlds],
            'domain_length': len(domain_info.domain),
            'has_port': parsed.port is not None,
            'is_https': parsed.scheme == 'https'
        }
        
        return analysis
        
    async def _analyze_dns(self, domain: str) -> Dict:
        analysis = {
            'has_dns': False,
            'ip_addresses': [],
            'has_mx': False,
            'has_txt': False,
            'ns_servers': [],
            'aaaa_records': [],
            'cname_records': []
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
                
            try:
                aaaa = dns.resolver.resolve(domain, 'AAAA')
                analysis['aaaa_records'] = [str(r) for r in aaaa]
            except:
                pass
                
            try:
                cname = dns.resolver.resolve(domain, 'CNAME')
                analysis['cname_records'] = [str(r) for r in cname]
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
            'is_private': False,
            'name_servers': [],
            'status': [],
            'emails': [],
            'country': None
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
                
            if hasattr(w, 'name_servers') and w.name_servers:
                analysis['name_servers'] = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                
            if hasattr(w, 'status') and w.status:
                analysis['status'] = w.status if isinstance(w.status, list) else [w.status]
                
            if hasattr(w, 'emails') and w.emails:
                analysis['emails'] = w.emails if isinstance(w.emails, list) else [w.emails]
                
            if hasattr(w, 'country') and w.country:
                analysis['country'] = w.country
                
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
            'version': None,
            'serial_number': None,
            'signature_algorithm': None,
            'subject_alt_names': []
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
                analysis['serial_number'] = cert.get('serialNumber')
                analysis['signature_algorithm'] = cert.get('signatureAlgorithm')
                
                if 'subjectAltName' in cert:
                    analysis['subject_alt_names'] = [str(x[1]) for x in cert['subjectAltName']]
                
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
            'action_url': None,
            'has_file_upload': False,
            'has_hidden_fields': False,
            'field_names': []
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
            name = inp.get('name', '')
            if name:
                analysis['field_names'].append(name)
            
            if input_type == 'password':
                analysis['has_password'] = True
                
            if input_type == 'file':
                analysis['has_file_upload'] = True
                
            if input_type == 'hidden':
                analysis['has_hidden_fields'] = True
                
            name_lower = name.lower()
            if any(word in name_lower for word in ['card', 'cvv', 'ccv', 'credit', 'pan', 'cardnumber']):
                analysis['has_credit_card'] = True
                
        return analysis
        
    async def _analyze_script(self, script, base_url: str) -> Optional[Dict]:
        script_src = script.get('src', '')
        
        analysis = {
            'src': script_src,
            'external': False,
            'has_malicious_patterns': False,
            'patterns_found': [],
            'length': 0,
            'is_minified': False,
            'has_eval': False,
            'has_document_write': False
        }
        
        if script_src:
            if script_src.startswith('http'):
                analysis['external'] = True
            else:
                analysis['src'] = urljoin(base_url, script_src)
                
        if script.string:
            content = script.string
            analysis['length'] = len(content)
            
            lines = content.split('\n')
            if len(lines) < 10 and len(content) > 1000:
                analysis['is_minified'] = True
            
            if 'eval(' in content:
                analysis['has_eval'] = True
            if 'document.write' in content:
                analysis['has_document_write'] = True
                
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
                async with self.session.get(url, allow_redirects=True, ssl=True) as response:
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
            'has_redirect': False,
            'meta_tags': {},
            'links_analysis': {},
            'page_structure': {},
            'hidden_content': {},
            'crypto_scam': {},
            'html_content': ''  
        }
        
        try:
            async with self.session.get(url, allow_redirects=True, ssl=True) as response:
                redirects = [str(r.url) for r in response.history]
                html = await response.text()
                result['html_content'] = html  
                soup = BeautifulSoup(html, 'html.parser')
                
                result['has_redirect'] = len(redirects) > 0
                
                if len(redirects) > 2:
                    result['suspicious_patterns'].append(
                        f"Множественные редиректы ({len(redirects)})"
                    )

                casino_analysis = await self._detect_casino(soup, url)
                result["casino_analysis"] = casino_analysis
                if casino_analysis["is_casino"]:
                    result["suspicious_patterns"].append(
                        f"🎰 ОБНАРУЖЕНО КАЗИНО (уверенность: {casino_analysis['confidence']})"
                    )

                crypto_analysis = await self._detect_crypto_scam(soup, url)
                result["crypto_scam"] = crypto_analysis
                if crypto_analysis["is_crypto_scam"]:
                    result["suspicious_patterns"].append(
                        f"🪙 КРИПТО-МОШЕННИЧЕСТВО (уверенность: {crypto_analysis['confidence']})"
                    )

                login_analysis = await self._detect_login_phishing(soup, url)
                result["login_analysis"] = login_analysis
                if login_analysis["suspicious_login"]:
                    result["suspicious_patterns"].append(
                        f"Фишинговая страница входа ({login_analysis['brand_detected']})"
                    )
 
                result['meta_tags'] = await self._analyze_meta_tags(soup, url)
                
                result['links_analysis'] = await self._analyze_links(soup, url)
                
                result['page_structure'] = await self._analyze_page_structure(soup)
                
                result['hidden_content'] = await self._detect_hidden_content(soup)
                
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
                
                urgent_words = ['urgent', 'immediately', 'warning', 'alert', 'suspended', 'срочно']
                urgent_count = sum(text_content.count(word) for word in urgent_words)
                result['content_analysis']['urgent_word_count'] = urgent_count
                
                if scam_count > 5:
                    result['suspicious_patterns'].append(f'Много мошеннических слов ({scam_count})')
                    
                if urgent_count > 3:
                    result['suspicious_patterns'].append(f'Агрессивная риторика ({urgent_count} слов срочности)')
                    
                risk_score = 0
                risk_score += len(result['form_analysis']) * 5
                risk_score += len(result['suspicious_patterns']) * 10
                risk_score += len([f for f in result['form_analysis'] if f['has_password']]) * 20
                risk_score += len(result['external_resources']) * 2
                
                if crypto_analysis.get('is_crypto_scam'):
                    risk_score += 40
                    
                if casino_analysis.get('is_casino'):
                    risk_score += 30
                    
                if result['hidden_content'].get('hidden_elements', 0) > 5:
                    risk_score += 15
                    
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
        deep_scan = scan_result.get('deep_scan', {})
        
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
            
            casino = deep_scan.get('casino_analysis', {})
            features['is_casino'] = int(casino.get('is_casino', False))
            
            crypto = deep_scan.get('crypto_scam', {})
            features['is_crypto_scam'] = int(crypto.get('is_crypto_scam', False))
            
            hidden = deep_scan.get('hidden_content', {})
            features['hidden_elements_count'] = hidden.get('hidden_elements', 0)
            features['hidden_inputs_count'] = len(hidden.get('hidden_inputs', []))
            
            links = deep_scan.get('links_analysis', {})
            features['external_links_count'] = len(links.get('external_links', []))
            features['internal_links_count'] = len(links.get('internal_links', []))
            
            meta = deep_scan.get('meta_tags', {})
            features['has_meta_description'] = int(meta.get('description') is not None)
            features['has_og_tags'] = int(len(meta.get('og_tags', {})) > 0)
            
            structure = deep_scan.get('page_structure', {})
            features['div_ratio'] = structure.get('div_count', 0) / max(structure.get('section_count', 1), 1)
            
        else:
            features['num_forms'] = 0
            features['num_password_forms'] = 0
            features['num_external_scripts'] = 0
            features['num_external_resources'] = 0
            features['scam_word_count'] = 0
            features['has_brand_impersonation'] = 0
            features['num_suspicious_patterns'] = 0
            features['is_casino'] = 0
            features['is_crypto_scam'] = 0
            features['hidden_elements_count'] = 0
            features['hidden_inputs_count'] = 0
            features['external_links_count'] = 0
            features['internal_links_count'] = 0
            features['has_meta_description'] = 0
            features['has_og_tags'] = 0
            features['div_ratio'] = 0
            
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
