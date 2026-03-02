from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from urllib.parse import unquote
from typing import Optional, List
import asyncio
from datetime import datetime, timedelta
import json
import sqlite3
import hashlib
import logging
from contextlib import asynccontextmanager
import os 

from collector import CyberScanCollector, scan_url_async
from ai_model import CyberScanAI
from monitor import monitor, start_monitor_background 
from ai_model import anti_phishing_ai
from ai_auto_trainer import ai_trainer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ai_model = CyberScanAI()

def init_db():
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT NOT NULL,
                  result TEXT NOT NULL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  risk_score INTEGER,
                  is_malicious BOOLEAN)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS scan_cache
                 (url_hash TEXT PRIMARY KEY,
                  url TEXT NOT NULL,
                  result TEXT NOT NULL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  expires_at DATETIME)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS domain_reputation
                 (domain TEXT PRIMARY KEY,
                  total_scans INTEGER DEFAULT 0,
                  avg_risk_score REAL DEFAULT 0,
                  last_scan DATETIME,
                  is_malicious INTEGER DEFAULT 0,
                  first_seen DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS ai_training_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  training_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                  num_samples INTEGER,
                  accuracy REAL,
                  precision REAL,
                  recall REAL,
                  f1_score REAL,
                  model_path TEXT)''')
    
    c.execute('CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_cache_expires ON scan_cache(expires_at)')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

init_db()

ai_training_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting CyberScan AI application...")
    
    try:
        ai_model.load_model()
        logger.info("✅ CyberScanAI model loaded successfully")
    except Exception as e:
        logger.warning(f"⚠️ No pre-trained model found: {e}")
    
    try:
        anti_phishing_ai.load_model()
        logger.info("✅ Anti-Phishing AI model loaded successfully")
    except Exception as e:
        logger.warning(f"⚠️ No anti-phishing model found: {e}")
        logger.info("🔄 Training initial anti-phishing model...")
        metrics = anti_phishing_ai.train_anti_phishing(use_synthetic=True)
        anti_phishing_ai.save_model()
        logger.info(f"✅ Initial anti-phishing model trained with accuracy: {metrics['accuracy']:.3f}")
    
    asyncio.create_task(start_monitor_background())
    logger.info("🚀 Background monitor started")
    
    global ai_training_task
    ai_training_task = asyncio.create_task(auto_ai_training_loop())
    logger.info("🧠 Auto AI training loop started (every 24 hours)")
    
    yield
    
    if ai_training_task:
        ai_training_task.cancel()
    
    logger.info("👋 Shutting down CyberScan AI...")

app = FastAPI(
    title="CyberScan AI",
    description="Advanced website security scanner with ML",
    version="2.0.0", 
    lifespan=lifespan
)

templates = Jinja2Templates(directory="templates")


async def auto_ai_training_loop():
    """
    Автоматический цикл обучения AI модели
    Запускается раз в 24 часа
    """
    while True:
        try:
            await asyncio.sleep(24 * 3600)
            
            logger.info("="*60)
            logger.info("🤖 AUTO AI TRAINING CYCLE STARTED")
            logger.info("="*60)
            
            metrics = await ai_trainer.auto_train()
            
            if metrics:
                logger.info(f"✅ Auto training successful!")
                logger.info(f"   Accuracy: {metrics['accuracy']:.3f}")
                logger.info(f"   Samples: {metrics.get('samples', 0)}")
            else:
                logger.info("⏸️ Auto training skipped (not enough data)")
            
        except asyncio.CancelledError:
            logger.info("🛑 Auto AI training loop cancelled")
            break
        except Exception as e:
            logger.error(f"❌ Error in auto training loop: {e}")
            await asyncio.sleep(3600) 


def get_cached_result(url: str, max_age_hours: int = 24) -> Optional[dict]:
    url_hash = hashlib.md5(url.encode()).hexdigest()
    
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute("""SELECT result FROM scan_cache 
                 WHERE url_hash = ? AND expires_at > datetime('now')
                 ORDER BY timestamp DESC LIMIT 1""", (url_hash,))
    
    cached = c.fetchone()
    conn.close()
    
    if cached:
        return json.loads(cached[0])
    return None

def save_to_cache(url: str, result: dict, expire_hours: int = 24):
    url_hash = hashlib.md5(url.encode()).hexdigest()
    expires_at = (datetime.now() + timedelta(hours=expire_hours)).isoformat()
    
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute("""INSERT OR REPLACE INTO scan_cache (url_hash, url, result, expires_at)
                 VALUES (?, ?, ?, ?)""",
              (url_hash, url, json.dumps(result), expires_at))
    
    conn.commit()
    conn.close()

def save_scan_history(url: str, result: dict):
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    risk_score = result.get('level1', {}).get('risk_score', 0)
    is_malicious = risk_score > 50
    
    c.execute("""INSERT INTO scans (url, result, risk_score, is_malicious)
                 VALUES (?, ?, ?, ?)""",
              (url, json.dumps(result), risk_score, is_malicious))
    
    conn.commit()
    conn.close()

def update_domain_reputation(url: str, result: dict):
    from urllib.parse import urlparse
    from tldextract import extract
    
    parsed = urlparse(url)
    domain_info = extract(parsed.netloc or parsed.path)
    domain = f"{domain_info.domain}.{domain_info.suffix}".lower()
    
    risk_score = result.get('level1', {}).get('risk_score', 0)
    is_malicious = risk_score > 50
    
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute("""INSERT INTO domain_reputation (domain, total_scans, avg_risk_score, last_scan, is_malicious)
                 VALUES (?, 1, ?, datetime('now'), ?)
                 ON CONFLICT(domain) DO UPDATE SET
                 total_scans = total_scans + 1,
                 avg_risk_score = (avg_risk_score * total_scans + ?) / (total_scans + 1),
                 last_scan = datetime('now'),
                 is_malicious = CASE WHEN ? > 50 THEN 1 ELSE is_malicious END""",
              (domain, risk_score, 1 if is_malicious else 0, risk_score, risk_score))
    
    conn.commit()
    conn.close()

def prepare_result_for_template(result: dict) -> dict:
    level1 = result.get('level1', {})
    deep_scan = result.get('deep_scan', {})

    ssl_analysis = level1.get('ssl_analysis', {})
    whois_analysis = level1.get('whois_analysis', {})
    domain_age = whois_analysis.get('domain_age_days')

    casino_analysis = deep_scan.get('casino_analysis', {})
    is_casino = casino_analysis.get('is_casino', False)
    casino_indicators = casino_analysis.get('indicators', [])
    casino_confidence = casino_analysis.get('confidence', 'low')

    technical_indicators = {
        "ssl": {
            "valid": ssl_analysis.get('valid', False),
            "issuer": ssl_analysis.get('issuer_name', ssl_analysis.get('issuer', 'Unknown')),
            "days_left": ssl_analysis.get('days_until_expiry', 0),
            "protocol": ssl_analysis.get('protocol_version', 'N/A')
        },
        "dns": {
            "has_dns": level1.get('dns_analysis', {}).get('has_dns', False),
            "ip_count": len(level1.get('dns_analysis', {}).get('ip_addresses', [])),
            "has_mx": level1.get('dns_analysis', {}).get('has_mx_records', False)
        },
        "domain": {
            "age_days": domain_age,
            "registrar": whois_analysis.get('registrar', 'Unknown'),
            "creation_date": whois_analysis.get('creation_date'),
            "expiry_date": whois_analysis.get('expiry_date')
        },
        "performance": {
            "response_time": level1.get('response_time', 0),
            "page_size": level1.get('page_size', 0),
            "redirect_count": level1.get('redirect_count', 0)
        }
    }

    phishing_indicators = {
        "url_suspicious": [],
        "content_suspicious": [],
        "form_analysis": [],
        "brand_risks": []
    }

    url_features = level1.get('url_features', {})
    if url_features:
        if url_features.get('has_ip_address'):
            phishing_indicators["url_suspicious"].append("URL содержит IP-адрес вместо домена")
        if url_features.get('num_subdomains', 0) > 3:
            phishing_indicators["url_suspicious"].append(f"Много поддоменов ({url_features.get('num_subdomains')})")
        if url_features.get('url_length', 0) > 75:
            phishing_indicators["url_suspicious"].append("Длинный, запутанный URL")
        if url_features.get('has_suspicious_words'):
            phishing_indicators["url_suspicious"].append("Содержит подозрительные слова (secure, login, verify)")

    form_analysis = deep_scan.get('form_analysis', [])
    for form in form_analysis:
        form_info = {
            "action": form.get('action', ''),
            "method": form.get('method', 'GET'),
            "has_password": form.get('has_password', False),
            "has_credit_card": form.get('has_credit_card', False),
            "inputs": form.get('input_count', 0),
            "external_action": form.get('external_action', False)
        }
        
        if form_info["has_password"]:
            if form_info["external_action"]:
                form_info["risk"] = "high"
                form_info["note"] = "🚨 Пароль уходит на внешний домен!"
            else:
                form_info["risk"] = "medium"
                form_info["note"] = "⚠️ Форма входа на сайте"

            if form_info["has_credit_card"]:
               form_info["risk"] = "critical"
               form_info["note"] = "💳 Запрос данных карты - проверь HTTPS!"
            
        phishing_indicators["form_analysis"].append(form_info)

    for pattern in deep_scan.get('suspicious_patterns', [])[:10]:
        if any(word in pattern.lower() for word in ['password', 'login', 'bank', 'card', 'paypal', 'apple', 'microsoft']):
             phishing_indicators["content_suspicious"].append(f"🔴 {pattern}")
        else:
             phishing_indicators["content_suspicious"].append(f"🟠 {pattern}")
    
    if deep_scan.get('brand_impersonation'):
        brand = deep_scan['brand_impersonation']
        confidence = deep_scan.get('brand_confidence', 'medium')
        
        if confidence == 'high':
            phishing_indicators["brand_risks"].append(f"🚨 ОЧЕНЬ ПОХОЖЕ на {brand}!")
        else:
            phishing_indicators["brand_risks"].append(f"⚠️ Возможная имитация {brand}")   

    positive_indicators = {
        "security": [],
        "trust": [],
        "technical": []
    }
    
    if ssl_analysis.get('valid'):
        positive_indicators["security"].append(f"✅ SSL сертификат от {ssl_analysis.get('issuer_name', 'Unknown')}")
    if domain_age and domain_age > 365:
        positive_indicators["trust"].append(f"✅ Домену больше года ({domain_age} дней)")
    if level1.get('dns_analysis', {}).get('has_mx_records'):
        positive_indicators["technical"].append("✅ Настроена почта (не временный домен)")
    if level1.get('response_time', 999) < 1.0:
        positive_indicators["technical"].append("✅ Быстрая загрузка (хороший хостинг)")  

    negative_indicators = {
        "security": [],
        "trust": [],
        "phishing": [],
        "technical": []
    }
    
    if not ssl_analysis.get('valid'):
        negative_indicators["security"].append("❌ Нет валидного SSL")
    if domain_age and domain_age < 30:
        negative_indicators["trust"].append(f"❌ Домен создан {domain_age} дней назад (очень свежий)")
    elif domain_age and domain_age < 90:
        negative_indicators["trust"].append(f"⚠️ Домену меньше 3 месяцев ({domain_age} дней)")
    
    for flag in level1.get('risk_flags', []):
        if any(word in flag.lower() for word in ['phish', 'fake', 'spoof', 'fraud']):
            negative_indicators["phishing"].append(f"🎣 {flag}")
        else:
            negative_indicators["technical"].append(f"⚠️ {flag}")

    if is_casino:
        if casino_confidence == 'high':
            negative_indicators["phishing"].append("🎰 ОНЛАЙН-КАЗИНО (высокая уверенность)")
            casino_risk_boost = 40
        elif casino_confidence == 'medium':
            negative_indicators["phishing"].append("🎰 Подозрение на онлайн-казино")
            casino_risk_boost = 30
        else:
            negative_indicators["phishing"].append("🎰 Возможные признаки казино")
            casino_risk_boost = 20
            

        phishing_indicators["form_analysis"].append({
            "risk": "critical" if casino_confidence == "high" else "high",
            "has_password": False,
            "has_credit_card": False,
            "inputs": 0,
            "note": f"🎰 Признаки казино: {', '.join(casino_indicators[:3])}",
            "action": "",
            "external_action": False
        })
    else:
        casino_risk_boost = 0
    
    risk_score = level1.get('risk_score', 0)
    risk_score = min(100, risk_score + casino_risk_boost)  
    
    if risk_score < 30:
        status = "Safe"
        status_color = "green"
        summary = "✅ Сайт безопасен. Все ключевые проверки пройдены."
    elif risk_score < 60:
        status = "Suspicious"
        status_color = "orange"
        summary = f"⚠️ Обнаружено {len(phishing_indicators['form_analysis'])} форм и {len(negative_indicators['phishing'])} фишинговых признаков. Будьте осторожны."
    else:
        status = "Dangerous"
        status_color = "red"
        summary = f"🚨 ВЫСОКИЙ РИСК! Обнаружены признаки фишинга: {len(phishing_indicators['form_analysis'])} подозрительных форм, имитация бренда."
    
    detailed_report = {
        "technical": technical_indicators,
        "phishing": phishing_indicators,
        "positive": positive_indicators,
        "negative": negative_indicators
    }
    
    return {
        "site": result.get('url', ''),
        "status": status,
        "status_color": status_color,
        "risk": risk_score,
        "trustScore": max(0, 100 - risk_score),
        "summary": summary,
        "trustIndicators": positive_indicators["security"] + positive_indicators["trust"],
        "suspiciousIndicators": negative_indicators["phishing"] + negative_indicators["security"],
        "greenFlags": positive_indicators["security"][:3] + positive_indicators["trust"][:3],
        "redFlags": negative_indicators["phishing"][:5] + negative_indicators["security"][:5],
        "phishingForms": phishing_indicators["form_analysis"],
        "brandRisks": phishing_indicators["brand_risks"],
        "casino_detected": is_casino,
        "casino_indicators": casino_indicators,
        "casino_confidence": casino_confidence,
        "details": result,
        "detailed_report": detailed_report
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Главная страница"""
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM scans")
    total_scans = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scans WHERE is_malicious = 1")
    malicious_found = c.fetchone()[0]
    
    c.execute("SELECT COUNT(DISTINCT url) FROM scans")
    unique_domains = c.fetchone()[0]
    
    c.execute("SELECT url, risk_score, timestamp FROM scans ORDER BY timestamp DESC LIMIT 5")
    recent_scans = [{"url": row[0], "risk": row[1], "time": row[2]} for row in c.fetchall()]
    
    conn.close()
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "result": None,
        "total_scans": total_scans,
        "malicious_found": malicious_found,
        "unique_domains": unique_domains,
        "recent_scans": recent_scans
    })

@app.head("/")
async def head_home():
    return Response(status_code=200)

@app.get("/check/{url:path}", response_class=HTMLResponse)
async def check_site(request: Request, url: str):
    """Проверка одного сайта по URL"""
    decoded_url = unquote(url)
    
    if not decoded_url.startswith(('http://', 'https://')):
        decoded_url = 'https://' + decoded_url
    
    cached = get_cached_result(decoded_url)
    if cached:
        logger.info(f"Returning cached result for {decoded_url}")
        result_for_template = prepare_result_for_template(cached)
    else:
        logger.info(f"Scanning {decoded_url}...")
        
        try:
            scan_result = await scan_url_async(decoded_url)
            
            save_scan_history(decoded_url, scan_result)
            save_to_cache(decoded_url, scan_result)
            update_domain_reputation(decoded_url, scan_result)
            
            if ai_model.model is not None:
                try:
                    ai_prediction = ai_model.predict(scan_result)
                    scan_result['ai_analysis'] = ai_prediction
                except Exception as e:
                    logger.error(f"AI prediction error: {e}")
            
            result_for_template = prepare_result_for_template(scan_result)
            
        except Exception as e:
            logger.error(f"Scan error for {decoded_url}: {e}")
            result_for_template = {
                "site": decoded_url,
                "status": "Error",
                "status_color": "gray",
                "risk": 0,
                "trustScore": 0,
                "summary": f"Ошибка при сканировании: {str(e)}",
                "greenFlags": [],
                "redFlags": ["Сканирование не удалось"],
                "details": {}
            }
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "result": result_for_template
    })

@app.get("/scan", response_class=HTMLResponse)
async def scan_multiple(request: Request):
    """Сканирование списка предопределенных сайтов"""
    
    sites_to_scan = [
        "https://google.com",
        "https://facebook.com",
        "https://youtube.com",
        "http://suspicious-site.xyz",
        "https://github.com",
        "https://www.wikipedia.org",
        "https://www.kaspi.kz",

        "http://lk-bank.online/kaspi-kz",
        "http://kaspi.kz.secure-login.xyz",
        "http://paypal-verification-center.com",
        "http://apple-id-login.net",
        "http://secure-account-verify.com",

        "http://vulkan-777.com",
        "http://joycasino-bonus.top",
        "http://1xbet-zerkalo.ru",
        "http://pinup-casino.website",
        "http://casino-bez-depozita.ru",
        "http://vulkan-platinum.com",
        "http://azino777.online",

        "http://super-prize.tk",
        "http://double-your-money.ga",
        "http://crypto-bonus.xyz",
        "http://win-iphone.cf",

        "http://guaranteed-profit.online",
        "http://passive-income.work",
        "http://get-rich-quick.trade",
    ]
    
    results = []
    
    for site in sites_to_scan:  
        try:
            logger.info(f"Scanning {site}...")
            scan_result = await scan_url_async(site)
            result_for_template = prepare_result_for_template(scan_result)
            results.append(result_for_template)
        except Exception as e:
            logger.error(f"Error scanning {site}: {e}")
    
    results.sort(key=lambda x: x.get('risk', 0), reverse=True)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "result": results[0] if results else None,
        "multiple_results": results,
        "total_scanned": len(results)
    })

@app.get("/api/check/{url:path}")
async def api_check_site(url: str):
    """API endpoint для проверки сайта (возвращает JSON)"""
    decoded_url = unquote(url)
    
    if not decoded_url.startswith(('http://', 'https://')):
        decoded_url = 'https://' + decoded_url
    
    cached = get_cached_result(decoded_url)
    if cached:
        return JSONResponse({
            "cached": True,
            "result": cached
        })
    
    try:
        scan_result = await scan_url_async(decoded_url)
        
        save_scan_history(decoded_url, scan_result)
        save_to_cache(decoded_url, scan_result)
        update_domain_reputation(decoded_url, scan_result)
        
        return JSONResponse({
            "cached": False,
            "result": scan_result
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
async def api_stats():
    """API для получения статистики"""
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM scans")
    total_scans = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scans WHERE is_malicious = 1")
    malicious = c.fetchone()[0]
    
    c.execute("SELECT AVG(risk_score) FROM scans")
    avg_risk = c.fetchone()[0] or 0
    
    c.execute("""SELECT date(timestamp) as day, COUNT(*), AVG(risk_score)
                 FROM scans 
                 WHERE timestamp > datetime('now', '-7 days')
                 GROUP BY date(timestamp)
                 ORDER BY day""")
    
    daily_stats = [
        {"date": row[0], "count": row[1], "avg_risk": row[2]}
        for row in c.fetchall()
    ]
    
    c.execute("""SELECT domain, total_scans, avg_risk_score 
                 FROM domain_reputation 
                 WHERE is_malicious = 1
                 ORDER BY total_scans DESC 
                 LIMIT 10""")
    
    top_malicious = [
        {"domain": row[0], "scans": row[1], "avg_risk": row[2]}
        for row in c.fetchall()
    ]
    
    conn.close()
    
    return JSONResponse({
        "total_scans": total_scans,
        "malicious_found": malicious,
        "avg_risk": round(avg_risk, 2),
        "daily_stats": daily_stats,
        "top_malicious": top_malicious
    })

@app.get("/api/history")
async def api_history(limit: int = 50, offset: int = 0):
    """API для получения истории проверок"""
    conn = sqlite3.connect('cyberscan.db')
    c = conn.cursor()
    
    c.execute("""SELECT url, risk_score, timestamp, is_malicious
                 FROM scans 
                 ORDER BY timestamp DESC 
                 LIMIT ? OFFSET ?""", (limit, offset))
    
    scans = [
        {
            "url": row[0],
            "risk_score": row[1],
            "timestamp": row[2],
            "is_malicious": bool(row[3])
        }
        for row in c.fetchall()
    ]
    
    c.execute("SELECT COUNT(*) FROM scans")
    total = c.fetchone()[0]
    
    conn.close()
    
    return JSONResponse({
        "total": total,
        "offset": offset,
        "limit": limit,
        "scans": scans
    })

@app.post("/api/train")
async def api_train_model():
    """Ручное обучение основной модели (опционально)"""
    try:
        conn = sqlite3.connect('cyberscan.db')
        c = conn.cursor()
        
        c.execute("""SELECT url, is_malicious FROM scans 
                     WHERE is_malicious IS NOT NULL
                     ORDER BY RANDOM() LIMIT 1000""")
        
        training_data = c.fetchall()
        conn.close()
        
        if len(training_data) < 10:
            return JSONResponse({
                "success": False,
                "message": "Not enough training data (need at least 10 samples)"
            })
        
        features = []
        labels = []

        from collector import scan_url_async, CyberScanCollector
        collector = CyberScanCollector()
        
        for url, label in training_data:
            scan = await scan_url_async(url)
            features.append(collector.extract_features_for_ml(scan))
            labels.append(label)

        accuracy = ai_model.train(features, labels)
        ai_model.save_model()
        
        return JSONResponse({
            "success": True,
            "accuracy": accuracy,
            "samples": len(training_data)
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/illegal-sites")
async def get_illegal_sites(category: Optional[str] = None, limit: int = 100, offset: int = 0):
    """Получение списка отслеживаемых нелегальных сайтов"""
    try:
        sites = monitor.get_illegal_sites(category, limit, offset)
        stats = monitor.get_statistics()
        
        return JSONResponse({
            "success": True,
            "sites": sites,
            "statistics": stats,
            "total": len(sites)
        })
    except Exception as e:
        logger.error(f"Error getting illegal sites: {e}")
        return JSONResponse({
            "success": False,
            "error": str(e),
            "sites": [],
            "statistics": {"total": 0, "by_category": {}}
        })

@app.post("/api/monitor/run")
async def run_monitor_manual():
    """Ручной запуск цикла мониторинга"""
    try:
        await monitor.run_monitor_cycle()
        return JSONResponse({"success": True, "message": "Monitor cycle completed"})
    except Exception as e:
        logger.error(f"Monitor cycle error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request):
    """Страница мониторинга нелегальных сайтов"""
    try:
        stats = monitor.get_statistics()
        return templates.TemplateResponse("index.html", {
            "request": request,
            "statistics": stats
        })
    except Exception as e:
        logger.error(f"Error loading monitor page: {e}")
        return templates.TemplateResponse("index.html", {
            "request": request,
            "statistics": {"total": 0, "by_category": {}},
            "error": str(e)
        })


@app.get("/api/ai/anti-phishing/predict")
async def ai_anti_phishing_predict(url: str):
    """Предсказание фишинга с помощью Anti-Phishing AI"""
    try:
        from collector import scan_url_async
        
        scan_result = await scan_url_async(url)
        
        html_content = None
        if 'deep_scan' in scan_result and 'html_content' in scan_result:
            html_content = scan_result.get('html_content')
        

        prediction = anti_phishing_ai.predict_phishing(scan_result, html_content)
        
        return JSONResponse({
            "success": True,
            "url": url,
            "prediction": prediction
        })
        
    except Exception as e:
        logger.error(f"Anti-phishing prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ai/training-stats")
async def get_ai_training_stats():
    """Статистика обучения AI модели"""
    try:
        stats = ai_trainer.get_training_stats()
        return JSONResponse({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        logger.error(f"Error getting AI stats: {e}")
        return JSONResponse({
            'success': False,
            'error': str(e)
        }, status_code=500)

@app.post("/api/ai/train-now")
async def train_ai_now(secret: str = ""):
    """Принудительное обучение (только с секретным ключом)"""
    if secret != "cyberscan_ai_2026":
        raise HTTPException(status_code=403, detail="Forbidden")
    
    try:
        logger.info("🚀 Manual AI training triggered")
        metrics = await ai_trainer.auto_train(force=True)
        
        if metrics:
            return JSONResponse({
                'success': True,
                'message': 'AI model trained successfully',
                'metrics': {
                    'accuracy': metrics.get('accuracy', 0),
                    'precision': metrics.get('precision', 0),
                    'recall': metrics.get('recall', 0),
                    'f1': metrics.get('f1', 0),
                    'samples': metrics.get('samples', 0)
                }
            })
        else:
            return JSONResponse({
                'success': False,
                'message': 'Training failed or not enough data'
            })
            
    except Exception as e:
        logger.error(f"Manual training error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ai/model-info")
async def get_ai_model_info():
    """Информация о текущей AI модели"""
    try:
        info = {
            'model_loaded': anti_phishing_ai.model is not None,
            'features_count': len(anti_phishing_ai.phishing_features),
            'features_sample': anti_phishing_ai.phishing_features[:10],
            'brands_supported': list(anti_phishing_ai.brands.keys()),
            'model_path': anti_phishing_ai.model_path
        }
        
        stats = ai_trainer.get_training_stats()
        info['training_stats'] = stats
        
        if anti_phishing_ai.model:
            info['model_type'] = 'Ensemble (RF + GB + NN)'
        
        return JSONResponse({
            'success': True,
            'info': info
        })
        
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
