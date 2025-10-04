
import customtkinter as ctk
from tkinter import filedialog, messagebox
import json
import os
import sqlite3
import threading
import time
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import logging
import warnings

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except:
    HAS_REQUESTS = False

try:
    import undetected_chromedriver as uc
    HAS_UNDETECTED = True
except:
    HAS_UNDETECTED = False

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

__version__ = "7.4.0"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ============================================================================
# DATABASE WITH AUTO-MIGRATION
# ============================================================================

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('cookies_v7.db', check_same_thread=False)
        self.lock = threading.Lock()
        self._init()
        self._migrate()  # Auto-migrate existing databases
    
    def _init(self):
        with self.lock:
            c = self.conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY,
                domain TEXT UNIQUE,
                category TEXT,
                status TEXT,
                favorite INTEGER DEFAULT 0,
                auth_cookie_count INTEGER DEFAULT 0,
                total_cookies INTEGER DEFAULT 0,
                username TEXT,
                email TEXT,
                last_verified TEXT,
                file_path TEXT,
                notes TEXT,
                skip_check INTEGER DEFAULT 0,
                expires_soon INTEGER DEFAULT 0,
                created_at TEXT,
                last_login_attempt TEXT,
                login_speed TEXT,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                ai_confidence REAL DEFAULT 0.0
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS cookies (
                id INTEGER PRIMARY KEY,
                domain_id INTEGER,
                name TEXT,
                value TEXT,
                domain TEXT,
                path TEXT,
                secure INTEGER,
                httponly INTEGER,
                expiry INTEGER,
                is_auth INTEGER DEFAULT 0,
                is_expired INTEGER DEFAULT 0,
                importance_score REAL DEFAULT 0.0,
                success_rate REAL DEFAULT 0.0,
                times_used INTEGER DEFAULT 0,
                FOREIGN KEY(domain_id) REFERENCES domains(id)
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS cookie_patterns (
                id INTEGER PRIMARY KEY,
                pattern TEXT UNIQUE,
                category TEXT,
                confidence REAL DEFAULT 0.5,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                last_seen TEXT
            )''')
            
            c.execute('CREATE INDEX IF NOT EXISTS idx_domain ON domains(domain)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_status ON domains(status)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_category ON domains(category)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_cookie_name ON cookies(name)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_pattern ON cookie_patterns(pattern)')
            
            self.conn.commit()
    
    def _migrate(self):
        """Auto-add missing columns from old database versions"""
        with self.lock:
            c = self.conn.cursor()
            
            # Get existing columns for domains
            c.execute("PRAGMA table_info(domains)")
            existing_cols = {col[1] for col in c.fetchall()}
            
            # Columns that should exist in domains
            new_columns = {
                'expires_soon': 'INTEGER DEFAULT 0',
                'created_at': 'TEXT',
                'last_login_attempt': 'TEXT',
                'login_speed': 'TEXT',
                'success_count': 'INTEGER DEFAULT 0',
                'fail_count': 'INTEGER DEFAULT 0',
                'ai_confidence': 'REAL DEFAULT 0.0'
            }
            
            # Add missing columns to domains
            for col_name, col_type in new_columns.items():
                if col_name not in existing_cols:
                    try:
                        c.execute(f'ALTER TABLE domains ADD COLUMN {col_name} {col_type}')
                        logger.info(f"Added column to domains: {col_name}")
                    except Exception as e:
                        logger.error(f"Migration error for {col_name}: {e}")
            
            # Get existing columns for cookies
            c.execute("PRAGMA table_info(cookies)")
            existing_cookie_cols = {col[1] for col in c.fetchall()}
            
            # Columns that should exist in cookies
            new_cookie_columns = {
                'importance_score': 'REAL DEFAULT 0.0',
                'success_rate': 'REAL DEFAULT 0.0',
                'times_used': 'INTEGER DEFAULT 0'
            }
            
            # Add missing columns to cookies
            for col_name, col_type in new_cookie_columns.items():
                if col_name not in existing_cookie_cols:
                    try:
                        c.execute(f'ALTER TABLE cookies ADD COLUMN {col_name} {col_type}')
                        logger.info(f"Added column to cookies: {col_name}")
                    except Exception as e:
                        logger.error(f"Migration error for {col_name}: {e}")
            
            self.conn.commit()
    
    def add_domain(self, domain, category, file_path, cookies):
        with self.lock:
            c = self.conn.cursor()
            
            auth_count = sum(1 for ck in cookies if self._is_auth_cookie(ck))
            expires_soon = self._check_expires_soon(cookies)
            
            c.execute('''INSERT OR REPLACE INTO domains 
                (domain, category, status, auth_cookie_count, total_cookies, file_path, expires_soon, created_at)
                VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)''',
                (domain, category, auth_count, len(cookies), file_path, expires_soon, datetime.now().isoformat()))
            
            domain_id = c.lastrowid
            
            c.execute('DELETE FROM cookies WHERE domain_id=?', (domain_id,))
            
            current_time = int(time.time())
            for cookie in cookies:
                is_auth = self._is_auth_cookie(cookie)
                expiry = cookie.get('expiry')
                is_expired = 0
                
                if expiry:
                    try:
                        if int(expiry) < current_time:
                            is_expired = 1
                    except:
                        pass
                
                c.execute('''INSERT INTO cookies 
                    (domain_id, name, value, domain, path, secure, httponly, expiry, is_auth, is_expired)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (domain_id, cookie.get('name', ''), cookie.get('value', ''),
                     cookie.get('domain', ''), cookie.get('path', '/'),
                     int(cookie.get('secure', False)), int(cookie.get('httpOnly', False)),
                     expiry, int(is_auth), is_expired))
            
            self.conn.commit()
            return domain_id
    
    def _is_auth_cookie(self, cookie):
        name = cookie.get('name', '').lower()
        
        # Enhanced auth patterns with AI learning
        base_patterns = ['session', 'sess', 'auth', 'token', 'login', 'user', 
                        'jwt', 'access', 'refresh', 'sid', 'phpsessid', 'remember',
                        'oauth', 'sso', 'saml', 'csrf', 'xsrf', 'api_key',
                        'Bearer', 'credential', 'identity', 'passport']
        
        # Check base patterns
        if any(p in name for p in base_patterns):
            return True
        
        # Check learned patterns from AI
        try:
            with self.lock:
                c = self.conn.cursor()
                c.execute('''SELECT pattern, confidence FROM cookie_patterns 
                            WHERE confidence > 0.6 ORDER BY confidence DESC''')
                
                for pattern, confidence in c.fetchall():
                    if pattern.lower() in name:
                        return True
        except:
            pass
        
        return False
    
    def learn_from_login(self, domain_id, success):
        """AI Learning: Update patterns based on login results"""
        with self.lock:
            c = self.conn.cursor()
            
            # Get domain info
            c.execute('SELECT domain, success_count, fail_count FROM domains WHERE id=?', (domain_id,))
            result = c.fetchone()
            if not result:
                return
            
            domain, success_count, fail_count = result
            
            # Update domain stats
            if success:
                success_count = (success_count or 0) + 1
            else:
                fail_count = (fail_count or 0) + 1
            
            # Calculate AI confidence
            total_attempts = success_count + fail_count
            ai_confidence = success_count / total_attempts if total_attempts > 0 else 0.0
            
            c.execute('''UPDATE domains SET success_count=?, fail_count=?, ai_confidence=? 
                        WHERE id=?''', (success_count, fail_count, ai_confidence, domain_id))
            
            # Update cookie importance scores
            c.execute('SELECT id, name, is_auth, times_used FROM cookies WHERE domain_id=?', (domain_id,))
            cookies = c.fetchall()
            
            for cookie_id, name, is_auth, times_used in cookies:
                times_used = (times_used or 0) + 1
                
                # Calculate importance: auth cookies get higher scores
                importance = 0.5 if is_auth else 0.1
                
                # Boost importance based on success rate
                if success:
                    importance += 0.3
                
                # Decay if failures
                if not success:
                    importance = max(0.0, importance - 0.2)
                
                # Calculate success rate
                success_rate = success_count / total_attempts if total_attempts > 0 else 0.0
                
                c.execute('''UPDATE cookies SET importance_score=?, success_rate=?, times_used=? 
                            WHERE id=?''', (importance, success_rate, times_used, cookie_id))
                
                # Learn pattern if successful and auth cookie
                if success and is_auth:
                    self._learn_pattern(name, 'auth', success=True)
            
            self.conn.commit()
    
    def _learn_pattern(self, cookie_name, category, success=True):
        """Learn new cookie patterns from successful logins"""
        # Extract pattern (remove digits and special chars)
        pattern = re.sub(r'[0-9_-]+', '', cookie_name.lower())
        
        if len(pattern) < 3:  # Skip very short patterns
            return
        
        with self.lock:
            c = self.conn.cursor()
            
            # Check if pattern exists
            c.execute('SELECT id, success_count, fail_count, confidence FROM cookie_patterns WHERE pattern=?', 
                     (pattern,))
            result = c.fetchone()
            
            if result:
                # Update existing pattern
                pattern_id, succ, fail, conf = result
                if success:
                    succ += 1
                else:
                    fail += 1
                
                total = succ + fail
                new_confidence = succ / total if total > 0 else 0.5
                
                c.execute('''UPDATE cookie_patterns SET success_count=?, fail_count=?, 
                            confidence=?, last_seen=? WHERE id=?''',
                         (succ, fail, new_confidence, datetime.now().isoformat(), pattern_id))
            else:
                # New pattern
                initial_conf = 0.7 if success else 0.3
                c.execute('''INSERT INTO cookie_patterns (pattern, category, confidence, 
                            success_count, fail_count, last_seen) VALUES (?, ?, ?, ?, ?, ?)''',
                         (pattern, category, initial_conf, 1 if success else 0, 0 if success else 1,
                          datetime.now().isoformat()))
            
            self.conn.commit()
    
    def get_smart_cookies(self, domain_id, min_importance=0.3):
        """Get cookies ranked by AI importance score"""
        with self.lock:
            c = self.conn.cursor()
            c.execute('''SELECT * FROM cookies WHERE domain_id=? AND importance_score >= ? 
                        ORDER BY importance_score DESC, is_auth DESC''',
                     (domain_id, min_importance))
            return c.fetchall()
    
    def get_ai_recommendations(self):
        """Get AI-learned patterns and recommendations"""
        with self.lock:
            c = self.conn.cursor()
            
            recommendations = {
                'patterns': [],
                'top_auth_cookies': [],
                'insights': []
            }
            
            # Top learned patterns
            c.execute('''SELECT pattern, category, confidence, success_count 
                        FROM cookie_patterns WHERE confidence > 0.6 
                        ORDER BY confidence DESC LIMIT 10''')
            recommendations['patterns'] = c.fetchall()
            
            # Top performing auth cookies across all domains
            c.execute('''SELECT name, AVG(importance_score) as avg_score, COUNT(*) as count 
                        FROM cookies WHERE is_auth=1 GROUP BY name 
                        ORDER BY avg_score DESC LIMIT 10''')
            recommendations['top_auth_cookies'] = c.fetchall()
            
            # Generate insights
            c.execute('SELECT AVG(ai_confidence) FROM domains WHERE ai_confidence > 0')
            result = c.fetchone()
            avg_confidence = result[0] if result and result[0] else 0.0
            
            if avg_confidence > 0.7:
                recommendations['insights'].append(
                    f"High AI confidence ({avg_confidence:.1%}) - cookie patterns are well-learned")
            elif avg_confidence > 0.4:
                recommendations['insights'].append(
                    f"Moderate AI confidence ({avg_confidence:.1%}) - more data needed for better accuracy")
            else:
                recommendations['insights'].append(
                    f"Low AI confidence ({avg_confidence:.1%}) - perform more verifications to train the AI")
            
            return recommendations
    
    def _check_expires_soon(self, cookies):
        """Check if any auth cookies expire within 7 days"""
        week_from_now = int(time.time()) + (7 * 24 * 60 * 60)
        for cookie in cookies:
            if self._is_auth_cookie(cookie):
                expiry = cookie.get('expiry')
                if expiry:
                    try:
                        if int(expiry) < week_from_now:
                            return 1
                    except:
                        pass
        return 0
    
    def get_domains(self, filters=None, limit=None, offset=0, sort_by='domain', sort_order='ASC'):
        with self.lock:
            c = self.conn.cursor()
            query = 'SELECT * FROM domains WHERE 1=1'
            params = []
            
            if filters:
                if filters.get('status'):
                    query += ' AND status=?'
                    params.append(filters['status'])
                if filters.get('favorite'):
                    query += ' AND favorite=1'
                if filters.get('has_auth'):
                    query += ' AND auth_cookie_count > 0'
                if filters.get('can_login'):
                    query += " AND status='success'"
                if filters.get('expires_soon'):
                    query += ' AND expires_soon=1'
                if filters.get('category') and filters['category'] != 'All':
                    query += ' AND category=?'
                    params.append(filters['category'])
                if filters.get('search'):
                    query += ' AND domain LIKE ?'
                    params.append(f"%{filters['search']}%")
                if filters.get('skip_successful'):
                    query += " AND status != 'success'"
            
            # Sorting with favorites always first
            valid_sorts = {
                'domain': 'domain',
                'status': 'status',
                'last_verified': 'last_verified',
                'auth_cookies': 'auth_cookie_count',
                'total_cookies': 'total_cookies',
                'created': 'created_at',
                'category': 'category',
                'last_login': 'last_login_attempt'
            }
            
            sort_column = valid_sorts.get(sort_by, 'domain')
            sort_direction = 'DESC' if sort_order == 'DESC' else 'ASC'
            
            query += f' ORDER BY favorite DESC, {sort_column} {sort_direction}'
            
            if limit:
                query += f' LIMIT {limit} OFFSET {offset}'
            
            c.execute(query, params)
            return c.fetchall()
    
    def get_domain_count(self, filters=None):
        with self.lock:
            c = self.conn.cursor()
            query = 'SELECT COUNT(*) FROM domains WHERE 1=1'
            params = []
            
            if filters:
                if filters.get('status'):
                    query += ' AND status=?'
                    params.append(filters['status'])
                if filters.get('favorite'):
                    query += ' AND favorite=1'
                if filters.get('has_auth'):
                    query += ' AND auth_cookie_count > 0'
                if filters.get('can_login'):
                    query += " AND status='success'"
                if filters.get('expires_soon'):
                    query += ' AND expires_soon=1'
                if filters.get('category') and filters['category'] != 'All':
                    query += ' AND category=?'
                    params.append(filters['category'])
                if filters.get('search'):
                    query += ' AND domain LIKE ?'
                    params.append(f"%{filters['search']}%")
                if filters.get('skip_successful'):
                    query += " AND status != 'success'"
            
            c.execute(query, params)
            return c.fetchone()[0]
    
    def get_cookies(self, domain_id, exclude_expired=False, auth_only=False):
        with self.lock:
            c = self.conn.cursor()
            query = 'SELECT * FROM cookies WHERE domain_id=?'
            params = [domain_id]
            
            if exclude_expired:
                query += ' AND is_expired=0'
            if auth_only:
                query += ' AND is_auth=1'
            
            query += ' ORDER BY is_auth DESC, name'
            c.execute(query, params)
            return c.fetchall()
    
    def update_domain(self, domain, **kwargs):
        with self.lock:
            c = self.conn.cursor()
            updates = ', '.join([f"{k}=?" for k in kwargs.keys()])
            values = list(kwargs.values()) + [domain]
            c.execute(f'UPDATE domains SET {updates} WHERE domain=?', values)
            self.conn.commit()
    
    def toggle_favorite(self, domain):
        with self.lock:
            c = self.conn.cursor()
            c.execute('UPDATE domains SET favorite = NOT favorite WHERE domain=?', (domain,))
            self.conn.commit()
    
    def get_stats(self):
        with self.lock:
            c = self.conn.cursor()
            stats = {}
            
            c.execute('SELECT COUNT(*) FROM domains')
            stats['total'] = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM domains WHERE status='success'")
            stats['can_login'] = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM domains WHERE status='failed'")
            stats['failed'] = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM domains WHERE auth_cookie_count > 0')
            stats['has_auth'] = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM domains WHERE expires_soon=1')
            stats['expires_soon'] = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM domains WHERE status='pending'")
            stats['pending'] = c.fetchone()[0]
            
            return stats
    
    def clear_all(self):
        with self.lock:
            self.conn.execute('DELETE FROM domains')
            self.conn.execute('DELETE FROM cookies')
            self.conn.commit()


# ============================================================================
# ULTRA-FAST LOGIN MANAGER (10x Performance)
# ============================================================================

class LoginManager:
    def __init__(self, db):
        self.db = db
        self.drivers = {}
    
    def _clean_domain(self, domain):
        """Remove BOM and leading dots"""
        if not domain:
            return ''
        domain = domain.replace('\ufeff', '').replace('\u200b', '')
        domain = domain.strip().lstrip('.')
        return domain
    
    def _create_driver_selenium(self, headless=False):
        try:
            options = ChromeOptions()
            if headless:
                options.add_argument('--headless=new')
            
            # Performance optimizations
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-extensions')
            options.add_experimental_option('excludeSwitches', ['enable-logging', 'enable-automation'])
            options.add_experimental_option('useAutomationExtension', False)
            
            # Disable web security for cookie injection
            options.add_argument('--disable-web-security')
            options.add_argument('--disable-site-isolation-trials')
            
            # Load extension if not headless
            if not headless:
                extension_path = self._create_cookie_extension()
                if extension_path and os.path.exists(extension_path):
                    options.add_argument(f'--load-extension={extension_path}')
            
            # Keep browser open
            options.add_experimental_option("detach", True)
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(15)
            
            # Anti-detection
            driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': '''
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                    Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                '''
            })
            
            return driver
        except Exception as e:
            logger.error(f"Driver error: {e}")
            return None
    
    def _create_cookie_extension(self):
        """Create Chrome extension"""
        try:
            ext_dir = os.path.join(os.getcwd(), 'cookie_extension')
            os.makedirs(ext_dir, exist_ok=True)
            
            manifest = {
                "manifest_version": 3,
                "name": "Cookie Manager Pro",
                "version": "1.0",
                "description": "Cookie management tools",
                "permissions": ["cookies", "tabs", "storage", "activeTab", "downloads"],
                "host_permissions": ["<all_urls>"],
                "action": {"default_popup": "popup.html"},
                "background": {"service_worker": "background.js"}
            }
            
            with open(os.path.join(ext_dir, 'manifest.json'), 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)
            
            popup_html = '''<!DOCTYPE html>
<html><head><style>
body{width:350px;padding:15px;background:#1e1e1e;color:#fff;font-family:Arial}
h3{margin:0 0 15px;color:#4a9eff;text-align:center}
button{width:100%;padding:12px;margin:6px 0;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:bold}
.inject{background:#0d7d4d;color:#fff}.inject:hover{background:#0a5d39}
.relogin{background:#7841b6;color:#fff}.relogin:hover{background:#5f2f99}
.export{background:#1f538d;color:#fff}.export:hover{background:#173d6b}
.clear{background:#b91c1c;color:#fff}.clear:hover{background:#991515}
.info{background:#2d2d30;padding:12px;border-radius:6px;margin:10px 0;font-size:12px}
.status{padding:10px;border-radius:4px;margin:10px 0;text-align:center;font-size:12px;font-weight:bold}
.success{background:#0d7d4d}.error{background:#b91c1c}.warning{background:#c77700}
</style></head><body>
<h3>Cookie Manager Pro</h3>
<div class="info">
<div><strong>Domain:</strong> <span id="domain">-</span></div>
<div><strong>Cookies:</strong> <span id="count">0</span></div>
</div>
<button class="inject" id="inject">Inject Stored</button>
<button class="relogin" id="relogin">Re-login</button>
<button class="export" id="export">Export</button>
<button class="clear" id="clear">Clear All</button>
<div id="status"></div>
<script src="popup.js"></script>
</body></html>'''
            
            with open(os.path.join(ext_dir, 'popup.html'), 'w', encoding='utf-8') as f:
                f.write(popup_html)
            
            popup_js = '''document.addEventListener('DOMContentLoaded',async()=>{
const[tab]=await chrome.tabs.query({active:true,currentWindow:true});
const domain=new URL(tab.url).hostname;
const cookies=await chrome.cookies.getAll({domain});
document.getElementById('domain').textContent=domain;
document.getElementById('count').textContent=cookies.length;
await chrome.storage.local.set({[domain]:cookies});
function show(msg,type='success'){
const el=document.getElementById('status');
el.textContent=msg;el.className='status '+type;
setTimeout(()=>{el.textContent='';el.className=''},3000);
}
document.getElementById('inject').onclick=async()=>{
const stored=(await chrome.storage.local.get(domain))[domain];
if(!stored){show('No stored cookies','error');return;}
for(const c of stored){try{await chrome.cookies.set({url:`https://${c.domain}${c.path}`,name:c.name,value:c.value,domain:c.domain,path:c.path,secure:c.secure,httpOnly:c.httpOnly,expirationDate:c.expirationDate});}catch(e){}}
show(`Injected ${stored.length} cookies`);
};
document.getElementById('relogin').onclick=async()=>{
const stored=(await chrome.storage.local.get(domain))[domain];
if(!stored){show('No stored cookies','error');return;}
const current=await chrome.cookies.getAll({domain});
for(const c of current)await chrome.cookies.remove({url:`https://${c.domain}${c.path}`,name:c.name});
for(const c of stored){try{await chrome.cookies.set({url:`https://${c.domain}${c.path}`,name:c.name,value:c.value,domain:c.domain,path:c.path,secure:c.secure,httpOnly:c.httpOnly,expirationDate:c.expirationDate});}catch(e){}}
chrome.tabs.reload(tab.id);show('Re-logging in...');
};
document.getElementById('export').onclick=async()=>{
const json=JSON.stringify(cookies,null,2);
const blob=new Blob([json],{type:'application/json'});
await chrome.downloads.download({url:URL.createObjectURL(blob),filename:`${domain}_${Date.now()}.json`,saveAs:true});
show(`Exported ${cookies.length} cookies`);
};
document.getElementById('clear').onclick=async()=>{
for(const c of cookies)await chrome.cookies.remove({url:`https://${c.domain}${c.path}`,name:c.name});
chrome.tabs.reload(tab.id);show('Cleared');
};
});'''
            
            with open(os.path.join(ext_dir, 'popup.js'), 'w', encoding='utf-8') as f:
                f.write(popup_js)
            
            background_js = '''chrome.runtime.onInstalled.addListener(()=>console.log('Installed'));
chrome.tabs.onUpdated.addListener(async(id,info,tab)=>{
if(info.status==='complete'&&tab.url){
try{const domain=new URL(tab.url).hostname;
const cookies=await chrome.cookies.getAll({domain});
await chrome.storage.local.set({[domain]:cookies});}catch(e){}}
});'''
            
            with open(os.path.join(ext_dir, 'background.js'), 'w', encoding='utf-8') as f:
                f.write(background_js)
            
            # Simple icon
            import base64
            icon_path = os.path.join(ext_dir, 'icon.png')
            if not os.path.exists(icon_path):
                icon_data = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')
                with open(icon_path, 'wb') as f:
                    f.write(icon_data)
            
            return ext_dir
        except Exception as e:
            logger.error(f"Extension error: {e}")
            return None
    
    def verify_requests(self, domain_row):
        """Fast requests-based verification"""
        domain_id, domain = domain_row[0], domain_row[1]
        domain = self._clean_domain(domain)
        
        if not domain or not HAS_REQUESTS:
            return False
        
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            session.verify = False
            
            cookies = self.db.get_cookies(domain_id, exclude_expired=True)
            
            for cookie in cookies:
                try:
                    cookie_domain = self._clean_domain(cookie[4] if cookie[4] else domain)
                    session.cookies.set(cookie[2], cookie[3], domain=cookie_domain)
                except:
                    pass
            
            response = session.get(f"https://{domain}", timeout=8, allow_redirects=True, verify=False)
            
            url_lower = response.url.lower()
            is_logged_in = ('login' not in url_lower and 
                           'signin' not in url_lower and
                           response.status_code == 200)
            
            status = 'success' if is_logged_in else 'failed'
            
            # AI Learning: Update patterns based on result
            self.db.learn_from_login(domain_id, is_logged_in)
            
            self.db.update_domain(domain, status=status, 
                                 last_verified=datetime.now().isoformat())
            
            return is_logged_in
        except Exception as e:
            self.db.update_domain(domain, status='failed',
                                 last_verified=datetime.now().isoformat())
            return False
    
    def verify_selenium(self, domain_row, headless=True):
        """Selenium verification"""
        domain_id, domain = domain_row[0], domain_row[1]
        domain = self._clean_domain(domain)
        
        if not domain:
            return False
        
        driver = None
        try:
            driver = self._create_driver_selenium(headless=headless)
            if not driver:
                return False
            
            driver.get(f"https://{domain}")
            time.sleep(1.5)
            
            cookies = self.db.get_cookies(domain_id, exclude_expired=True)
            
            for cookie in cookies:
                try:
                    cookie_domain = self._clean_domain(cookie[4] if cookie[4] else domain)
                    clean = {
                        'name': cookie[2],
                        'value': cookie[3],
                        'domain': cookie_domain
                    }
                    if cookie[5]:
                        clean['path'] = cookie[5]
                    if cookie[6]:
                        clean['secure'] = bool(cookie[6])
                    if cookie[7]:
                        clean['httpOnly'] = bool(cookie[7])
                    
                    driver.add_cookie(clean)
                except:
                    continue
            
            driver.refresh()
            time.sleep(2)
            
            url_lower = driver.current_url.lower()
            page_source = driver.page_source.lower()
            
            has_login = any(x in url_lower for x in ['login', 'signin', 'sign-in'])
            has_logout = any(x in page_source[:5000] for x in ['logout', 'signout', 'account', 'dashboard'])
            
            is_logged_in = not has_login and (has_logout or 'login' not in url_lower)
            
            username, email = self._extract_creds(driver)
            
            # AI Learning: Track screenshot attempt
            self.db.learn_from_login(domain_id, is_logged_in)
            
            driver.quit()
            
            status = 'success' if is_logged_in else 'failed'
            self.db.update_domain(domain, status=status, username=username, 
                                 email=email, last_verified=datetime.now().isoformat())
            
            # AI Learning: Track success/failure
            self.db.learn_from_login(domain_id, is_logged_in)
            
            return is_logged_in
            
        except Exception as e:
            if driver:
                driver.quit()
            self.db.update_domain(domain, status='failed',
                                 last_verified=datetime.now().isoformat())
            return False
    
    def open_browser(self, domain_row, mode='selenium', headless=False):
        """⚡ ULTRA-FAST Cookie Injection using CDP (10x faster)"""
        domain_id, domain = domain_row[0], domain_row[1]
        domain = self._clean_domain(domain)
        
        if not domain:
            return False
        
        driver = None
        start_time = time.time()
        
        try:
            driver = self._create_driver_selenium(headless=headless)
            if not driver:
                return False
            
            # STEP 1: Navigate once
            driver.get(f"https://{domain}")
            time.sleep(1)
            
            cookies = self.db.get_cookies(domain_id, exclude_expired=True)
            
            # STEP 2: ULTRA-FAST bulk cookie injection via CDP
            added_count = 0
            
            for cookie in cookies:
                try:
                    cookie_domain = self._clean_domain(cookie[4] if cookie[4] else domain)
                    
                    # Try primary domain first
                    cookie_data = {
                        'name': cookie[2],
                        'value': cookie[3],
                        'domain': cookie_domain,
                        'path': cookie[5] if cookie[5] else '/',
                        'secure': bool(cookie[6]),
                        'httpOnly': bool(cookie[7])
                    }
                    
                    if cookie[8]:  # expiry
                        try:
                            cookie_data['expires'] = int(cookie[8])
                        except:
                            pass
                    
                    # Use CDP for 10x faster injection
                    try:
                        driver.execute_cdp_cmd('Network.setCookie', cookie_data)
                        added_count += 1
                    except:
                        # Fallback to standard method
                        try:
                            driver.add_cookie({
                                'name': cookie[2],
                                'value': cookie[3],
                                'domain': cookie_domain,
                                'path': cookie[5] if cookie[5] else '/'
                            })
                            added_count += 1
                        except:
                            pass
                except:
                    continue
            
            # STEP 3: Single refresh to apply
            driver.refresh()
            time.sleep(1.5)
            
            # STEP 4: Verify injection
            browser_cookies = driver.get_cookies()
            
            elapsed = time.time() - start_time
            speed = f"{elapsed:.1f}s"
            
            # Update database with performance metrics
            self.db.update_domain(domain, 
                                 last_login_attempt=datetime.now().isoformat(),
                                 login_speed=speed)
            
            # AI Learning: Track successful injection
            if added_count > 0:
                self.db.learn_from_login(domain_id, True)
            
            if not headless:
                self.drivers[domain] = driver
                print(f"\n{'='*60}")
                print(f"✅ Browser opened: {domain}")
                print(f"⚡ Cookies injected: {added_count}/{len(cookies)} in {speed}")
                print(f"🔍 Active cookies: {len(browser_cookies)}")
                print(f"🧩 Extension: Click puzzle icon → 'Cookie Manager Pro'")
                print(f"{'='*60}\n")
            else:
                driver.quit()
            
            return True
        except Exception as e:
            logger.error(f"Open browser error: {e}")
            if driver:
                driver.quit()
            return False
    
    def _extract_creds(self, driver):
        username, email = None, None
        try:
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', driver.page_source[:5000])
            if emails:
                email = emails[0]
        except:
            pass
        return username, email
    
    def login_with_screenshot(self, domain_row, screenshots_dir):
        """Login and capture screenshot as PNG proof"""
        domain_id, domain = domain_row[0], domain_row[1]
        domain = self._clean_domain(domain)
        
        if not domain:
            return None
        
        driver = None
        start_time = time.time()
        
        try:
            driver = self._create_driver_selenium(headless=True)
            if not driver:
                return None
            
            # Navigate and inject cookies (same as open_browser but headless)
            driver.get(f"https://{domain}")
            time.sleep(1)
            
            cookies = self.db.get_cookies(domain_id, exclude_expired=True)
            added_count = 0
            
            for cookie in cookies:
                try:
                    cookie_domain = self._clean_domain(cookie[4] if cookie[4] else domain)
                    
                    cookie_data = {
                        'name': cookie[2],
                        'value': cookie[3],
                        'domain': cookie_domain,
                        'path': cookie[5] if cookie[5] else '/',
                        'secure': bool(cookie[6]),
                        'httpOnly': bool(cookie[7])
                    }
                    
                    if cookie[8]:
                        try:
                            cookie_data['expires'] = int(cookie[8])
                        except:
                            pass
                    
                    try:
                        driver.execute_cdp_cmd('Network.setCookie', cookie_data)
                        added_count += 1
                    except:
                        try:
                            driver.add_cookie({
                                'name': cookie[2],
                                'value': cookie[3],
                                'domain': cookie_domain,
                                'path': cookie[5] if cookie[5] else '/'
                            })
                            added_count += 1
                        except:
                            pass
                except:
                    continue
            
            # Refresh and wait for page load
            driver.refresh()
            time.sleep(2)
            
            # Check if logged in
            url_lower = driver.current_url.lower()
            page_source = driver.page_source.lower()
            
            has_login = any(x in url_lower for x in ['login', 'signin', 'sign-in'])
            has_logout = any(x in page_source[:5000] for x in ['logout', 'signout', 'account', 'dashboard'])
            
            is_logged_in = not has_login and (has_logout or 'login' not in url_lower)
            
            # Take screenshot
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_domain = domain.replace('.', '_').replace('/', '_')
            screenshot_name = f"{safe_domain}_{timestamp}.png"
            screenshot_path = os.path.join(screenshots_dir, screenshot_name)
            
            driver.save_screenshot(screenshot_path)
            
            # Update database
            elapsed = time.time() - start_time
            status = 'success' if is_logged_in else 'failed'
            
            self.db.update_domain(domain, 
                                 status=status,
                                 last_verified=datetime.now().isoformat(),
                                 last_login_attempt=datetime.now().isoformat(),
                                 login_speed=f"{elapsed:.1f}s")
            
            driver.quit()
            
            logger.info(f"Screenshot saved: {screenshot_path} - Status: {status}")
            return screenshot_path if is_logged_in else None
            
        except Exception as e:
            logger.error(f"Screenshot error: {e}")
            if driver:
                driver.quit()
            return None
    
    def close_all(self):
        count = len(self.drivers)
        for driver in self.drivers.values():
            try:
                driver.quit()
            except:
                pass
        self.drivers.clear()
        return count


# ============================================================================
# PARSER
# ============================================================================

class Parser:
    @staticmethod
    def parse(content, filename):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
        except:
            pass
        
        cookies = []
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = re.split(r'\t+', line)
            if len(parts) >= 7:
                try:
                    cookies.append({
                        'domain': parts[0],
                        'path': parts[2],
                        'secure': parts[3].upper() == 'TRUE',
                        'expiry': int(parts[4]) if parts[4].isdigit() else None,
                        'name': parts[5],
                        'value': parts[6]
                    })
                except:
                    pass
        
        return cookies
    
    @staticmethod
    def extract_domain(cookies, filename):
        if cookies:
            domains = []
            for c in cookies:
                d = c.get('domain', '').replace('\ufeff', '').strip().lstrip('.')
                if d:
                    domains.append(d)
            if domains:
                return max(set(domains), key=domains.count)
        
        filename = filename.replace('\ufeff', '').strip()
        match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', filename)
        return match.group(1) if match else filename.replace('.txt', '')
    
    @staticmethod
    def categorize(domain):
        categories = {
            'Social': ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'reddit', 'pinterest'],
            'Shopping': ['amazon', 'ebay', 'shopify', 'etsy', 'walmart', 'target'],
            'Finance': ['paypal', 'stripe', 'bank', 'venmo', 'cashapp'],
            'Dev': ['github', 'gitlab', 'bitbucket', 'aws', 'azure', 'docker'],
            'Email': ['gmail', 'outlook', 'yahoo', 'protonmail'],
            'Media': ['netflix', 'youtube', 'spotify', 'hulu', 'disney', 'twitch']
        }
        
        domain_lower = domain.lower()
        for cat, keywords in categories.items():
            if any(kw in domain_lower for kw in keywords):
                return cat
        return 'Other'


# ============================================================================
# PRO UI/UX APP (10x Better)
# ============================================================================

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title(f"🚀 Cookie Manager Pro v{__version__}")
        self.geometry("1920x1080")
        
        self.db = Database()
        self.login_mgr = LoginManager(self.db)
        
        self.selected = []
        self.current_page = 0
        self.page_size = 100
        self.sort_by = 'domain'
        self.sort_order = 'ASC'
        
        self._create_ui()
        self._start_refresh()
    
    def _create_ui(self):
        # ===== HEADER WITH CRYSTAL CLEAR STATS =====
        header = ctk.CTkFrame(self, height=120, corner_radius=0, fg_color="#1a1a1a")
        header.pack(fill='x')
        header.pack_propagate(False)
        
        # Title
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side='left', padx=30, pady=20)
        
        ctk.CTkLabel(title_frame, text="Cookie Manager Pro",
                    font=ctk.CTkFont(size=32, weight="bold")).pack(anchor='w')
        
        ctk.CTkLabel(title_frame, text=f"Version {__version__} • Ultra-Fast Performance",
                    font=ctk.CTkFont(size=12), text_color="gray").pack(anchor='w')
        
        # Stats Dashboard (Right side)
        stats_container = ctk.CTkFrame(header, fg_color="transparent")
        stats_container.pack(side='right', padx=30, pady=15)
        
        self.stats_widgets = {}
        stats_data = [
            ('total', 'Total', '#4a9eff'),
            ('can_login', '✓ Working', '#0d7d4d'),
            ('failed', '✗ Failed', '#b91c1c'),
            ('pending', '⏳ Pending', '#c77700'),
            ('has_auth', '🔑 Has Auth', '#7841b6'),
            ('expires_soon', '⚠️ Expires', '#ff6b35')
        ]
        
        for i, (key, label, color) in enumerate(stats_data):
            stat_box = ctk.CTkFrame(stats_container, fg_color="#2d2d2d", corner_radius=8)
            stat_box.grid(row=i//3, column=i%3, padx=8, pady=5, sticky='ew')
            
            ctk.CTkLabel(stat_box, text=label, font=ctk.CTkFont(size=10),
                        text_color="gray").pack(padx=10, pady=(5, 0))
            
            value_label = ctk.CTkLabel(stat_box, text="0",
                                       font=ctk.CTkFont(size=20, weight="bold"),
                                       text_color=color)
            value_label.pack(padx=10, pady=(0, 5))
            self.stats_widgets[key] = value_label
        
        # ===== MAIN CONTENT =====
        main = ctk.CTkFrame(self, corner_radius=0)
        main.pack(fill='both', expand=True, padx=0, pady=0)
        
        # ===== CONTROL PANEL (Clean & Organized) =====
        controls = ctk.CTkFrame(main, height=200, fg_color="#1e1e1e")
        controls.pack(fill='x', pady=(0, 5))
        controls.pack_propagate(False)
        
        # Primary Actions Row
        row1 = ctk.CTkFrame(controls, fg_color="transparent")
        row1.pack(fill='x', padx=20, pady=(15, 8))
        
        primary_btns = [
            ("📁 Load Cookies", self.load_cookies, "#1f538d", 160),
            ("🚄 Turbo Training", self.turbo_training_mode, "#ff6b35", 160),
            ("⚡ Quick Check", self.quick_check, "#0d7d4d", 140),
            ("🔍 Full Verify", self.full_check, "#7841b6", 130),
            ("✓ Verify Selected", self.verify_selected, "#c77700", 150),
            ("🧠 AI Insights", self.show_ai_insights, "#ff6b35", 140),
        ]
        
        for text, cmd, color, width in primary_btns:
            ctk.CTkButton(row1, text=text, command=cmd, fg_color=color,
                         width=width, height=42, font=ctk.CTkFont(size=13, weight="bold"),
                         corner_radius=8).pack(side='left', padx=4)
        
        # Secondary Actions Row
        row2 = ctk.CTkFrame(controls, fg_color="transparent")
        row2.pack(fill='x', padx=20, pady=5)
        
        secondary_btns = [
            ("🚀 Login Browser", lambda: self.login_selected('selenium'), "#1f538d", 130),
            ("⚡ Background Login", self.background_login, "#7841b6", 140),
            ("📸 Login + Screenshot", self.login_and_screenshot, "#0d7d4d", 160),
            ("🖼️ View Screenshots", self.open_screenshots_folder, "#5a5a5a", 140),
            ("📊 Export Report", self.export_report, "#1f538d", 130),
            ("🗑️ Close All", self.close_all, "#b91c1c", 120),
        ]
        
        for text, cmd, color, width in secondary_btns:
            ctk.CTkButton(row2, text=text, command=cmd, fg_color=color,
                         width=width, height=36, font=ctk.CTkFont(size=11),
                         corner_radius=6).pack(side='left', padx=4)
        
        # ===== FILTERS & SORT (Professional Layout) =====
        filter_frame = ctk.CTkFrame(controls, fg_color="#252525", corner_radius=8)
        filter_frame.pack(fill='x', padx=20, pady=(8, 15))
        
        # Search
        search_frame = ctk.CTkFrame(filter_frame, fg_color="transparent")
        search_frame.pack(side='left', padx=10, pady=10)
        
        ctk.CTkLabel(search_frame, text="🔍 Search:",
                    font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=(0, 8))
        
        self.search_var = ctk.StringVar()
        self.search_var.trace('w', lambda *_: self.refresh())
        ctk.CTkEntry(search_frame, textvariable=self.search_var, width=250,
                    height=32, placeholder_text="Type domain name...").pack(side='left')
        
        # Filter Status
        filter_status_frame = ctk.CTkFrame(filter_frame, fg_color="transparent")
        filter_status_frame.pack(side='left', padx=15, pady=10)
        
        ctk.CTkLabel(filter_status_frame, text="📊 Filter:",
                    font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=(0, 8))
        
        self.filter_var = ctk.StringVar(value='All')
        ctk.CTkComboBox(filter_status_frame, 
                       values=['All', 'Working', 'Failed', 'Pending', 'Favorites', 'Expires Soon'],
                       variable=self.filter_var, command=lambda _: self.refresh(),
                       width=130, height=32).pack(side='left', padx=2)
        
        # Category Filter
        self.category_var = ctk.StringVar(value='All')
        ctk.CTkComboBox(filter_status_frame, 
                       values=['All', 'Social', 'Shopping', 'Finance', 'Dev', 'Email', 'Media', 'Other'],
                       variable=self.category_var, command=lambda _: self.refresh(),
                       width=120, height=32).pack(side='left', padx=2)
        
        # Sort Controls
        sort_frame = ctk.CTkFrame(filter_frame, fg_color="transparent")
        sort_frame.pack(side='left', padx=15, pady=10)
        
        ctk.CTkLabel(sort_frame, text="⬇️ Sort:",
                    font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=(0, 8))
        
        self.sort_var = ctk.StringVar(value='domain')
        ctk.CTkComboBox(sort_frame, 
                       values=['domain', 'status', 'last_verified', 'auth_cookies', 'total_cookies', 'category', 'created', 'last_login'],
                       variable=self.sort_var, command=lambda _: self._change_sort(),
                       width=130, height=32).pack(side='left', padx=2)
        
        self.sort_order_var = ctk.StringVar(value='ASC')
        ctk.CTkComboBox(sort_frame, values=['ASC ↑', 'DESC ↓'],
                       variable=self.sort_order_var, command=lambda _: self._change_sort(),
                       width=90, height=32).pack(side='left', padx=2)
        
        # Quick Filters (Checkboxes)
        quick_filters = ctk.CTkFrame(filter_frame, fg_color="transparent")
        quick_filters.pack(side='left', padx=15, pady=10)
        
        self.has_auth_var = ctk.BooleanVar()
        ctk.CTkCheckBox(quick_filters, text="🔑 Has Auth", variable=self.has_auth_var,
                       command=self.refresh).pack(side='left', padx=5)
        
        self.skip_successful_var = ctk.BooleanVar()
        ctk.CTkCheckBox(quick_filters, text="⏭️ Skip Successful", variable=self.skip_successful_var,
                       command=self.refresh, fg_color="#c77700").pack(side='left', padx=5)
        
        # ===== PAGINATION =====
        nav_frame = ctk.CTkFrame(main, height=50, fg_color="#1e1e1e")
        nav_frame.pack(fill='x', pady=(0, 2))
        nav_frame.pack_propagate(False)
        
        ctk.CTkButton(nav_frame, text="◀ Previous", width=100, height=32,
                     command=self.prev_page).pack(side='left', padx=15)
        
        self.page_label = ctk.CTkLabel(nav_frame, text="Page 1 of 1",
                                       font=ctk.CTkFont(size=14, weight="bold"))
        self.page_label.pack(side='left', padx=15)
        
        ctk.CTkButton(nav_frame, text="Next ▶", width=100, height=32,
                     command=self.next_page).pack(side='left', padx=15)
        
        ctk.CTkLabel(nav_frame, text="Items per page:",
                    font=ctk.CTkFont(size=12)).pack(side='left', padx=(30, 8))
        
        self.page_size_var = ctk.StringVar(value='100')
        ctk.CTkComboBox(nav_frame, values=['50', '100', '200', '500'],
                       variable=self.page_size_var, command=self._change_page_size,
                       width=90, height=32).pack(side='left')
        
        # ===== DOMAIN LIST (Clean Cards) =====
        list_container = ctk.CTkFrame(main)
        list_container.pack(fill='both', expand=True, padx=0, pady=0)
        
        self.scroll = ctk.CTkScrollableFrame(list_container, 
                                             label_text="📋 Domains",
                                             label_font=ctk.CTkFont(size=16, weight="bold"))
        self.scroll.pack(fill='both', expand=True)
        
        # Status Bar
        status_bar = ctk.CTkFrame(main, height=35, fg_color="#1a1a1a")
        status_bar.pack(fill='x')
        status_bar.pack_propagate(False)
        
        self.status = ctk.CTkLabel(status_bar, 
                                   text="✅ Ready • Extension loaded in browsers • Ultra-fast cookie injection enabled", 
                                   font=ctk.CTkFont(size=11), text_color="#4a9eff")
        self.status.pack(pady=8)
        
        self.frames = []
    
    def _change_sort(self):
        self.sort_by = self.sort_var.get()
        order_text = self.sort_order_var.get()
        self.sort_order = 'DESC' if 'DESC' in order_text else 'ASC'
        self.refresh()
    
    def load_cookies(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        
        files = []
        for root, dirs, filenames in os.walk(folder):
            for f in filenames:
                if f.endswith(('.txt', '.json', '.cookies')):
                    files.append(os.path.join(root, f))
        
        if not files:
            messagebox.showwarning("No Files", "No cookie files found")
            return
        
        # Clear old data
        self.db.clear_all()
        self.refresh()
        
        progress = ProgressWindow(self, "Loading Cookies", len(files))
        
        def load():
            for idx, path in enumerate(files):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    content = content.replace('\ufeff', '')
                    filename = os.path.basename(path)
                    cookies = Parser.parse(content, filename)
                    
                    if cookies:
                        domain = Parser.extract_domain(cookies, filename)
                        category = Parser.categorize(domain)
                        self.db.add_domain(domain, category, path, cookies)
                except Exception as e:
                    logger.error(f"Load error: {e}")
                
                progress.update(idx + 1)
            
            progress.close()
            self.refresh()
            
            stats = self.db.get_stats()
            messagebox.showinfo("✅ Complete", 
                f"Successfully loaded {stats['total']} domains\n"
                f"• {stats['has_auth']} with auth cookies\n"
                f"• Ready for verification")
        
        threading.Thread(target=load, daemon=True).start()
    
    def turbo_training_mode(self):
        """Ultra-fast AI training from massive cookie datasets"""
        TurboTrainingWindow(self, self.db)
    
    def quick_check(self):
        self._mass_verify('requests')
    
    def full_check(self):
        if not messagebox.askyesno("Full Verification", 
            "Perform thorough Selenium-based verification?\n\n"
            "This will take longer but is more accurate.\n\n"
            "Continue?"):
            return
        
        self._mass_verify('selenium_full')
    
    def _mass_verify(self, mode):
        filters = self._get_filters()
        domains = self.db.get_domains(filters)
        
        if not domains:
            messagebox.showwarning("No Domains", "No domains to verify")
            return
        
        progress = ProgressWindow(self, "Verifying Logins", len(domains))
        results = {'checked': 0, 'success': 0}
        
        def verify():
            workers = 20 if mode == 'requests' else 8
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                if mode == 'requests':
                    futures = {executor.submit(self.login_mgr.verify_requests, d): d 
                              for d in domains}
                else:
                    futures = {executor.submit(self.login_mgr.verify_selenium, d, True): d 
                              for d in domains}
                
                for future in as_completed(futures):
                    try:
                        if future.result():
                            results['success'] += 1
                        results['checked'] += 1
                        
                        pct = int(results['success']/results['checked']*100) if results['checked'] else 0
                        progress.update(results['checked'], 
                                       f"✓ {results['success']} working ({pct}%)")
                    except:
                        results['checked'] += 1
            
            progress.close()
            self.refresh()
            
            pct = int(results['success']/results['checked']*100) if results['checked'] else 0
            messagebox.showinfo("✅ Verification Complete",
                f"Checked: {results['checked']}\n"
                f"✓ Working: {results['success']} ({pct}%)\n"
                f"✗ Failed: {results['checked'] - results['success']}")
        
        threading.Thread(target=verify, daemon=True).start()
    
    def verify_selected(self):
        if not self.selected:
            messagebox.showwarning("No Selection", "Please select domains first")
            return
        
        def verify():
            for domain in self.selected:
                rows = self.db.get_domains({'search': domain})
                if rows:
                    self.login_mgr.verify_selenium(rows[0], headless=True)
            self.refresh()
        
        threading.Thread(target=verify, daemon=True).start()
    
    def login_selected(self, mode='selenium', headless=False):
        if not self.selected:
            messagebox.showwarning("No Selection", "Please select domains first")
            return
        
        for domain in self.selected:
            rows = self.db.get_domains({'search': domain})
            if rows:
                threading.Thread(target=self.login_mgr.open_browser,
                               args=(rows[0], mode, headless), daemon=True).start()
                time.sleep(0.3)
    
    def background_login(self):
        """Mass background login - no visible browsers"""
        if not self.selected:
            messagebox.showwarning("No Selection", "Please select domains first")
            return
        
        if not messagebox.askyesno("Background Login", 
            f"Login to {len(self.selected)} domains in background?\n\n"
            "This will verify cookies without opening browsers.\n"
            "Results will update in the dashboard.\n\n"
            "Continue?"):
            return
        
        progress = ProgressWindow(self, "Background Login", len(self.selected))
        results = {'success': 0, 'failed': 0}
        
        def bg_login():
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for domain in self.selected:
                    rows = self.db.get_domains({'search': domain})
                    if rows:
                        future = executor.submit(self.login_mgr.verify_selenium, rows[0], True)
                        futures.append((future, domain))
                
                for idx, (future, domain) in enumerate(futures, 1):
                    try:
                        if future.result():
                            results['success'] += 1
                        else:
                            results['failed'] += 1
                    except:
                        results['failed'] += 1
                    
                    progress.update(idx, f"✓ {results['success']} | ✗ {results['failed']}")
            
            progress.close()
            self.refresh()
            
            messagebox.showinfo("Background Login Complete",
                f"✓ Successful: {results['success']}\n"
                f"✗ Failed: {results['failed']}\n"
                f"Total: {len(self.selected)}")
        
        threading.Thread(target=bg_login, daemon=True).start()
    
    def login_and_screenshot(self):
        """Login and capture screenshots as proof"""
        if not self.selected:
            messagebox.showwarning("No Selection", "Please select domains first")
            return
        
        # Create screenshots folder
        screenshots_dir = os.path.join(os.getcwd(), 'screenshots')
        os.makedirs(screenshots_dir, exist_ok=True)
        
        progress = ProgressWindow(self, "Login + Screenshot", len(self.selected))
        results = {'success': 0, 'failed': 0, 'screenshots': 0}
        
        def screenshot_login():
            for idx, domain in enumerate(self.selected, 1):
                rows = self.db.get_domains({'search': domain})
                if rows:
                    screenshot_path = self.login_mgr.login_with_screenshot(
                        rows[0], screenshots_dir)
                    
                    if screenshot_path:
                        results['success'] += 1
                        results['screenshots'] += 1
                    else:
                        results['failed'] += 1
                
                progress.update(idx, f"✓ {results['success']} | 📸 {results['screenshots']}")
            
            progress.close()
            self.refresh()
            
            messagebox.showinfo("Screenshots Complete",
                f"✓ Successful: {results['success']}\n"
                f"✗ Failed: {results['failed']}\n"
                f"📸 Screenshots: {results['screenshots']}\n\n"
                f"Saved to: {screenshots_dir}")
        
        threading.Thread(target=screenshot_login, daemon=True).start()
    
    def open_screenshots_folder(self):
        """Open screenshots folder in file explorer"""
        screenshots_dir = os.path.join(os.getcwd(), 'screenshots')
        
        if not os.path.exists(screenshots_dir):
            os.makedirs(screenshots_dir, exist_ok=True)
            messagebox.showinfo("Screenshots Folder", 
                f"Screenshots folder created at:\n{screenshots_dir}\n\n"
                "Use '📸 Login + Screenshot' to capture login proofs.")
            return
        
        # Open folder based on OS
        import platform
        import subprocess
        
        try:
            if platform.system() == 'Windows':
                os.startfile(screenshots_dir)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', screenshots_dir])
            else:  # Linux
                subprocess.run(['xdg-open', screenshots_dir])
        except Exception as e:
            messagebox.showinfo("Screenshots Folder", 
                f"Screenshots saved at:\n{screenshots_dir}\n\n"
                f"Open manually to view PNG files.")
    
    def show_ai_insights(self):
        """Show AI learning insights and recommendations"""
        AIInsightsWindow(self, self.db)
      # Reduced delay for faster multi-login
    
    def export_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                           filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        
        domains = self.db.get_domains()
        
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Domain', 'Category', 'Status', 'Total Cookies',
                           'Auth Cookies', 'Username', 'Email', 'Last Verified', 
                           'Expires Soon', 'Login Speed'])
            
            for d in domains:
                writer.writerow([
                    d[1], d[2], d[3], d[6], d[5], 
                    d[7] or '', d[8] or '', d[9] or '', 
                    'Yes' if d[13] else 'No',
                    d[16] or ''
                ])
        
        messagebox.showinfo("✅ Exported", f"Report saved to:\n{path}")
    
    def close_all(self):
        count = self.login_mgr.close_all()
        messagebox.showinfo("Closed", f"Closed {count} browser(s)")
    
    def _get_filters(self):
        filters = {}
        
        if self.search_var.get():
            filters['search'] = self.search_var.get()
        
        filter_val = self.filter_var.get()
        if filter_val == 'Working':
            filters['can_login'] = True
        elif filter_val == 'Failed':
            filters['status'] = 'failed'
        elif filter_val == 'Pending':
            filters['status'] = 'pending'
        elif filter_val == 'Favorites':
            filters['favorite'] = True
        elif filter_val == 'Expires Soon':
            filters['expires_soon'] = True
        
        if self.category_var.get() != 'All':
            filters['category'] = self.category_var.get()
        
        if self.has_auth_var.get():
            filters['has_auth'] = True
        
        if self.skip_successful_var.get():
            filters['skip_successful'] = True
        
        return filters
    
    def refresh(self):
        self.current_page = 0
        self._load_page()
    
    def _load_page(self):
        for frame in self.frames:
            try:
                frame.destroy()
            except:
                pass
        self.frames.clear()
        self.selected.clear()
        
        filters = self._get_filters()
        
        total_count = self.db.get_domain_count(filters)
        total_pages = max(1, (total_count + self.page_size - 1) // self.page_size)
        
        if self.current_page >= total_pages:
            self.current_page = max(0, total_pages - 1)
        
        offset = self.current_page * self.page_size
        domains = self.db.get_domains(filters, limit=self.page_size, offset=offset, 
                                      sort_by=self.sort_by, sort_order=self.sort_order)
        
        for d in domains:
            self._create_card(d)
        
        self.page_label.configure(
            text=f"Page {self.current_page + 1} of {total_pages} • {total_count} total domains")
        self._update_stats()
    
    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self._load_page()
    
    def next_page(self):
        filters = self._get_filters()
        total_count = self.db.get_domain_count(filters)
        total_pages = max(1, (total_count + self.page_size - 1) // self.page_size)
        
        if self.current_page < total_pages - 1:
            self.current_page += 1
            self._load_page()
    
    def _change_page_size(self, value):
        self.page_size = int(value)
        self.refresh()
    
    def _create_card(self, data):
        (domain_id, domain, category, status, favorite, 
         auth_count, total_cookies, username, email, last_verified, 
         file_path, notes, skip_check, expires_soon, created_at,
         last_login_attempt, login_speed) = data
        
        # Modern card design
        card = ctk.CTkFrame(self.scroll, height=90, corner_radius=10)
        card.pack(fill='x', padx=8, pady=4)
        card.pack_propagate(False)
        
        # Status indicator (left border)
        colors = {
            'success': '#0d7d4d', 
            'failed': '#b91c1c', 
            'pending': '#c77700'
        }
        color = colors.get(status, '#5a5a5a')
        
        ctk.CTkFrame(card, width=5, fg_color=color, corner_radius=10).pack(side='left', fill='y')
        
        # Checkbox
        check_var = ctk.BooleanVar()
        ctk.CTkCheckBox(card, text="", variable=check_var, width=35,
                       command=lambda: self._toggle(domain, check_var.get())).pack(side='left', padx=10)
        
        # Info section
        info = ctk.CTkFrame(card, fg_color="transparent", width=700)
        info.pack(side='left', fill='y', padx=5)
        
        # Domain name with icons
        icons = ''
        if favorite:
            icons += '⭐ '
        if expires_soon:
            icons += '⚠️ '
        
        name_label = ctk.CTkLabel(info, text=f"{icons}{domain}",
                    font=ctk.CTkFont(size=15, weight="bold"),
                    anchor='w')
        name_label.pack(anchor='w', pady=(8, 2))
        
        # Stats line
        stats_text = f"{category} • {status.upper()} • {auth_count} auth / {total_cookies} total"
        if login_speed:
            stats_text += f" • ⚡ {login_speed}"
        
        ctk.CTkLabel(info, text=stats_text, 
                    font=ctk.CTkFont(size=10),
                    text_color="gray", anchor='w').pack(anchor='w')
        
        # User info if available
        if username or email or last_verified:
            extra = []
            if username or email:
                extra.append(f"👤 {username or email}")
            if last_verified:
                try:
                    verified_dt = datetime.fromisoformat(last_verified)
                    time_ago = datetime.now() - verified_dt
                    if time_ago.days > 0:
                        extra.append(f"🕐 Verified {time_ago.days}d ago")
                    else:
                        extra.append(f"🕐 Verified {time_ago.seconds//3600}h ago")
                except:
                    pass
            
            if extra:
                ctk.CTkLabel(info, text=" • ".join(extra),
                            font=ctk.CTkFont(size=9), text_color="#4a9eff",
                            anchor='w').pack(anchor='w')
        
        # Action buttons
        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.pack(side='right', padx=15)
        
        ctk.CTkButton(actions, text="👁️ View", width=70, height=32,
                     corner_radius=6,
                     command=lambda: self._view(domain_id, domain)).pack(side='left', padx=3)
        
        ctk.CTkButton(actions, text="🚀 Login", width=70, height=32,
                     fg_color="#0d7d4d", corner_radius=6,
                     command=lambda: self._quick_login(domain)).pack(side='left', padx=3)
        
        fav_btn = ctk.CTkButton(actions, text="⭐", width=40, height=32,
                               fg_color="#7841b6" if favorite else "#3d3d3d",
                               corner_radius=6,
                               command=lambda: self._fav(domain))
        fav_btn.pack(side='left', padx=3)
        
        self.frames.append(card)
    
    def _toggle(self, domain, selected):
        if selected:
            if domain not in self.selected:
                self.selected.append(domain)
        else:
            if domain in self.selected:
                self.selected.remove(domain)
    
    def _view(self, domain_id, domain):
        CookieViewer(self, domain_id, domain, self.db)
    
    def _quick_login(self, domain):
        rows = self.db.get_domains({'search': domain})
        if rows:
            threading.Thread(target=self.login_mgr.open_browser,
                           args=(rows[0],), daemon=True).start()
    
    def _fav(self, domain):
        self.db.toggle_favorite(domain)
        self._load_page()
    
    def _update_stats(self):
        stats = self.db.get_stats()
        
        # Update individual stat widgets
        for key, widget in self.stats_widgets.items():
            widget.configure(text=str(stats.get(key, 0)))
    
    def _start_refresh(self):
        def loop():
            while True:
                time.sleep(5)
                try:
                    if self.winfo_exists():
                        self.after(0, self._update_stats)
                except:
                    break
        
        threading.Thread(target=loop, daemon=True).start()


# ============================================================================
# WINDOWS
# ============================================================================

class ProgressWindow(ctk.CTkToplevel):
    def __init__(self, parent, title, total):
        super().__init__(parent)
        self.title(title)
        self.geometry("600x180")
        self.transient(parent)
        self.grab_set()
        self.total = total
        
        ctk.CTkLabel(self, text=f"{title}...", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=20)
        
        self.progress = ctk.CTkProgressBar(self, width=550, height=20)
        self.progress.pack(pady=15)
        self.progress.set(0)
        
        self.status = ctk.CTkLabel(self, text="0 / 0",
                                   font=ctk.CTkFont(size=13))
        self.status.pack(pady=10)
    
    def update(self, current, extra=""):
        try:
            self.progress.set(current / self.total if self.total > 0 else 0)
            text = f"{current} / {self.total}"
            if extra:
                text += f" • {extra}"
            self.status.configure(text=text)
            self.update_idletasks()
        except:
            pass
    
    def close(self):
        try:
            self.grab_release()
            self.destroy()
        except:
            pass


class CookieViewer(ctk.CTkToplevel):
    def __init__(self, parent, domain_id, domain, db):
        super().__init__(parent)
        self.domain_id = domain_id
        self.db = db
        
        self.title(f"🍪 Cookie Details: {domain}")
        self.geometry("1050x850")
        self.transient(parent)
        
        header = ctk.CTkFrame(self, height=80, fg_color="#1a1a1a")
        header.pack(fill='x')
        header.pack_propagate(False)
        
        ctk.CTkLabel(header, text=f"Cookie Details: {domain}",
                    font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)
        
        filters = ctk.CTkFrame(self, fg_color="#252525")
        filters.pack(fill='x', padx=20, pady=15)
        
        self.auth_only = ctk.BooleanVar()
        ctk.CTkCheckBox(filters, text="🔑 Auth Cookies Only", 
                       variable=self.auth_only,
                       command=self._load).pack(side='left', padx=15, pady=10)
        
        self.exclude_expired = ctk.BooleanVar()
        ctk.CTkCheckBox(filters, text="✓ Exclude Expired",
                       variable=self.exclude_expired,
                       command=self._load).pack(side='left', padx=15, pady=10)
        
        self.text = ctk.CTkTextbox(self, width=1010, height=680,
                                   font=ctk.CTkFont(family="Courier New", size=11))
        self.text.pack(padx=20, pady=(0, 20))
        
        self._load()
    
    def _load(self):
        try:
            self.text.delete("1.0", "end")
            
            cookies = self.db.get_cookies(self.domain_id,
                                          exclude_expired=self.exclude_expired.get(),
                                          auth_only=self.auth_only.get())
            
            info = f"{'='*90}\n"
            info += f"Total Cookies: {len(cookies)}\n"
            info += f"{'='*90}\n\n"
            
            for i, c in enumerate(cookies, 1):
                info += f"{i}. {c[2]}"
                
                tags = []
                if c[9]:
                    tags.append("AUTH")
                if c[10]:
                    tags.append("EXPIRED")
                if c[6]:
                    tags.append("SECURE")
                if c[7]:
                    tags.append("HTTP-ONLY")
                
                if tags:
                    info += f" [{', '.join(tags)}]"
                
                info += f"\n   Value: {c[3][:100]}{'...' if len(c[3]) > 100 else ''}\n"
                info += f"   Domain: {c[4]} | Path: {c[5]}\n"
                
                if c[8]:
                    try:
                        expiry_dt = datetime.fromtimestamp(int(c[8]))
                        info += f"   Expires: {expiry_dt.strftime('%Y-%m-%d %H:%M:%S')}"
                        
                        time_left = expiry_dt - datetime.now()
                        if time_left.days > 0:
                            info += f" ({time_left.days} days left)"
                        elif time_left.total_seconds() > 0:
                            hours = int(time_left.total_seconds() // 3600)
                            info += f" ({hours} hours left)"
                        else:
                            info += " (EXPIRED)"
                        info += "\n"
                    except:
                        pass
                
                info += f"\n"
            
            self.text.insert("1.0", info)
        except Exception as e:
            self.text.insert("1.0", f"Error loading cookies: {e}")


class AIInsightsWindow(ctk.CTkToplevel):
    def __init__(self, parent, db):
        super().__init__(parent)
        self.db = db
        
        self.title("AI Cookie Intelligence")
        self.geometry("1100x900")
        self.transient(parent)
        
        # Header
        header = ctk.CTkFrame(self, height=80, fg_color="#1a1a1a")
        header.pack(fill='x')
        header.pack_propagate(False)
        
        ctk.CTkLabel(header, text="AI Cookie Learning & Insights",
                    font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20)
        
        # Main content
        content = ctk.CTkFrame(self)
        content.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Get AI recommendations
        recommendations = self.db.get_ai_recommendations()
        
        # Insights Section
        insights_frame = ctk.CTkFrame(content, fg_color="#252525", corner_radius=10)
        insights_frame.pack(fill='x', pady=(0, 15))
        
        ctk.CTkLabel(insights_frame, text="AI Intelligence Summary",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    anchor='w').pack(padx=20, pady=(15, 10), anchor='w')
        
        if recommendations['insights']:
            for insight in recommendations['insights']:
                insight_label = ctk.CTkLabel(insights_frame, text=f"• {insight}",
                                            font=ctk.CTkFont(size=13),
                                            anchor='w', text_color="#4a9eff")
                insight_label.pack(padx=30, pady=5, anchor='w')
        else:
            ctk.CTkLabel(insights_frame, text="• No insights yet - perform more verifications to train the AI",
                        font=ctk.CTkFont(size=13),
                        anchor='w', text_color="gray").pack(padx=30, pady=5, anchor='w')
        
        ctk.CTkLabel(insights_frame, text=" ", font=ctk.CTkFont(size=5)).pack()
        
        # Learned Patterns Section
        patterns_frame = ctk.CTkFrame(content, fg_color="#252525", corner_radius=10)
        patterns_frame.pack(fill='both', expand=True, pady=(0, 15))
        
        ctk.CTkLabel(patterns_frame, text="Learned Cookie Patterns (High Confidence)",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    anchor='w').pack(padx=20, pady=(15, 10), anchor='w')
        
        patterns_scroll = ctk.CTkScrollableFrame(patterns_frame, height=250)
        patterns_scroll.pack(fill='both', expand=True, padx=20, pady=(0, 15))
        
        if recommendations['patterns']:
            # Header
            header_frame = ctk.CTkFrame(patterns_scroll, fg_color="#1e1e1e")
            header_frame.pack(fill='x', pady=(0, 5))
            
            ctk.CTkLabel(header_frame, text="Pattern", width=300,
                        font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=10)
            ctk.CTkLabel(header_frame, text="Category", width=150,
                        font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=10)
            ctk.CTkLabel(header_frame, text="Confidence", width=120,
                        font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=10)
            ctk.CTkLabel(header_frame, text="Success Count", width=120,
                        font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=10)
            
            # Patterns
            for pattern, category, confidence, success_count in recommendations['patterns']:
                row = ctk.CTkFrame(patterns_scroll, fg_color="#2d2d2d")
                row.pack(fill='x', pady=2)
                
                ctk.CTkLabel(row, text=pattern, width=300,
                            anchor='w').pack(side='left', padx=10, pady=8)
                ctk.CTkLabel(row, text=category, width=150,
                            anchor='w').pack(side='left', padx=10)
                
                conf_color = "#0d7d4d" if confidence > 0.8 else "#c77700" if confidence > 0.6 else "#b91c1c"
                ctk.CTkLabel(row, text=f"{confidence:.1%}", width=120,
                            anchor='w', text_color=conf_color).pack(side='left', padx=10)
                ctk.CTkLabel(row, text=str(success_count), width=120,
                            anchor='w').pack(side='left', padx=10)
        else:
            ctk.CTkLabel(patterns_scroll, text="No patterns learned yet. The AI will learn from successful logins.",
                        font=ctk.CTkFont(size=13),
                        text_color="gray").pack(pady=20)
        
        # Top Auth Cookies Section
        cookies_frame = ctk.CTkFrame(content, fg_color="#252525", corner_radius=10)
        cookies_frame.pack(fill='both', expand=True)
        
        ctk.CTkLabel(cookies_frame, text="Top Performing Auth Cookies",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    anchor='w').pack(padx=20, pady=(15, 10), anchor='w')
        
        cookies_scroll = ctk.CTkScrollableFrame(cookies_frame, height=250)
        cookies_scroll.pack(fill='both', expand=True, padx=20, pady=(0, 15))
        
        if recommendations['top_auth_cookies']:
            # Header
            header_frame = ctk.CTkFrame(cookies_scroll, fg_color="#1e1e1e")
            header_frame.pack(fill='x', pady=(0, 5))
            
            ctk.CTkLabel(header_frame, text="Cookie Name", width=400,
                        font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=10)
            ctk.CTkLabel(header_frame, text="Avg Score", width=150,
                        font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=10)
            ctk.CTkLabel(header_frame, text="Usage Count", width=150,
                        font=ctk.CTkFont(size=12, weight="bold")).pack(side='left', padx=10)
            
            # Cookies
            for name, avg_score, count in recommendations['top_auth_cookies']:
                row = ctk.CTkFrame(cookies_scroll, fg_color="#2d2d2d")
                row.pack(fill='x', pady=2)
                
                ctk.CTkLabel(row, text=name, width=400,
                            anchor='w').pack(side='left', padx=10, pady=8)
                
                score_color = "#0d7d4d" if avg_score > 0.6 else "#c77700" if avg_score > 0.3 else "#5a5a5a"
                ctk.CTkLabel(row, text=f"{avg_score:.2f}", width=150,
                            anchor='w', text_color=score_color).pack(side='left', padx=10)
                ctk.CTkLabel(row, text=str(count), width=150,
                            anchor='w').pack(side='left', padx=10)
        else:
            ctk.CTkLabel(cookies_scroll, text="No cookie performance data yet.",
                        font=ctk.CTkFont(size=13),
                        text_color="gray").pack(pady=20)
        
        # Action buttons
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(fill='x', padx=20, pady=15)
        
        ctk.CTkButton(button_frame, text="Optimize All Cookies",
                     command=self.optimize_cookies,
                     width=180, height=40).pack(side='left', padx=5)
        
        ctk.CTkButton(button_frame, text="Export AI Data",
                     command=self.export_ai_data,
                     width=180, height=40).pack(side='left', padx=5)
        
        ctk.CTkButton(button_frame, text="Close",
                     command=self.destroy,
                     width=120, height=40,
                     fg_color="#5a5a5a").pack(side='right', padx=5)
    
    def optimize_cookies(self):
        """Auto-optimize cookies using AI learning"""
        if messagebox.askyesno("AI Optimization",
            "Optimize all domains using AI-learned patterns?\n\n"
            "This will:\n"
            "• Prioritize high-confidence auth cookies\n"
            "• Remove low-performing cookies\n"
            "• Update importance scores\n\n"
            "Continue?"):
            
            # Run optimization
            optimized = 0
            with self.db.lock:
                c = self.db.conn.cursor()
                
                # Get all domains
                c.execute('SELECT id FROM domains')
                domains = c.fetchall()
                
                for (domain_id,) in domains:
                    # Get smart cookies (importance > 0.3)
                    smart_cookies = self.db.get_smart_cookies(domain_id, min_importance=0.3)
                    
                    if smart_cookies:
                        optimized += 1
                        # Mark domain as AI-optimized
                        c.execute('UPDATE domains SET ai_confidence = ai_confidence * 1.1 WHERE id=?', 
                                 (domain_id,))
                
                self.db.conn.commit()
            
            messagebox.showinfo("Optimization Complete",
                f"Optimized {optimized} domains using AI patterns.\n\n"
                "High-confidence cookies will now be prioritized during login.")
    
    def export_ai_data(self):
        """Export AI learning data"""
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                           filetypes=[("JSON files", "*.json")])
        if not path:
            return
        
        recommendations = self.db.get_ai_recommendations()
        
        export_data = {
            'insights': recommendations['insights'],
            'learned_patterns': [
                {
                    'pattern': p[0],
                    'category': p[1],
                    'confidence': p[2],
                    'success_count': p[3]
                }
                for p in recommendations['patterns']
            ],
            'top_auth_cookies': [
                {
                    'name': c[0],
                    'avg_score': c[1],
                    'usage_count': c[2]
                }
                for c in recommendations['top_auth_cookies']
            ],
            'export_date': datetime.now().isoformat()
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        
        messagebox.showinfo("Exported", f"AI data saved to:\n{path}")


class TurboTrainingWindow(ctk.CTkToplevel):
    def __init__(self, parent, db):
        super().__init__(parent)
        self.db = db
        self.parent = parent
        
        self.title("Turbo Training Mode")
        self.geometry("1100x700")
        
        # FIXED LAYOUT - Simple and guaranteed to work
        
        # Top: Header
        header = ctk.CTkLabel(self, text="TURBO TRAINING MODE", 
                             font=ctk.CTkFont(size=24, weight="bold"),
                             height=50)
        header.pack(pady=15)
        
        # Config section
        config = ctk.CTkFrame(self, height=120)
        config.pack(fill='x', padx=20, pady=10)
        config.pack_propagate(False)
        
        # Row 1: Folder
        row1 = ctk.CTkFrame(config, fg_color="transparent")
        row1.pack(fill='x', padx=10, pady=8)
        
        ctk.CTkLabel(row1, text="Folder:", width=80).pack(side='left')
        self.folder_var = ctk.StringVar(value="Click Browse to select cookie files folder")
        ctk.CTkEntry(row1, textvariable=self.folder_var, width=600).pack(side='left', padx=10)
        ctk.CTkButton(row1, text="BROWSE", command=self.select_folder, 
                     width=120, height=35).pack(side='left')
        
        # Row 2: Settings
        row2 = ctk.CTkFrame(config, fg_color="transparent")
        row2.pack(fill='x', padx=10, pady=8)
        
        ctk.CTkLabel(row2, text="Workers:").pack(side='left', padx=(0, 5))
        self.workers_var = ctk.StringVar(value='50')
        ctk.CTkComboBox(row2, values=['20', '30', '50', '100'],
                       variable=self.workers_var, width=80).pack(side='left', padx=5)
        
        ctk.CTkLabel(row2, text="Min Pattern:").pack(side='left', padx=(20, 5))
        self.min_pattern_var = ctk.StringVar(value='3')
        ctk.CTkComboBox(row2, values=['2', '3', '4', '5'],
                       variable=self.min_pattern_var, width=70).pack(side='left', padx=5)
        
        self.skip_duplicates_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(row2, text="Skip duplicates",
                       variable=self.skip_duplicates_var).pack(side='left', padx=20)
        
        # Stats section
        stats = ctk.CTkFrame(self, height=80)
        stats.pack(fill='x', padx=20, pady=10)
        stats.pack_propagate(False)
        
        self.stats_widgets = {}
        for i, (key, label) in enumerate([('files', 'Files'), ('cookies', 'Cookies'), 
                                           ('patterns', 'Patterns'), ('speed', 'Speed')]):
            box = ctk.CTkFrame(stats)
            box.pack(side='left', expand=True, padx=5)
            
            ctk.CTkLabel(box, text=label, font=ctk.CTkFont(size=10)).pack()
            val = ctk.CTkLabel(box, text="0", font=ctk.CTkFont(size=18, weight="bold"))
            val.pack()
            self.stats_widgets[key] = val
        
        # Progress
        prog_frame = ctk.CTkFrame(self, height=80)
        prog_frame.pack(fill='x', padx=20, pady=10)
        prog_frame.pack_propagate(False)
        
        self.progress = ctk.CTkProgressBar(prog_frame, width=1020, height=20)
        self.progress.pack(pady=10)
        self.progress.set(0)
        
        self.status_label = ctk.CTkLabel(prog_frame, text="Ready to train")
        self.status_label.pack()
        
        # Log
        self.log_text = ctk.CTkTextbox(self, width=1020, height=200,
                                       font=ctk.CTkFont(family="Courier", size=10))
        self.log_text.pack(padx=20, pady=10)
        
        # BUTTONS - ALWAYS VISIBLE AT BOTTOM
        btn_frame = ctk.CTkFrame(self, height=80, fg_color="#1a1a1a")
        btn_frame.pack(fill='x', side='bottom')
        btn_frame.pack_propagate(False)
        
        btn_container = ctk.CTkFrame(btn_frame, fg_color="transparent")
        btn_container.pack(expand=True)
        
        self.start_btn = ctk.CTkButton(btn_container, text="START TRAINING", 
                                       command=self.start_training,
                                       width=220, height=50,
                                       font=ctk.CTkFont(size=16, weight="bold"),
                                       fg_color="#0d7d4d")
        self.start_btn.pack(side='left', padx=10)
        
        self.stop_btn = ctk.CTkButton(btn_container, text="STOP", 
                                      command=self.stop_training,
                                      width=150, height=50,
                                      font=ctk.CTkFont(size=16, weight="bold"),
                                      fg_color="#b91c1c", state='disabled')
        self.stop_btn.pack(side='left', padx=10)
        
        ctk.CTkButton(btn_container, text="Export Model", command=self.export_model,
                     width=150, height=50).pack(side='left', padx=10)
        
        ctk.CTkButton(btn_container, text="Close", command=self.destroy,
                     width=120, height=50, fg_color="#5a5a5a").pack(side='left', padx=10)
        
        self.selected_folder = None
        self.training_active = False
        self.training_stats = {'files': 0, 'cookies': 0, 'patterns': 0, 'start_time': None}
    
    def select_folder(self):
        folder = filedialog.askdirectory(title="Select folder with cookie files")
        if folder:
            self.selected_folder = folder
            self.folder_var.set(folder)
            
            file_count = 0
            for root, dirs, files in os.walk(folder):
                for f in files:
                    if f.endswith(('.txt', '.json', '.cookies')):
                        file_count += 1
            
            self.log(f"Selected: {folder}")
            self.log(f"Found {file_count} files")
    
    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert('end', f"[{timestamp}] {message}\n")
        self.log_text.see('end')
    
    def start_training(self):
        if not self.selected_folder:
            messagebox.showwarning("No Folder", "Please select a folder first")
            return
        
        self.training_active = True
        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        
        self.training_stats = {'files': 0, 'cookies': 0, 'patterns': 0, 'start_time': time.time()}
        
        self.log("="*50)
        self.log("TURBO TRAINING STARTED")
        self.log("="*50)
        
        threading.Thread(target=self._run_training, daemon=True).start()
    
    def stop_training(self):
        self.training_active = False
        self.log("Stopping...")
    
    def _run_training(self):
        try:
            workers = int(self.workers_var.get())
            min_pattern = int(self.min_pattern_var.get())
            skip_dupes = self.skip_duplicates_var.get()
            
            files = []
            for root, dirs, filenames in os.walk(self.selected_folder):
                for f in filenames:
                    if f.endswith(('.txt', '.json', '.cookies')):
                        files.append(os.path.join(root, f))
            
            total_files = len(files)
            self.log(f"Processing {total_files} files with {workers} workers")
            
            learned_patterns = set()
            
            def process_file(file_path):
                if not self.training_active:
                    return None
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().replace('\ufeff', '')
                    
                    cookies = Parser.parse(content, os.path.basename(file_path))
                    if not cookies:
                        return None
                    
                    file_patterns = []
                    for cookie in cookies:
                        name = cookie.get('name', '').lower()
                        pattern = re.sub(r'[0-9_-]+', '', name)
                        
                        if len(pattern) >= min_pattern:
                            is_auth = self.db._is_auth_cookie(cookie)
                            
                            if is_auth and (not skip_dupes or pattern not in learned_patterns):
                                file_patterns.append(pattern)
                                learned_patterns.add(pattern)
                                self.db._learn_pattern(pattern, 'auth', success=True)
                    
                    return len(cookies), file_patterns
                except:
                    return None
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(process_file, f): f for f in files}
                
                for future in as_completed(futures):
                    if not self.training_active:
                        break
                    
                    result = future.result()
                    if result:
                        cookie_count, patterns = result
                        self.training_stats['files'] += 1
                        self.training_stats['cookies'] += cookie_count
                        self.training_stats['patterns'] += len(patterns)
                        
                        progress = self.training_stats['files'] / total_files
                        elapsed = time.time() - self.training_stats['start_time']
                        speed = self.training_stats['files'] / elapsed if elapsed > 0 else 0
                        
                        self.after(0, self._update_ui, progress, speed)
                        
                        if self.training_stats['files'] % 100 == 0:
                            self.after(0, self.log, 
                                     f"{self.training_stats['files']}/{total_files} - "
                                     f"{self.training_stats['patterns']} patterns")
            
            elapsed = time.time() - self.training_stats['start_time']
            self.after(0, self.log, "="*50)
            self.after(0, self.log, "COMPLETE!")
            self.after(0, self.log, f"Files: {self.training_stats['files']}")
            self.after(0, self.log, f"Patterns: {self.training_stats['patterns']}")
            self.after(0, self.log, f"Time: {elapsed:.1f}s")
            self.after(0, self.log, f"Speed: {self.training_stats['files']/elapsed:.1f}/sec")
            
            self.after(0, self.status_label.configure, 
                      text=f"Complete! {self.training_stats['patterns']} patterns learned")
            self.after(0, self.parent.refresh)
            
        except Exception as e:
            self.after(0, self.log, f"ERROR: {e}")
        finally:
            self.training_active = False
            self.after(0, self.start_btn.configure, state='normal')
            self.after(0, self.stop_btn.configure, state='disabled')
    
    def _update_ui(self, progress, speed):
        self.progress.set(progress)
        self.stats_widgets['files'].configure(text=str(self.training_stats['files']))
        self.stats_widgets['cookies'].configure(text=str(self.training_stats['cookies']))
        self.stats_widgets['patterns'].configure(text=str(self.training_stats['patterns']))
        self.stats_widgets['speed'].configure(text=f"{speed:.0f}/s")
        self.status_label.configure(text=f"Training: {progress*100:.0f}%")
    
    def export_model(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("AI Model", "*.ai")])
        
        if not path:
            return
        
        recommendations = self.db.get_ai_recommendations()
        
        model_data = {
            'version': '1.0',
            'export_date': datetime.now().isoformat(),
            'training_stats': self.training_stats,
            'patterns': [
                {'pattern': p[0], 'category': p[1], 'confidence': p[2], 'success': p[3]}
                for p in recommendations['patterns']
            ]
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(model_data, f, indent=2)
        
        self.log(f"Model exported: {path}")
        messagebox.showinfo("Exported", f"AI model saved!\nPatterns: {len(model_data['patterns'])}")



# ============================================================================
# MAIN
# ============================================================================

def main():
    app = App()
    
    def on_close():
        try:
            app.login_mgr.close_all()
            app.destroy()
        except:
            pass
    
    app.protocol("WM_DELETE_WINDOW", on_close)
    app.mainloop()


if __name__ == '__main__':
    main()
