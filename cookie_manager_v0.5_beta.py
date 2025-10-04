"""
Enterprise Cookie Manager Pro v0.5 BETA - SESSION MANAGEMENT EDITION
✓ Multi-session tracking per domain
✓ Smart success rate sorting  
✓ Output logging (HTML + Screenshots)
✓ Improved stable UI layout
✓ Click domain to view all sessions
✓ Test each session individually
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox, Menu
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
import gc
import platform
import subprocess
import hashlib

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions

try:
    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

__version__ = "0.5-beta"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ===========================================================================
# DATABASE WITH SESSION TRACKING
# ===========================================================================

class Database:
    def __init__(self):
        try:
            self.conn = sqlite3.connect('cookies_v0.5.db', check_same_thread=False, timeout=30)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.lock = threading.Lock()
            self._init()
        except Exception as e:
            logger.error(f"Database init error: {e}")
            raise
    
    def _init(self):
        with self.lock:
            c = self.conn.cursor()
            
            c.execute('''CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY,
                domain TEXT UNIQUE,
                category TEXT,
                favorite INTEGER DEFAULT 0,
                session_count INTEGER DEFAULT 0,
                total_cookies INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0,
                created_at TEXT,
                last_updated TEXT
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY,
                domain_id INTEGER,
                session_hash TEXT,
                session_identifier TEXT,
                auth_cookie_count INTEGER DEFAULT 0,
                total_cookies INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                last_verified TEXT,
                login_speed TEXT,
                expires_soon INTEGER DEFAULT 0,
                file_path TEXT,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                created_at TEXT,
                FOREIGN KEY(domain_id) REFERENCES domains(id),
                UNIQUE(domain_id, session_hash)
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS cookies (
                id INTEGER PRIMARY KEY,
                session_id INTEGER,
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
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS login_outputs (
                id INTEGER PRIMARY KEY,
                session_id INTEGER,
                output_type TEXT,
                file_path TEXT,
                created_at TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )''')
            
            c.execute('CREATE INDEX IF NOT EXISTS idx_domain ON domains(domain)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_session_domain ON sessions(domain_id)')
            
            self.conn.commit()
    
    def add_domain_batch(self, domains_data):
        if not domains_data:
            return
        
        with self.lock:
            try:
                c = self.conn.cursor()
                c.execute('BEGIN TRANSACTION')
                
                for domain_data in domains_data:
                    try:
                        domain, category, file_path, cookies = domain_data
                        
                        if not domain:
                            continue
                        
                        c.execute('SELECT id FROM domains WHERE domain=?', (domain,))
                        existing = c.fetchone()
                        
                        if existing:
                            domain_id = existing[0]
                        else:
                            c.execute('''INSERT INTO domains 
                                (domain, category, created_at, last_updated)
                                VALUES (?, ?, ?, ?)''',
                                (domain, category, datetime.now().isoformat(), datetime.now().isoformat()))
                            domain_id = c.lastrowid
                        
                        session_hash = self._generate_session_hash(cookies)
                        session_identifier = self._extract_session_identifier(cookies)
                        
                        c.execute('SELECT id FROM sessions WHERE domain_id=? AND session_hash=?', 
                                 (domain_id, session_hash))
                        existing_session = c.fetchone()
                        
                        auth_count = sum(1 for ck in cookies if self._is_auth_cookie(ck))
                        expires_soon = self._check_expires_soon(cookies)
                        
                        if existing_session:
                            session_id = existing_session[0]
                            c.execute('''UPDATE sessions SET auth_cookie_count=?, total_cookies=?, 
                                        file_path=?, expires_soon=?, session_identifier=?
                                        WHERE id=?''',
                                     (auth_count, len(cookies), file_path, expires_soon, 
                                      session_identifier, session_id))
                            c.execute('DELETE FROM cookies WHERE session_id=?', (session_id,))
                        else:
                            c.execute('''INSERT INTO sessions 
                                (domain_id, session_hash, session_identifier, auth_cookie_count, 
                                 total_cookies, file_path, expires_soon, created_at, status)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')''',
                                (domain_id, session_hash, session_identifier, auth_count, 
                                 len(cookies), file_path, expires_soon, datetime.now().isoformat()))
                            session_id = c.lastrowid
                        
                        current_time = int(time.time())
                        cookie_batch = []
                        
                        for cookie in cookies[:200]:
                            try:
                                is_auth = self._is_auth_cookie(cookie)
                                expiry = cookie.get('expiry')
                                is_expired = 0
                                
                                if expiry:
                                    try:
                                        if int(expiry) < current_time:
                                            is_expired = 1
                                    except:
                                        pass
                                
                                cookie_batch.append((
                                    session_id, 
                                    str(cookie.get('name', ''))[:255], 
                                    str(cookie.get('value', ''))[:1000],
                                    str(cookie.get('domain', ''))[:255], 
                                    str(cookie.get('path', '/'))[:255],
                                    int(cookie.get('secure', False)), 
                                    int(cookie.get('httpOnly', False)),
                                    expiry, int(is_auth), is_expired, 0.5 if is_auth else 0.1
                                ))
                            except:
                                continue
                        
                        if cookie_batch:
                            c.executemany('''INSERT INTO cookies 
                                (session_id, name, value, domain, path, secure, httponly, expiry, is_auth, is_expired, importance_score)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', cookie_batch)
                        
                        c.execute('SELECT COUNT(*) FROM sessions WHERE domain_id=?', (domain_id,))
                        session_count = c.fetchone()[0]
                        
                        c.execute('SELECT SUM(total_cookies) FROM sessions WHERE domain_id=?', (domain_id,))
                        total_cookies = c.fetchone()[0] or 0
                        
                        c.execute('''UPDATE domains SET session_count=?, total_cookies=?, last_updated=?
                                    WHERE id=?''', (session_count, total_cookies, datetime.now().isoformat(), domain_id))
                    
                    except Exception as e:
                        logger.error(f"Domain insert error: {e}")
                        continue
                
                c.execute('COMMIT')
                self.conn.commit()
                
            except Exception as e:
                logger.error(f"Batch insert error: {e}")
                try:
                    c.execute('ROLLBACK')
                except:
                    pass
    
    def _generate_session_hash(self, cookies):
        try:
            auth_cookies = [c for c in cookies if self._is_auth_cookie(c)]
            if not auth_cookies:
                auth_cookies = cookies[:10]
            
            auth_cookies.sort(key=lambda x: x.get('name', ''))
            values = ''.join([str(c.get('value', ''))[:50] for c in auth_cookies[:5]])
            return hashlib.md5(values.encode()).hexdigest()[:16]
        except:
            return hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    
    def _extract_session_identifier(self, cookies):
        try:
            for cookie in cookies:
                name = str(cookie.get('name', '')).lower()
                if any(x in name for x in ['session', 'sess', 'user', 'id']):
                    value = str(cookie.get('value', ''))
                    if len(value) > 10:
                        return f"{cookie.get('name', 'Session')}[{value[:12]}...]"
            
            auth_cookies = [c for c in cookies if self._is_auth_cookie(c)]
            if auth_cookies:
                return f"{auth_cookies[0].get('name', 'Auth')}[{str(auth_cookies[0].get('value', ''))[:12]}...]"
            
            return "Session"
        except:
            return "Session"
    
    def _is_auth_cookie(self, cookie):
        try:
            name = str(cookie.get('name', '')).lower()
            value = str(cookie.get('value', ''))
            
            if len(value) < 10:
                return False
            
            patterns = ['session', 'sess', 'auth', 'token', 'login', 'user', 
                       'jwt', 'access', 'refresh', 'sid', 'phpsessid', 'remember']
            
            return any(p in name for p in patterns)
        except:
            return False
    
    def _check_expires_soon(self, cookies):
        try:
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
        except:
            return 0
    
    def get_domains(self, filters=None, limit=None, offset=0, sort_by='domain', sort_order='ASC'):
        try:
            with self.lock:
                c = self.conn.cursor()
                query = 'SELECT * FROM domains WHERE 1=1'
                params = []
                
                if filters:
                    if filters.get('favorite'):
                        query += ' AND favorite=1'
                    if filters.get('has_sessions'):
                        query += ' AND session_count > 0'
                    if filters.get('category') and filters['category'] != 'All':
                        query += ' AND category=?'
                        params.append(filters['category'])
                    if filters.get('search'):
                        query += ' AND domain LIKE ?'
                        params.append(f"%{filters['search']}%")
                
                valid_sorts = {
                    'domain': 'domain',
                    'sessions': 'session_count',
                    'success_rate': 'success_rate',
                    'category': 'category'
                }
                
                sort_col = valid_sorts.get(sort_by, 'domain')
                sort_dir = 'DESC' if sort_order == 'DESC' else 'ASC'
                query += f' ORDER BY favorite DESC, {sort_col} {sort_dir}'
                
                if limit:
                    query += f' LIMIT {limit} OFFSET {offset}'
                
                c.execute(query, params)
                return c.fetchall()
        except Exception as e:
            logger.error(f"Get domains error: {e}")
            return []
    
    def get_domain_count(self, filters=None):
        try:
            with self.lock:
                c = self.conn.cursor()
                query = 'SELECT COUNT(*) FROM domains WHERE 1=1'
                params = []
                
                if filters:
                    if filters.get('favorite'):
                        query += ' AND favorite=1'
                    if filters.get('has_sessions'):
                        query += ' AND session_count > 0'
                    if filters.get('category') and filters['category'] != 'All':
                        query += ' AND category=?'
                        params.append(filters['category'])
                    if filters.get('search'):
                        query += ' AND domain LIKE ?'
                        params.append(f"%{filters['search']}%")
                
                c.execute(query, params)
                return c.fetchone()[0]
        except:
            return 0
    
    def get_sessions(self, domain_id):
        try:
            with self.lock:
                c = self.conn.cursor()
                c.execute('SELECT * FROM sessions WHERE domain_id=? ORDER BY created_at DESC', (domain_id,))
                return c.fetchall()
        except:
            return []
    
    def get_session_cookies(self, session_id):
        try:
            with self.lock:
                c = self.conn.cursor()
                c.execute('SELECT * FROM cookies WHERE session_id=? ORDER BY is_auth DESC, name', (session_id,))
                return c.fetchall()
        except:
            return []
    
    def update_session_status(self, session_id, status, speed=None):
        try:
            with self.lock:
                c = self.conn.cursor()
                
                updates = {'status': status, 'last_verified': datetime.now().isoformat()}
                if speed:
                    updates['login_speed'] = speed
                
                c.execute('SELECT success_count, fail_count, domain_id FROM sessions WHERE id=?', (session_id,))
                result = c.fetchone()
                if not result:
                    return
                
                success_count, fail_count, domain_id = result
                
                if status == 'success':
                    success_count = (success_count or 0) + 1
                else:
                    fail_count = (fail_count or 0) + 1
                
                updates['success_count'] = success_count
                updates['fail_count'] = fail_count
                
                update_sql = ', '.join([f"{k}=?" for k in updates.keys()])
                values = list(updates.values()) + [session_id]
                c.execute(f'UPDATE sessions SET {update_sql} WHERE id=?', values)
                
                c.execute('''SELECT SUM(success_count), SUM(fail_count) 
                            FROM sessions WHERE domain_id=?''', (domain_id,))
                totals = c.fetchone()
                total_success = totals[0] or 0
                total_fail = totals[1] or 0
                total_attempts = total_success + total_fail
                
                success_rate = (total_success / total_attempts * 100) if total_attempts > 0 else 0
                
                c.execute('''UPDATE domains SET success_count=?, fail_count=?, success_rate=?, last_updated=?
                            WHERE id=?''', 
                         (total_success, total_fail, success_rate, datetime.now().isoformat(), domain_id))
                
                self.conn.commit()
        except Exception as e:
            logger.error(f"Update session error: {e}")
    
    def save_login_output(self, session_id, output_type, file_path):
        try:
            with self.lock:
                c = self.conn.cursor()
                c.execute('''INSERT INTO login_outputs (session_id, output_type, file_path, created_at)
                            VALUES (?, ?, ?, ?)''',
                         (session_id, output_type, file_path, datetime.now().isoformat()))
                self.conn.commit()
        except:
            pass
    
    def toggle_favorite(self, domain):
        try:
            with self.lock:
                c = self.conn.cursor()
                c.execute('UPDATE domains SET favorite = NOT favorite WHERE domain=?', (domain,))
                self.conn.commit()
        except:
            pass
    
    def get_stats(self):
        try:
            with self.lock:
                c = self.conn.cursor()
                stats = {}
                
                c.execute('SELECT COUNT(*) FROM domains')
                stats['total_domains'] = c.fetchone()[0]
                
                c.execute('SELECT COUNT(*) FROM sessions')
                stats['total_sessions'] = c.fetchone()[0]
                
                c.execute("SELECT COUNT(*) FROM sessions WHERE status='success'")
                stats['working_sessions'] = c.fetchone()[0]
                
                c.execute("SELECT COUNT(*) FROM sessions WHERE status='failed'")
                stats['failed_sessions'] = c.fetchone()[0]
                
                c.execute("SELECT COUNT(*) FROM sessions WHERE status='pending'")
                stats['pending_sessions'] = c.fetchone()[0]
                
                c.execute('SELECT AVG(success_rate) FROM domains WHERE success_rate > 0')
                result = c.fetchone()
                stats['avg_success_rate'] = result[0] if result and result[0] else 0.0
                
                return stats
        except:
            return {'total_domains': 0, 'total_sessions': 0, 'working_sessions': 0, 
                   'failed_sessions': 0, 'pending_sessions': 0, 'avg_success_rate': 0}


# ===========================================================================
# LOGIN MANAGER WITH OUTPUT LOGGING
# ===========================================================================

class LoginManager:
    def __init__(self, db):
        self.db = db
        self.drivers = {}
        
        self.outputs_dir = os.path.join(os.getcwd(), 'login_outputs')
        self.screenshots_dir = os.path.join(self.outputs_dir, 'screenshots')
        self.html_dir = os.path.join(self.outputs_dir, 'html')
        
        os.makedirs(self.screenshots_dir, exist_ok=True)
        os.makedirs(self.html_dir, exist_ok=True)
    
    def _clean_domain(self, domain):
        if not domain:
            return ''
        return str(domain).replace('\ufeff', '').strip().lstrip('.')
    
    def _create_driver(self, headless=False):
        try:
            options = ChromeOptions()
            if headless:
                options.add_argument('--headless=new')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            if headless:
                options.add_argument('--disable-images')
            options.add_argument('--disable-web-security')
            options.add_argument('--window-size=1920,1080')
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(15)
            return driver
        except Exception as e:
            logger.error(f"Driver error: {e}")
            return None
    
    def verify_session(self, session_row, domain, save_outputs=False):
        driver = None
        try:
            session_id = session_row[0]
            
            domain = self._clean_domain(domain)
            if not domain:
                return False
            
            start = time.time()
            driver = self._create_driver(headless=True)
            if not driver:
                return False
            
            cookies = self.db.get_session_cookies(session_id)
            
            driver.get(f"https://{domain}")
            time.sleep(1)
            
            for cookie in cookies[:50]:
                try:
                    cookie_domain = self._clean_domain(cookie[4] if cookie[4] else domain)
                    driver.execute_cdp_cmd('Network.setCookie', {
                        'name': cookie[2],
                        'value': cookie[3],
                        'domain': cookie_domain,
                        'path': cookie[5] if cookie[5] else '/',
                        'secure': bool(cookie[6]),
                        'httpOnly': bool(cookie[7])
                    })
                except:
                    continue
            
            driver.refresh()
            time.sleep(3)
            
            url = driver.current_url.lower()
            page_source = driver.page_source.lower()
            
            has_login = any(x in url for x in ['login', 'signin', 'sign-in', 'auth'])
            has_logout = any(x in page_source[:10000] for x in ['logout', 'signout', 'sign out', 'account', 'dashboard', 'profile'])
            
            is_logged_in = not has_login and has_logout
            
            elapsed = time.time() - start
            status = 'success' if is_logged_in else 'failed'
            
            if save_outputs and is_logged_in:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                safe_domain = domain.replace('.', '_').replace('/', '_')
                session_hash = session_row[2][:8]
                
                screenshot_name = f"{safe_domain}_{session_hash}_{timestamp}.png"
                screenshot_path = os.path.join(self.screenshots_dir, screenshot_name)
                driver.save_screenshot(screenshot_path)
                self.db.save_login_output(session_id, 'screenshot', screenshot_path)
                
                html_name = f"{safe_domain}_{session_hash}_{timestamp}.html"
                html_path = os.path.join(self.html_dir, html_name)
                with open(html_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(driver.page_source)
                self.db.save_login_output(session_id, 'html', html_path)
            
            self.db.update_session_status(session_id, status, f"{elapsed:.1f}s")
            
            driver.quit()
            return is_logged_in
            
        except Exception as e:
            logger.error(f"Session verify error: {e}")
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            return False
    
    def open_session_browser(self, session_row, domain):
        driver = None
        try:
            session_id = session_row[0]
            domain = self._clean_domain(domain)
            
            if not domain:
                return False
            
            driver = self._create_driver(headless=False)
            if not driver:
                return False
            
            cookies = self.db.get_session_cookies(session_id)
            
            driver.get(f"https://{domain}")
            time.sleep(1)
            
            for cookie in cookies[:50]:
                try:
                    cookie_domain = self._clean_domain(cookie[4] if cookie[4] else domain)
                    driver.execute_cdp_cmd('Network.setCookie', {
                        'name': cookie[2],
                        'value': cookie[3],
                        'domain': cookie_domain,
                        'path': cookie[5] if cookie[5] else '/',
                        'secure': bool(cookie[6]),
                        'httpOnly': bool(cookie[7])
                    })
                except:
                    continue
            
            driver.refresh()
            
            self.drivers[f"{domain}_{session_id}"] = driver
            return True
        except Exception as e:
            logger.error(f"Open browser error: {e}")
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            return False
    
    def close_all(self):
        count = len(self.drivers)
        for driver in list(self.drivers.values()):
            try:
                driver.quit()
            except:
                pass
        self.drivers.clear()
        return count


# ===========================================================================
# PARSER
# ===========================================================================

class Parser:
    @staticmethod
    def parse(content, filename):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                if 'cookies' in data:
                    return data['cookies']
                return [data]
        except:
            pass
        
        cookies = []
        try:
            lines = content.strip().split('\n')
            for line in lines[:1000]:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = re.split(r'\t+', line)
                if len(parts) >= 7:
                    try:
                        cookies.append({
                            'domain': parts[0][:255],
                            'path': parts[2][:255],
                            'secure': parts[3].upper() == 'TRUE',
                            'expiry': int(float(parts[4])) if parts[4].replace('.', '').isdigit() else None,
                            'name': parts[5][:255],
                            'value': parts[6][:1000]
                        })
                    except:
                        continue
        except:
            pass
        
        return cookies
    
    @staticmethod
    def extract_domain(cookies, filename):
        try:
            if cookies:
                domains = []
                for c in cookies:
                    d = str(c.get('domain', '')).strip().lstrip('.')
                    if d and len(d) < 255:
                        domains.append(d)
                if domains:
                    return max(set(domains), key=domains.count)
            
            match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', filename)
            return match.group(1) if match else os.path.splitext(filename)[0][:255]
        except:
            return "unknown"
    
    @staticmethod
    def categorize(domain):
        try:
            categories = {
                'Social': ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'reddit'],
                'Shopping': ['amazon', 'ebay', 'shopify', 'etsy', 'walmart'],
                'Finance': ['paypal', 'stripe', 'bank', 'chase', 'wells'],
                'Dev': ['github', 'gitlab', 'aws', 'azure', 'stackoverflow'],
                'Email': ['gmail', 'outlook', 'yahoo', 'proton'],
                'Media': ['netflix', 'youtube', 'spotify', 'twitch', 'hulu']
            }
            
            domain_lower = str(domain).lower()
            for cat, keywords in categories.items():
                if any(kw in domain_lower for kw in keywords):
                    return cat
            return 'Other'
        except:
            return 'Other'


# ===========================================================================
# PROGRESS WINDOW
# ===========================================================================

class ProgressWindow(ctk.CTkToplevel):
    def __init__(self, parent, title, total):
        super().__init__(parent)
        self.title(title)
        self.geometry("500x150")
        self.transient(parent)
        self.grab_set()
        self.total = total
        self.start_time = time.time()
        
        ctk.CTkLabel(self, text=f"{title}...", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(20, 10))
        
        self.progress = ctk.CTkProgressBar(self, width=450, height=20)
        self.progress.pack(padx=25, pady=10)
        self.progress.set(0)
        
        self.status = ctk.CTkLabel(self, text="Starting...", font=ctk.CTkFont(size=12))
        self.status.pack(pady=(0, 10))
        
        self.eta = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=10), text_color="gray")
        self.eta.pack(pady=(0, 10))
    
    def update(self, current, extra=""):
        try:
            self.progress.set(current / self.total if self.total > 0 else 0)
            
            elapsed = time.time() - self.start_time
            if current > 0:
                rate = current / elapsed
                remaining = self.total - current
                eta = remaining / rate if rate > 0 else 0
                eta_text = f"ETA: {timedelta(seconds=int(eta))}"
            else:
                eta_text = "Calculating..."
            
            text = f"{current} / {self.total}"
            if extra:
                text += f" • {extra}"
            
            self.status.configure(text=text)
            self.eta.configure(text=eta_text)
            self.update_idletasks()
        except:
            pass
    
    def close(self):
        try:
            self.grab_release()
            self.destroy()
        except:
            pass


# ===========================================================================
# SESSION VIEWER WINDOW - Shows all sessions for a domain
# ===========================================================================

class SessionViewer(ctk.CTkToplevel):
    def __init__(self, parent, domain_row, db, login_mgr):
        super().__init__(parent)
        self.domain_row = domain_row
        self.db = db
        self.login_mgr = login_mgr
        
        domain_id = domain_row[0]
        domain_name = domain_row[1]
        
        self.title(f"Sessions: {domain_name}")
        self.geometry("1000x700")
        self.transient(parent)
        
        # Header
        header = ctk.CTkFrame(self, height=80, fg_color="#1a1a1a")
        header.pack(fill='x')
        header.pack_propagate(False)
        
        header_content = ctk.CTkFrame(header, fg_color="transparent")
        header_content.pack(fill='both', expand=True, padx=20, pady=15)
        
        ctk.CTkLabel(header_content, text=f"All Sessions for: {domain_name}",
                    font=ctk.CTkFont(size=18, weight="bold")).pack(side='left')
        
        success_rate = domain_row[8]
        color = '#0d7d4d' if success_rate > 70 else '#c77700' if success_rate > 30 else '#b91c1c'
        ctk.CTkLabel(header_content, text=f"Success Rate: {success_rate:.1f}%",
                    font=ctk.CTkFont(size=14), text_color=color).pack(side='right', padx=10)
        
        # Sessions list
        list_frame = ctk.CTkScrollableFrame(self, fg_color="#0a0a0a")
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        sessions = self.db.get_sessions(domain_id)
        
        if not sessions:
            ctk.CTkLabel(list_frame, text="No sessions found", 
                        font=ctk.CTkFont(size=14), text_color="gray").pack(pady=50)
        else:
            for idx, session in enumerate(sessions):
                self._create_session_card(list_frame, session, domain_name, idx)
    
    def _create_session_card(self, parent, session, domain_name, idx):
        (session_id, domain_id, session_hash, session_identifier, auth_count, 
         total_cookies, status, last_verified, login_speed, expires_soon, 
         file_path, success_count, fail_count, created_at) = session
        
        card = ctk.CTkFrame(parent, fg_color="#1a1a1a", corner_radius=8)
        card.pack(fill='x', pady=5, padx=5)
        
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill='both', expand=True, padx=15, pady=12)
        
        # Top row - Session info
        top_row = ctk.CTkFrame(content, fg_color="transparent")
        top_row.pack(fill='x')
        
        ctk.CTkLabel(top_row, text=f"#{idx+1}: {session_identifier}",
                    font=ctk.CTkFont(size=13, weight="bold")).pack(side='left')
        
        status_colors = {'success': '#0d7d4d', 'failed': '#b91c1c', 'pending': '#c77700'}
        color = status_colors.get(status, '#666666')
        ctk.CTkLabel(top_row, text=status.upper(), font=ctk.CTkFont(size=11, weight='bold'),
                    text_color=color).pack(side='left', padx=15)
        
        if expires_soon:
            ctk.CTkLabel(top_row, text="⚠ EXPIRES SOON", font=ctk.CTkFont(size=10),
                        text_color='#ff6b35').pack(side='left')
        
        # Middle row - Stats
        mid_row = ctk.CTkFrame(content, fg_color="transparent")
        mid_row.pack(fill='x', pady=5)
        
        stats_text = f"Auth: {auth_count} | Total: {total_cookies}"
        if success_count or fail_count:
            total_attempts = success_count + fail_count
            session_rate = (success_count / total_attempts * 100) if total_attempts > 0 else 0
            stats_text += f" | Attempts: {total_attempts} ({session_rate:.0f}% success)"
        if login_speed:
            stats_text += f" | Speed: {login_speed}"
        
        ctk.CTkLabel(mid_row, text=stats_text, font=ctk.CTkFont(size=11),
                    text_color='#888888').pack(side='left')
        
        # Bottom row - Actions
        action_row = ctk.CTkFrame(content, fg_color="transparent")
        action_row.pack(fill='x', pady=(8, 0))
        
        ctk.CTkButton(action_row, text="Test Login", width=100, height=28,
                     command=lambda s=session: self._test_session(s, domain_name, False)).pack(side='left', padx=2)
        
        ctk.CTkButton(action_row, text="Test + Save Output", width=130, height=28,
                     command=lambda s=session: self._test_session(s, domain_name, True)).pack(side='left', padx=2)
        
        ctk.CTkButton(action_row, text="Open Browser", width=100, height=28,
                     command=lambda s=session: self._open_browser(s, domain_name)).pack(side='left', padx=2)
        
        ctk.CTkButton(action_row, text="View Cookies", width=100, height=28,
                     command=lambda s=session: self._view_cookies(s)).pack(side='left', padx=2)
    
    def _test_session(self, session, domain, save_outputs):
        def test():
            success = self.login_mgr.verify_session(session, domain, save_outputs)
            msg = "Login successful!" if success else "Login failed!"
            if save_outputs and success:
                msg += f"\n\nOutputs saved to:\n{self.login_mgr.outputs_dir}"
            self.after(0, lambda: messagebox.showinfo("Test Result", msg))
            self.after(0, self.destroy)  # Refresh parent
        
        threading.Thread(target=test, daemon=True).start()
        messagebox.showinfo("Testing", "Testing session...")
    
    def _open_browser(self, session, domain):
        def open_browser():
            self.login_mgr.open_session_browser(session, domain)
        
        threading.Thread(target=open_browser, daemon=True).start()
    
    def _view_cookies(self, session):
        CookieViewer(self, session[0], self.db)


# ===========================================================================
# COOKIE VIEWER
# ===========================================================================

class CookieViewer(ctk.CTkToplevel):
    def __init__(self, parent, session_id, db):
        super().__init__(parent)
        self.session_id = session_id
        self.db = db
        
        self.title(f"Cookies - Session #{session_id}")
        self.geometry("900x700")
        self.transient(parent)
        
        header = ctk.CTkFrame(self, height=60, fg_color="#1a1a1a")
        header.pack(fill='x')
        
        ctk.CTkLabel(header, text=f"Cookie Details - Session #{session_id}",
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        filters = ctk.CTkFrame(self, fg_color="#252525", height=50)
        filters.pack(fill='x', padx=10, pady=10)
        
        filter_content = ctk.CTkFrame(filters, fg_color="transparent")
        filter_content.pack(fill='both', expand=True, padx=15, pady=10)
        
        self.auth_only = ctk.BooleanVar()
        ctk.CTkCheckBox(filter_content, text="Auth Cookies Only", 
                       variable=self.auth_only, command=self._load).pack(side='left', padx=10)
        
        self.exclude_expired = ctk.BooleanVar()
        ctk.CTkCheckBox(filter_content, text="Exclude Expired",
                       variable=self.exclude_expired, command=self._load).pack(side='left', padx=10)
        
        self.text = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Courier New", size=11))
        self.text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        self._load()
    
    def _load(self):
        try:
            self.text.delete("1.0", "end")
            
            cookies = self.db.get_session_cookies(self.session_id)
            
            if self.exclude_expired.get():
                cookies = [c for c in cookies if not c[10]]
            if self.auth_only.get():
                cookies = [c for c in cookies if c[9]]
            
            info = f"{'='*80}\nTotal Cookies: {len(cookies)}\n{'='*80}\n\n"
            
            for i, c in enumerate(cookies, 1):
                info += f"{i}. {c[2]}"
                
                tags = []
                if c[9]:
                    tags.append("AUTH")
                if c[10]:
                    tags.append("EXPIRED")
                if c[6]:
                    tags.append("SECURE")
                
                if tags:
                    info += f" [{', '.join(tags)}]"
                
                info += f"\n   Value: {str(c[3])[:80]}...\n"
                info += f"   Domain: {c[4]} | Path: {c[5]}\n\n"
            
            self.text.insert("1.0", info)
        except Exception as e:
            self.text.insert("1.0", f"Error loading cookies: {e}")


# ===========================================================================
# DOMAIN TABLE - IMPROVED LAYOUT
# ===========================================================================

class DomainTable(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.row_widgets = []
        
        # Fixed header
        self._create_header()
        
        # Scrollable content
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color="#0a0a0a")
        self.scroll_frame.pack(fill='both', expand=True)
    
    def _create_header(self):
        header = ctk.CTkFrame(self, height=45, fg_color="#1a1a1a", corner_radius=0)
        header.pack(fill='x', pady=(0, 2))
        header.pack_propagate(False)
        
        columns = [
            ("FAV", 60),
            ("Domain", 350),
            ("Category", 100),
            ("Sessions", 90),
            ("Success Rate", 120),
            ("Total Cookies", 120),
        ]
        
        x = 10
        for col_name, width in columns:
            btn = ctk.CTkButton(header, text=col_name, width=width, height=35,
                              fg_color="transparent", hover_color="#2d2d2d",
                              font=ctk.CTkFont(size=11, weight="bold"),
                              command=lambda c=col_name: self._sort_by(c))
            btn.place(x=x, y=5)
            x += width + 5
    
    def _sort_by(self, col_name):
        sort_map = {
            'Domain': 'domain',
            'Category': 'category',
            'Sessions': 'sessions',
            'Success Rate': 'success_rate'
        }
        
        if col_name in sort_map:
            if self.app.sort_by == sort_map[col_name]:
                self.app.sort_order = 'ASC' if self.app.sort_order == 'DESC' else 'DESC'
            else:
                self.app.sort_by = sort_map[col_name]
                self.app.sort_order = 'DESC'
            self.app.refresh()
    
    def refresh(self, domains_data):
        for widget in self.row_widgets:
            try:
                widget.destroy()
            except:
                pass
        self.row_widgets.clear()
        
        for idx, data in enumerate(domains_data):
            self._create_row(idx, data)
    
    def _create_row(self, idx, data):
        try:
            (domain_id, domain, category, favorite, session_count, 
             total_cookies, success_count, fail_count, success_rate, *_) = data
            
            bg_color = "#1a1a1a" if idx % 2 == 0 else "#141414"
            
            row = ctk.CTkFrame(self.scroll_frame, height=40, fg_color=bg_color, corner_radius=0)
            row.pack(fill='x', pady=1)
            row.pack_propagate(False)
            
            # Make entire row clickable
            row.bind('<Button-1>', lambda e, d=data: self.app._show_sessions(d))
            row.configure(cursor="hand2")
            
            x = 10
            
            # Favorite button
            star = '★' if favorite else '☆'
            color = '#ffd700' if favorite else '#666666'
            fav_btn = ctk.CTkButton(row, text=star, width=50, height=30,
                                  fg_color=color, hover_color='#ffd700',
                                  font=ctk.CTkFont(size=14),
                                  command=lambda d=domain: self._toggle_fav(d))
            fav_btn.place(x=x, y=5)
            x += 65
            
            # Domain (clickable)
            dom_lbl = ctk.CTkLabel(row, text=domain, width=340, anchor='w',
                                 font=ctk.CTkFont(size=12))
            dom_lbl.place(x=x, y=10)
            dom_lbl.bind('<Button-1>', lambda e, d=data: self.app._show_sessions(d))
            dom_lbl.configure(cursor="hand2")
            x += 355
            
            # Category
            ctk.CTkLabel(row, text=category or 'Other', width=95,
                        font=ctk.CTkFont(size=11), text_color='#888888').place(x=x, y=10)
            x += 105
            
            # Sessions count
            ctk.CTkLabel(row, text=str(session_count), width=85,
                        font=ctk.CTkFont(size=11), text_color='#4a9eff').place(x=x, y=10)
            x += 95
            
            # Success rate
            rate_color = '#0d7d4d' if success_rate > 70 else '#c77700' if success_rate > 30 else '#b91c1c'
            rate_text = f"{success_rate:.1f}%" if success_rate > 0 else "N/A"
            ctk.CTkLabel(row, text=rate_text, width=115,
                        font=ctk.CTkFont(size=12, weight='bold'), text_color=rate_color).place(x=x, y=10)
            x += 125
            
            # Total cookies
            ctk.CTkLabel(row, text=str(total_cookies), width=115,
                        font=ctk.CTkFont(size=11), text_color='#888888').place(x=x, y=10)
            
            self.row_widgets.append(row)
        
        except Exception as e:
            logger.error(f"Create row error: {e}")
    
    def _toggle_fav(self, domain):
        self.app.db.toggle_favorite(domain)
        self.app.refresh()


# ===========================================================================
# MAIN APP
# ===========================================================================

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title(f"Cookie Manager Pro v{__version__} - Session Management")
        self.geometry("1100x850")
        self.minsize(1000, 750)
        
        try:
            self.db = Database()
            self.login_mgr = LoginManager(self.db)
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to initialize: {e}")
            self.destroy()
            return
        
        self.current_page = 0
        self.page_size = 100
        self.sort_by = 'success_rate'
        self.sort_order = 'DESC'
        self.is_loading = False
        self.current_domains = []
        
        self._create_ui()
        self._start_refresh()
    
    def _create_ui(self):
        # Header
        header = ctk.CTkFrame(self, height=120, fg_color="#1a1a1a", corner_radius=0)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        title_row = ctk.CTkFrame(header, fg_color="transparent")
        title_row.pack(fill='x', padx=20, pady=(15, 5))
        
        ctk.CTkLabel(title_row, text=f"Cookie Manager Pro v{__version__}",
                    font=ctk.CTkFont(size=20, weight="bold")).pack(side='left')
        
        self.loading_lbl = ctk.CTkLabel(title_row, text="", 
                                       font=ctk.CTkFont(size=10), text_color="#4a9eff")
        self.loading_lbl.pack(side='right')
        
        # Stats
        stats_row = ctk.CTkFrame(header, fg_color="transparent")
        stats_row.pack(fill='x', padx=20, pady=(0, 15))
        
        self.stats_widgets = {}
        stats_data = [
            ('total_domains', 'Domains', '#4a9eff'),
            ('total_sessions', 'Sessions', '#7841b6'),
            ('working_sessions', 'Working', '#0d7d4d'),
            ('failed_sessions', 'Failed', '#b91c1c'),
            ('pending_sessions', 'Pending', '#c77700'),
            ('avg_success_rate', 'Avg Rate', '#ffd700'),
        ]
        
        for i, (key, label, color) in enumerate(stats_data):
            stat = ctk.CTkFrame(stats_row, fg_color="#2d2d2d", corner_radius=6)
            stat.grid(row=0, column=i, padx=3, sticky='ew')
            stats_row.grid_columnconfigure(i, weight=1)
            
            ctk.CTkLabel(stat, text=label, font=ctk.CTkFont(size=9), text_color="gray").pack(padx=8, pady=(4, 0))
            
            if key == 'avg_success_rate':
                val = ctk.CTkLabel(stat, text="0%", font=ctk.CTkFont(size=14, weight="bold"), text_color=color)
            else:
                val = ctk.CTkLabel(stat, text="0", font=ctk.CTkFont(size=14, weight="bold"), text_color=color)
            val.pack(padx=8, pady=(0, 4))
            self.stats_widgets[key] = val
        
        # Toolbar
        toolbar = ctk.CTkFrame(self, height=55, fg_color="#1e1e1e")
        toolbar.pack(fill='x', padx=10, pady=(10, 5))
        toolbar.pack_propagate(False)
        
        toolbar_content = ctk.CTkFrame(toolbar, fg_color="transparent")
        toolbar_content.pack(fill='both', expand=True, padx=10, pady=10)
        
        btns = [
            ("📁 Load Cookies", self.load_cookies),
            ("🔍 Test All", self.test_all),
            ("📊 Open Outputs", self.open_outputs),
            ("💾 Export CSV", self.export_csv),
            ("🚫 Close Browsers", self.close_all),
        ]
        
        for text, cmd in btns:
            ctk.CTkButton(toolbar_content, text=text, command=cmd, width=130, height=35).pack(side='left', padx=3)
        
        # Filters
        filters = ctk.CTkFrame(self, height=55, fg_color="#252525")
        filters.pack(fill='x', padx=10, pady=(0, 10))
        filters.pack_propagate(False)
        
        filter_content = ctk.CTkFrame(filters, fg_color="transparent")
        filter_content.pack(fill='both', expand=True, padx=15, pady=10)
        
        ctk.CTkLabel(filter_content, text="Search:").pack(side='left', padx=(0, 5))
        
        self.search_var = ctk.StringVar()
        self.search_var.trace('w', lambda *_: self.refresh())
        ctk.CTkEntry(filter_content, textvariable=self.search_var, width=200, height=35,
                    placeholder_text="Type domain...").pack(side='left', padx=5)
        
        ctk.CTkLabel(filter_content, text="Category:").pack(side='left', padx=(15, 5))
        
        self.category_var = ctk.StringVar(value='All')
        ctk.CTkComboBox(filter_content, 
                       values=['All', 'Social', 'Shopping', 'Finance', 'Dev', 'Email', 'Media', 'Other'],
                       variable=self.category_var, command=lambda _: self.refresh(),
                       width=120, height=35).pack(side='left', padx=2)
        
        self.fav_var = ctk.BooleanVar()
        ctk.CTkCheckBox(filter_content, text="Favorites", variable=self.fav_var,
                       command=self.refresh).pack(side='left', padx=15)
        
        # Table
        table_container = ctk.CTkFrame(self, fg_color="transparent")
        table_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        self.table = DomainTable(table_container, self)
        self.table.pack(fill='both', expand=True)
        
        # Pagination
        pagination = ctk.CTkFrame(self, height=55, fg_color="#1e1e1e")
        pagination.pack(fill='x', padx=10, pady=(0, 10))
        pagination.pack_propagate(False)
        
        pag_content = ctk.CTkFrame(pagination, fg_color="transparent")
        pag_content.pack(fill='both', expand=True, padx=15, pady=10)
        
        ctk.CTkButton(pag_content, text="◀ Previous", width=100, height=35,
                     command=self.prev_page).pack(side='left', padx=(0, 10))
        
        self.page_label = ctk.CTkLabel(pag_content, text="Page 1 of 1",
                                     font=ctk.CTkFont(size=12, weight="bold"))
        self.page_label.pack(side='left', padx=10)
        
        ctk.CTkButton(pag_content, text="Next ▶", width=100, height=35,
                     command=self.next_page).pack(side='left', padx=(10, 20))
        
        ctk.CTkLabel(pag_content, text="Per page:").pack(side='left', padx=(20, 5))
        
        self.page_size_var = ctk.StringVar(value='100')
        ctk.CTkComboBox(pag_content, values=['50', '100', '200'],
                       variable=self.page_size_var, command=self._change_page_size,
                       width=80, height=35).pack(side='left')
        
        self.status_label = ctk.CTkLabel(pag_content, text="Ready • Click any domain to view sessions",
                                       font=ctk.CTkFont(size=11), text_color="#4a9eff")
        self.status_label.pack(side='right')
    
    def load_cookies(self):
        if self.is_loading:
            messagebox.showwarning("Loading", "Please wait...")
            return
        
        folder = filedialog.askdirectory()
        if not folder:
            return
        
        files = []
        try:
            for root, _, filenames in os.walk(folder):
                for f in filenames:
                    if f.endswith(('.txt', '.json', '.cookies')):
                        files.append(os.path.join(root, f))
        except Exception as e:
            messagebox.showerror("Scan Error", str(e))
            return
        
        if not files:
            messagebox.showwarning("No Files", "No cookie files found")
            return
        
        self.is_loading = True
        self.loading_lbl.configure(text="Loading...")
        
        try:
            progress = ProgressWindow(self, "Loading Cookies", len(files))
        except:
            self.is_loading = False
            return
        
        def load_safe():
            domains_data = []
            success = 0
            errors = 0
            
            try:
                for idx, path in enumerate(files, 1):
                    try:
                        if os.path.getsize(path) > 10_000_000:
                            continue
                        
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(5_000_000)
                        
                        content = content.replace('\ufeff', '')
                        cookies = Parser.parse(content, os.path.basename(path))
                        
                        if cookies:
                            domain = Parser.extract_domain(cookies, os.path.basename(path))
                            if domain:
                                category = Parser.categorize(domain)
                                domains_data.append((domain, category, path, cookies))
                                success += 1
                        
                        if idx % 10 == 0:
                            try:
                                self.after(0, lambda i=idx, s=success: progress.update(i, f"{s} domains"))
                            except:
                                pass
                        
                        if len(domains_data) >= 25:
                            try:
                                self.db.add_domain_batch(domains_data)
                                domains_data = []
                                gc.collect()
                            except:
                                errors += 1
                                domains_data = []
                    
                    except:
                        errors += 1
                
                if domains_data:
                    try:
                        self.db.add_domain_batch(domains_data)
                    except:
                        pass
            
            except:
                pass
            
            finally:
                try:
                    self.after(0, progress.close)
                    self.after(0, lambda: self._loading_complete(success, errors))
                except:
                    pass
        
        threading.Thread(target=load_safe, daemon=True).start()
    
    def _loading_complete(self, success, errors):
        self.is_loading = False
        self.loading_lbl.configure(text="")
        self.status_label.configure(text="Complete")
        self.refresh()
        messagebox.showinfo("Complete", f"Loaded: {success} domains\nErrors: {errors}")
    
    def test_all(self):
        if not messagebox.askyesno("Test All", 
            "This will test all pending sessions.\nSave outputs for successful logins?",
            icon='question'):
            return
        
        try:
            all_domains = self.db.get_domains()
            all_sessions = []
            
            for domain in all_domains:
                domain_id = domain[0]
                domain_name = domain[1]
                sessions = self.db.get_sessions(domain_id)
                for session in sessions:
                    if session[6] == 'pending':  # status
                        all_sessions.append((session, domain_name))
            
            if not all_sessions:
                messagebox.showinfo("No Sessions", "No pending sessions to test")
                return
            
            progress = ProgressWindow(self, "Testing Sessions", len(all_sessions))
            results = {'success': 0, 'failed': 0}
            
            def test():
                for idx, (session, domain_name) in enumerate(all_sessions, 1):
                    try:
                        success = self.login_mgr.verify_session(session, domain_name, save_outputs=True)
                        if success:
                            results['success'] += 1
                        else:
                            results['failed'] += 1
                        
                        progress.update(idx, f"{results['success']} success")
                        time.sleep(1)
                    except:
                        results['failed'] += 1
                
                progress.close()
                self.after(0, lambda: self._test_complete(results))
            
            threading.Thread(target=test, daemon=True).start()
        
        except Exception as e:
            logger.error(f"Test all error: {e}")
    
    def _test_complete(self, results):
        self.refresh()
        messagebox.showinfo("Testing Complete",
            f"Success: {results['success']}\nFailed: {results['failed']}\n\n"
            f"Outputs saved to:\n{self.login_mgr.outputs_dir}")
    
    def open_outputs(self):
        try:
            if platform.system() == 'Windows':
                os.startfile(self.login_mgr.outputs_dir)
            elif platform.system() == 'Darwin':
                subprocess.run(['open', self.login_mgr.outputs_dir])
            else:
                subprocess.run(['xdg-open', self.login_mgr.outputs_dir])
        except:
            messagebox.showinfo("Outputs", f"Folder: {self.login_mgr.outputs_dir}")
    
    def export_csv(self):
        try:
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if not path:
                return
            
            domains = self.db.get_domains()
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Category', 'Sessions', 'Success Rate', 'Total Cookies'])
                for d in domains:
                    writer.writerow([d[1], d[2], d[4], f"{d[8]:.1f}%", d[5]])
            
            messagebox.showinfo("Exported", f"Saved to: {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
    
    def close_all(self):
        count = self.login_mgr.close_all()
        messagebox.showinfo("Closed", f"Closed {count} browsers")
    
    def _show_sessions(self, domain_row):
        """Open session viewer window for this domain"""
        SessionViewer(self, domain_row, self.db, self.login_mgr)
    
    def _get_filters(self):
        filters = {}
        
        if self.search_var.get():
            filters['search'] = self.search_var.get()
        
        if self.fav_var.get():
            filters['favorite'] = True
        
        if self.category_var.get() != 'All':
            filters['category'] = self.category_var.get()
        
        return filters
    
    def refresh(self):
        self.current_page = 0
        self._load_page()
    
    def _load_page(self):
        try:
            filters = self._get_filters()
            total_count = self.db.get_domain_count(filters)
            total_pages = max(1, (total_count + self.page_size - 1) // self.page_size)
            
            if self.current_page >= total_pages:
                self.current_page = max(0, total_pages - 1)
            
            offset = self.current_page * self.page_size
            domains = self.db.get_domains(filters, limit=self.page_size, offset=offset, 
                                          sort_by=self.sort_by, sort_order=self.sort_order)
            
            self.current_domains = domains
            self.table.refresh(domains)
            
            self.page_label.configure(text=f"Page {self.current_page + 1} of {total_pages} • {total_count} total")
            self._update_stats()
        except Exception as e:
            logger.error(f"Load page error: {e}")
    
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
    
    def _update_stats(self):
        try:
            stats = self.db.get_stats()
            for key, widget in self.stats_widgets.items():
                if key == 'avg_success_rate':
                    widget.configure(text=f"{stats.get(key, 0):.1f}%")
                else:
                    widget.configure(text=str(stats.get(key, 0)))
        except:
            pass
    
    def _start_refresh(self):
        def loop():
            while True:
                time.sleep(5)
                try:
                    if self.winfo_exists():
                        self.after(0, self._update_stats)
                        gc.collect()
                except:
                    break
        
        threading.Thread(target=loop, daemon=True).start()


def main():
    try:
        app = App()
        
        def on_close():
            try:
                app.login_mgr.close_all()
                app.destroy()
            except:
                pass
        
        app.protocol("WM_DELETE_WINDOW", on_close)
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Failed to start: {e}")


if __name__ == '__main__':
    main()
