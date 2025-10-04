# Cookie Manager Pro v0.5 BETA - Session Management Edition

**Advanced cookie-based authentication manager with multi-session tracking, intelligent sorting, and automated output logging.**

---

## 🎯 Key Features

### ✨ New in v0.5 BETA

- **Multi-Session Support**: Each domain can have multiple sessions (different cookie sets representing different accounts/logins)
- **Smart Success Rate Sorting**: Automatically calculates and sorts domains by login success rate
- **Output Logging**: Automatically saves HTML page source + screenshots for successful logins
- **Session Viewer**: Click any domain to view ALL sessions and test each one individually
- **Improved UI**: Stable, compact table layout with fixed headers and smooth scrolling
- **Session Intelligence**: Automatically identifies unique sessions based on auth cookie fingerprints

### 🔥 Core Features

- **Bulk Cookie Import**: Load thousands of cookie files from folders automatically
- **Automated Testing**: Test all sessions with Selenium-based verification
- **Browser Integration**: Open any session directly in Chrome with cookies injected
- **Smart Detection**: Identifies auth cookies, expired cookies, and session identifiers
- **Export Reports**: Export domain/session data to CSV for analysis
- **Favorites System**: Star important domains for quick access
- **Advanced Filtering**: Filter by category, search, favorites, success rate

---

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Main Interface](#main-interface)
- [Session Management](#session-management)
- [Output Logging](#output-logging)
- [Database Structure](#database-structure)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## 🚀 Installation

### Prerequisites

```bash
# Python 3.8+ required
python --version

# Install required packages
pip install customtkinter selenium requests urllib3
```

### Chrome WebDriver

**Option 1 - Automatic (Recommended)**:
```bash
pip install webdriver-manager
```

**Option 2 - Manual**:
1. Download ChromeDriver: https://chromedriver.chromium.org/
2. Match your Chrome version
3. Add to system PATH

### Run the Application

```bash
python cookie_manager_v0.5_beta.py
```

---

## 🎮 Quick Start

### 1. Load Cookies

1. Click **"📁 Load Cookies"**
2. Select folder containing cookie files (`.txt`, `.json`, `.cookies`)
3. Wait for import to complete
4. Domains appear in the main table

### 2. View Sessions for a Domain

**Method 1**: Click anywhere on a domain row  
**Method 2**: Click the domain name directly

This opens the **Session Viewer** showing ALL sessions for that domain.

### 3. Test a Session

In the Session Viewer window:
- **"Test Login"** - Quick verification
- **"Test + Save Output"** - Verify AND save HTML + screenshot
- **"Open Browser"** - Open Chrome with cookies loaded
- **"View Cookies"** - See all cookies for this session

### 4. Bulk Testing

1. Click **"🔍 Test All"** in main toolbar
2. Choose whether to save outputs
3. All pending sessions will be tested automatically
4. Results saved to `login_outputs/` folder

---

## 📊 Main Interface

### Header Stats

```
┌─────────────────────────────────────────────────┐
│ Domains  │ Sessions │ Working │ Failed │ Pending │ Avg Rate │
│    45    │   127    │   89    │   23   │   15    │  70.1%   │
└─────────────────────────────────────────────────┘
```

- **Domains**: Total unique domains
- **Sessions**: Total session count across all domains  
- **Working**: Sessions that successfully logged in
- **Failed**: Sessions that failed verification
- **Pending**: Untested sessions
- **Avg Rate**: Average success rate across all domains

### Table Columns

| Column | Description |
|--------|-------------|
| **FAV** | ★ Click to favorite/unfavorite |
| **Domain** | Domain name (click to view sessions) |
| **Category** | Auto-categorized (Social, Shopping, Dev, etc.) |
| **Sessions** | Number of unique sessions for this domain |
| **Success Rate** | Login success % (green >70%, yellow 30-70%, red <30%) |
| **Total Cookies** | Sum of all cookies across all sessions |

### Toolbar Actions

- **📁 Load Cookies** - Import cookie files from folder
- **🔍 Test All** - Test all pending sessions with optional output saving
- **📊 Open Outputs** - Open `login_outputs/` folder in file explorer
- **💾 Export CSV** - Export table data to CSV file
- **🚫 Close Browsers** - Close all open browser windows

### Filters

- **Search**: Type to filter domains by name
- **Category**: Filter by auto-detected category
- **Favorites**: Show only starred domains

### Sorting

Click any column header to sort:
- **Domain**: Alphabetically (A-Z / Z-A)
- **Sessions**: By session count (High to Low / Low to High)
- **Success Rate**: By login success % ⭐ **Default - Shows best performing first**

---

## 🔐 Session Management

### What is a Session?

A **session** is a unique set of cookies representing a single login/account for a domain.

**Example**: You might have `facebook.com` with:
- Session #1: Alice's account cookies
- Session #2: Bob's account cookies  
- Session #3: Charlie's account cookies

Each session is tracked separately with its own success rate.

### How Sessions are Detected

The system creates unique sessions by:
1. **Hashing auth cookies** - Creates fingerprint from authentication cookies
2. **Different cookie values** = Different session
3. **Same cookies from different files** = Same session (merged)

### Session Identifier

Each session shows a readable identifier like:
```
session_id[3f7a8b2...]
PHPSESSID[9k4j2m...]
auth_token[a1b2c3...]
```

This helps you identify which account/login the cookies belong to.

### Session Viewer Window

When you click a domain, you see ALL its sessions:

```
┌─────────────────────────────────────────────────────────┐
│ All Sessions for: facebook.com                          │
│                                    Success Rate: 75.5%  │
├─────────────────────────────────────────────────────────┤
│ #1: session_id[abc123...]                               │
│ SUCCESS | Auth: 12 | Total: 45 | Attempts: 10 (80%)    │
│ [Test Login] [Test + Save] [Open Browser] [View Cookies]│
├─────────────────────────────────────────────────────────┤
│ #2: PHPSESSID[xyz789...]                                │
│ PENDING | Auth: 8 | Total: 32 | ⚠ EXPIRES SOON         │
│ [Test Login] [Test + Save] [Open Browser] [View Cookies]│
└─────────────────────────────────────────────────────────┘
```

#### Session Actions

1. **Test Login**
   - Quick headless verification
   - Updates status (SUCCESS/FAILED)
   - Takes ~5 seconds

2. **Test + Save Output**  
   - Verifies login
   - **Saves screenshot** to `login_outputs/screenshots/`
   - **Saves HTML source** to `login_outputs/html/`
   - Only saves if login succeeds

3. **Open Browser**
   - Opens visible Chrome window
   - Injects session cookies
   - Manually verify the login
   - Browser stays open for manual use

4. **View Cookies**
   - Shows all cookies for this session
   - Filter by Auth Only / Exclude Expired
   - See cookie details (name, value, domain, expiry)

---

## 📁 Output Logging

### Directory Structure

```
cookie_manager_v8_complete.py
cookies_v8.db
login_outputs/
├── screenshots/
│   ├── facebook_com_abc123_20250104_143022.png
│   ├── github_com_xyz789_20250104_143045.png
│   └── ...
└── html/
    ├── facebook_com_abc123_20250104_143022.html
    ├── github_com_xyz789_20250104_143045.html
    └── ...
```

### Output Files

**Screenshots**: Full-page PNG screenshots of logged-in pages  
**HTML**: Complete page source for analysis/verification

### Filename Format

```
{domain}_{session_hash}_{timestamp}.{ext}

Example:
amazon_com_a1b2c3d4_20250104_143530.png
         │         └── Timestamp (YYYYMMDD_HHMMSS)
         └── Session hash (first 8 chars)
```

### When Outputs are Saved

Outputs are saved ONLY when:
1. "Test + Save Output" button clicked in Session Viewer, OR
2. "Test All" is run with save option enabled
3. AND the login verification succeeds

**No outputs for failed logins** (saves disk space).

### Viewing Outputs

- Click **"📊 Open Outputs"** in toolbar
- Or manually browse to `login_outputs/` folder
- Screenshots open in default image viewer
- HTML files open in default browser

---

## 🗄️ Database Structure

### Tables

#### **domains**
Main domain tracking table.

```sql
domain          - Domain name (unique)
category        - Auto-detected category
favorite        - 1 if starred, 0 if not
session_count   - Number of sessions for this domain
total_cookies   - Sum of cookies across all sessions
success_count   - Total successful login attempts
fail_count      - Total failed login attempts  
success_rate    - Calculated % (success / total * 100)
```

#### **sessions**
Individual session tracking.

```sql
domain_id           - Foreign key to domains
session_hash        - Unique fingerprint (MD5 of auth cookies)
session_identifier  - Human-readable session name
auth_cookie_count   - Number of auth cookies
total_cookies       - Total cookies in this session
status              - 'pending', 'success', or 'failed'
last_verified       - ISO timestamp of last test
login_speed         - Time taken to verify (e.g. "3.2s")
expires_soon        - 1 if cookies expire within 7 days
success_count       - Successful attempts for THIS session
fail_count          - Failed attempts for THIS session
```

#### **cookies**
Cookie storage linked to sessions.

```sql
session_id      - Foreign key to sessions
name            - Cookie name
value           - Cookie value
domain          - Cookie domain
path            - Cookie path
secure          - 1 if HTTPS only
httponly        - 1 if HTTP only (no JS access)
expiry          - Unix timestamp expiration
is_auth         - 1 if detected as authentication cookie
is_expired      - 1 if past expiry date
importance_score - 0.0-1.0 calculated importance
```

#### **login_outputs**
Tracks saved output files.

```sql
session_id   - Which session this output is for
output_type  - 'screenshot' or 'html'
file_path    - Full path to the output file
created_at   - When output was created
```

### Database Location

`cookies_v0.5.db` in the same folder as the script.

### Backup Your Database

```bash
# Create backup
cp cookies_v0.5.db cookies_v0.5_backup.db

# Or use SQLite command
sqlite3 cookies_v0.5.db ".backup cookies_v0.5_backup.db"
```

---

## ⌨️ Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Refresh table | F5 |
| Search focus | Ctrl+F |
| Load cookies | Ctrl+O |
| Export CSV | Ctrl+E |
| Close app | Ctrl+Q |

*(Note: Some shortcuts may vary by OS)*

---

## 🔧 Troubleshooting

### "ChromeDriver not found"

**Solution**: Install webdriver-manager:
```bash
pip install webdriver-manager
```

Or download manually from https://chromedriver.chromium.org/

### "Database is locked"

**Solution**: 
- Close all instances of the app
- Delete `cookies_v0.5.db-wal` and `cookies_v0.5.db-shm` files
- Restart the app

### Sessions not detecting properly

**Solution**: 
- Ensure cookie files have proper formatting
- Supported formats: Netscape format (tab-separated), JSON
- Check that cookies aren't all expired

### Login verification always fails

**Possible causes**:
1. **Cookies expired** - Check cookie expiry dates
2. **Wrong domain** - Ensure domain matches cookie domain
3. **Bot detection** - Some sites detect headless browsers
4. **2FA required** - Can't bypass two-factor authentication

### UI is laggy with many domains

**Solutions**:
- Reduce page size (50 instead of 100)
- Use filters to narrow results
- Database has 10,000+ domains? Consider splitting data

### Can't import certain cookie files

**Supported formats**:
```
# Netscape/Mozilla format (tab-separated)
.domain.com    TRUE    /    FALSE    1234567890    name    value

# JSON format
[{"name": "cookie", "value": "val", "domain": ".example.com", ...}]
```

**Not supported**:
- Encrypted Chrome cookies (need to decrypt first)
- Binary formats
- Custom proprietary formats

---

## ❓ FAQ

### Q: How many sessions can one domain have?

**A**: Unlimited. The system will create a new session for each unique set of cookies.

### Q: What's the difference between "Test Login" and "Test + Save Output"?

**A**: 
- **Test Login**: Quick verification only, no files saved
- **Test + Save Output**: Verification + saves screenshot & HTML if successful

### Q: Can I delete sessions?

**A**: Currently no UI for deletion. Manually edit the database or re-import cookies.

### Q: Why is my success rate 0%?

**A**: No sessions have been tested yet. Run "Test All" or test individual sessions.

### Q: How does the success rate calculation work?

**A**: 
```
Success Rate = (Total Success / Total Attempts) × 100

Example:
- Success: 15 times
- Failed: 5 times  
- Total: 20 attempts
- Rate: (15/20) × 100 = 75%
```

### Q: Can I use this with Firefox/Safari?

**A**: Currently Chrome only. Firefox support possible but requires geckodriver.

### Q: Is my cookie data secure?

**A**: 
- ✅ Stored locally in SQLite database
- ✅ No cloud upload or external connections (except during login testing)
- ⚠️ Database is NOT encrypted - anyone with file access can read cookies
- 🔒 Recommendation: Use full-disk encryption on your system

### Q: What happens to expired cookies?

**A**: 
- Marked as `is_expired=1` in database
- Can be filtered out in Cookie Viewer
- Still stored (for historical tracking)
- Won't be used in login attempts

### Q: Can I run multiple instances?

**A**: Not recommended. SQLite database may lock. If needed, use separate folders with separate databases.

### Q: How to contribute or report bugs?

**A**: This is a standalone script. Report issues through your distribution channel or modify the code directly.

---

## 📈 Performance Tips

### For Large Cookie Collections (10,000+ domains)

1. **Use Filters**: Don't load everything at once
2. **Reduce Page Size**: Use 50 per page instead of 200
3. **Regular Cleanup**: Remove old/expired sessions
4. **Index Optimization**: Database auto-indexes on domain, status
5. **Test in Batches**: Don't test all 10k at once

### For Faster Testing

1. **Quick Check Mode**: Use requests-based verification (if implemented)
2. **Parallel Testing**: System uses ThreadPoolExecutor for concurrent tests
3. **Skip Successful**: Filter out already-verified sessions
4. **Headless Mode**: Always faster than visible browsers

---

## 🔐 Security Considerations

### Cookie Data is Sensitive

Cookies can contain:
- Session tokens (login bypass)
- Authentication credentials
- Personal information
- Financial data access

### Best Practices

1. **Never share the database file**
2. **Encrypt your hard drive**
3. **Don't commit cookies to Git** (add to `.gitignore`)
4. **Delete when done** with analysis
5. **Legal use only** - Only test cookies you own or have permission to use

### Legal Disclaimer

This tool is for:
- ✅ Security research (your own accounts)
- ✅ Authorized penetration testing
- ✅ Cookie management for your accounts
- ❌ Unauthorized access
- ❌ Account theft
- ❌ Illegal activities

**You are responsible for how you use this software.**

---

## 🛠️ Advanced Usage

### Custom Categories

Edit the `Parser.categorize()` function:

```python
categories = {
    'Banking': ['chase', 'wellsfargo', 'bofa'],
    'MyCategory': ['keyword1', 'keyword2'],
}
```

### Database Queries

Direct SQL access:

```bash
sqlite3 cookies_v0.5.db

# Show all domains with >80% success rate
SELECT domain, success_rate 
FROM domains 
WHERE success_rate > 80 
ORDER BY success_rate DESC;

# Count sessions by status
SELECT status, COUNT(*) 
FROM sessions 
GROUP BY status;
```

### Export All Session Data

```sql
.mode csv
.output sessions_export.csv
SELECT d.domain, s.session_identifier, s.status, s.success_count, s.fail_count
FROM sessions s
JOIN domains d ON s.domain_id = d.id
ORDER BY d.domain;
.quit
```

---

## 📚 Version History

### v0.5 BETA (Current)
- ✨ Multi-session support per domain
- ✨ Session-based success rate tracking
- ✨ Output logging (HTML + screenshots)
- ✨ Click domain to view all sessions
- ✨ Improved stable UI layout
- 🔧 Fixed table rendering issues
- 🔧 Better session detection algorithm

### Earlier versions
- Table view implementation
- AI insights
- Progress tracking
- Export capabilities

---

## 🤝 Credits

Built with:
- **CustomTkinter** - Modern UI framework
- **Selenium** - Browser automation
- **SQLite** - Database storage
- **Python** - Core language

---

## 📄 License

This software is provided as-is for educational and authorized security research purposes.

---

## 📞 Support

For issues, questions, or suggestions:
- Check the FAQ section
- Review troubleshooting guide
- Modify the source code as needed (it's Python!)

---

**Happy Cookie Managing! 🍪**

*Remember: With great cookies comes great responsibility.*
