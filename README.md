# KW Security - WordPress Plugin

A lightweight WordPress security plugin that provides controlled updates and essential security enhancements for WordPress installations.

## Features

- 🔒 **Controlled Updates**: Allows security patches while blocking major updates
- 🛡️ **HTTP Security Headers**: X-Frame-Options, CSP, HSTS, Referrer-Policy, Permissions-Policy
- 🚪 **Hide Login URL**: Replace `/wp-login.php` with a custom slug
- 👤 **User Enumeration Protection**: Block `?author=N` leaks and gate `/wp/v2/users` REST endpoint
- 🔐 **Login Rate Limiting**: Lock out IPs after repeated failed login attempts
- 🔍 **File Integrity Monitoring**: Daily scan of WP root for unknown PHP files and modifications to `index.php` / `wp-config.php`
- 💬 **Comment Security**: Disables comments, pingbacks, and trackbacks
- 📁 **File Security**: Prevents dangerous file uploads and disables file editing
- 🔁 **GitHub Update Notifications**: Surfaces new releases on the WordPress Updates screen
- ⚙️ **Feature Toggles**: Every feature can be enabled or disabled per site from **Settings → KW Security**

## Installation

1. Download the plugin zip file
2. Go to **WordPress Admin → Plugins → Add New**
3. Click **Upload Plugin** and select the zip file
4. Click **Install Now**
5. Click **Activate Plugin**
6. Configure feature toggles at **Settings → KW Security**

## Feature Toggles

Every security feature can be turned on or off per site from **Settings → KW Security**.
Defaults: all features enabled, except **Hide Login URL** (opt-in, off by default).

| Toggle | Default | What it controls |
|---|---|---|
| Disable Comments | ON | Comments site-wide, dashboard widget, REST endpoints, pingbacks |
| File Security | ON | Dangerous upload blocking, file editor disable, `/uploads/.htaccess` |
| Controlled Auto-Updates | ON | Security-only auto-updates for core/plugins/themes |
| Disable XML-RPC Pingbacks | ON | XML-RPC disable + pingback method removal |
| HTTP Security Headers | ON | X-Frame-Options, CSP, HSTS, Referrer-Policy, Permissions-Policy |
| Block User Enumeration | ON | `/?author=N` 404, auth required for `/wp/v2/users` |
| Login Rate Limiting | ON | 5 failed attempts / 15 min → 1-hour IP lockout; generic "Invalid login credentials" error |
| File Integrity Monitoring | ON | Daily WP-Cron scan; emails admin on unknown PHP in root or modified `index.php` / `wp-config.php` |
| Hide Login URL | **OFF** | Custom login slug; replaces `/wp-login.php` and `/wp-admin` |

> **About "Hide Login URL":** Disabled by default because changing the login URL is a disruptive change that requires bookmarking a custom URL. Enable only when ready, and configure the slug in the same Settings → KW Security page before saving.

When a feature is disabled, **none of its hooks are registered** — there is zero runtime cost.

## What This Plugin Does

### Update Management
- ✅ **Allows minor WordPress core updates** (security patches: 6.1.1 → 6.1.2)
- ❌ **Blocks major WordPress core updates** (feature releases: 6.1.x → 6.2.x)
- ✅ **Allows plugin security updates** (patch versions only)
- ❌ **Blocks regular plugin updates** (feature releases)
- ❌ **Blocks all theme updates**

### Security Enhancements
- ❌ **Disables XML-RPC** for improved security
- 🔒 **Controlled automatic updates** to prevent breaking changes
- 🛡️ **Security-first update policy**

### Comment Security
- ❌ **Disables all comments** site-wide
- ❌ **Disables pingbacks and trackbacks**
- 🚫 **Removes comment admin pages** and menu items
- 🔒 **Blocks comment REST API endpoints**
- 🧹 **Hides existing comments** from frontend

### File Security
- ❌ **Disables WordPress file editor** in admin area
- 🚫 **Blocks dangerous file uploads** (.php, .exe, .bat, .js, etc.)
- 🔒 **Prevents PHP execution** in uploads directory
- 🛡️ **Blocks double extensions** (e.g., file.php.jpg)
- 📁 **Creates .htaccess protection** in uploads folder

## Technical Details

### Requirements
- **WordPress**: 5.0 or higher
- **PHP**: 7.4 or higher

### File Structure
```
kw-security/
├── kw-security.php                      # Main plugin file & autoloader
├── classes/
│   ├── settings.php                    # Feature toggle UI + is_enabled() helper
│   ├── class-kw-security.php           # Core security class (gated by toggles)
│   ├── hide-login-url.php              # Custom login URL routing
│   ├── security-headers.php            # HTTP security headers
│   ├── user-enumeration.php            # Block user enumeration
│   ├── login-rate-limiter.php          # Failed-login IP lockout
│   ├── file-integrity.php              # Daily root-dir scan + email alerts
│   └── updater.php                     # GitHub-based update checker
├── vendor/
│   └── plugin-update-checker/          # PUC v5.6 library (vendored)
└── README.md                           # This file
```

### Constants Defined
- `KW_SECURITY_NAME` - Plugin name
- `KW_SECURITY_VERSION` - Current version
- `KW_SECURITY_SLUG` - Plugin slug
- `KW_SECURITY_MINIMUM_WP_VERSION` - Minimum WordPress version
- `KW_SECURITY_PLUGIN_DIR` - Plugin directory path
- `KW_SECURITY_PLUGIN_URL` - Plugin URL
- `KW_SECURITY_PLUGIN_FILE` - Main plugin file path

## Security Features Explained

### Update Filtering Logic

#### Core Updates
- **Security patches**: Allowed (e.g., 6.1.1 → 6.1.2)
- **Major releases**: Blocked (e.g., 6.1.x → 6.2.x)
- **Minor releases**: Blocked (e.g., 6.1.x → 6.2.x)

#### Plugin Updates
- **Patch versions**: Allowed (e.g., 1.2.3 → 1.2.4)
- **Minor versions**: Blocked (e.g., 1.2.x → 1.3.x)
- **Major versions**: Blocked (e.g., 1.x.x → 2.x.x)

#### Theme Updates
- **All updates**: Blocked for stability

### XML-RPC Security
XML-RPC is disabled to prevent:
- Brute force attacks
- DDoS amplification attacks
- Unauthorized remote access

### Comment Security
Comments are completely disabled to prevent:
- **Comment spam** and automated spam bots
- **Security vulnerabilities** in comment processing
- **Database bloat** from spam comments
- **SEO penalties** from spammy comment content
- **Performance issues** from comment queries

The plugin removes:
- Comment forms from all posts and pages
- Comment admin pages and menu items
- Comment-related database queries
- Comment REST API endpoints
- Admin bar comment notifications
- Dashboard comment widgets

### File Security
File uploads are secured to prevent:
- **Malicious file uploads** that could compromise the server
- **PHP backdoors** being uploaded and executed
- **Script execution** in the uploads directory
- **Double extension attacks** (file.php.jpg)

The plugin blocks these dangerous file types:
- **Executable files**: .exe, .com, .bat, .cmd, .scr, .msi, .dll
- **Script files**: .php, .js, .vbs, .py, .pl, .sh, .cgi
- **Web scripts**: .asp, .aspx, .jsp, .cfm
- **Database files**: .sql, .db, .sqlite, .mdb
- **Config files**: .htaccess, .ini, .conf, .config
- **Backup files**: .bak, .backup, .old, .tmp

Additionally, it:
- Creates .htaccess rules in uploads directory
- Prevents execution of any PHP files in uploads
- Disables the WordPress file editor completely

## Hooks & Filters

### Actions Added
- `admin_init` - Disables comment admin functionality
- `init` - Disables comment frontend functionality and file editing
- `admin_menu` - Removes comment admin menu
- `wp_enqueue_scripts` - Removes comment reply scripts

### Filters Added
- `allow_minor_auto_core_updates` - Enables security updates
- `allow_major_auto_core_updates` - Disables major updates
- `auto_update_plugin` - Controls plugin updates
- `auto_update_theme` - Disables theme updates
- `pre_site_transient_update_core` - Filters core updates
- `pre_site_transient_update_themes` - Hides theme updates
- `xmlrpc_enabled` - Disables XML-RPC
- `comments_open` - Disables comments
- `pings_open` - Disables pingbacks/trackbacks
- `comments_array` - Hides existing comments
- `rest_endpoints` - Removes comment REST API endpoints
- `upload_mimes` - Restricts allowed file upload types
- `wp_handle_upload_prefilter` - Blocks dangerous file uploads

## Customization for Developers

### Changing Update Policy
Modify the `is_security_update()` method to adjust what constitutes a security update:
```php
private function is_security_update($item) {
    // Your custom logic here
}
```

### Adding More Security Features
Extend the `init_hooks()` method to add additional security measures.

## Releasing a New Version

Follow these steps every time you want to push an update to client sites.

### Step 1 — Bump the version

In `kw-security.php`, update **both** places:

```php
// Plugin header (line ~4)
Version: 26.05.06

// Constant (line ~18)
define('KW_SECURITY_VERSION', '26.05.06');
```

Version format is `YY.MM.PATCH` (e.g. `26.05.06` = year 2026, May, patch 6).

### Step 2 — Commit and push

```bash
git add kw-security.php
git commit -m "chore: bump version to 26.05.06"
git push
```

### Step 3 — Create the release zip

Clone or pull the repo locally, then run this in PowerShell **from inside the repo's parent directory**:

```powershell
$tmp = "$env:TEMP\kw-security"
if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
Copy-Item -Path ".\kw-security-plugin" -Destination $tmp -Recurse -Force
Compress-Archive -Path $tmp -DestinationPath ".\kw-security.zip" -Force
Remove-Item $tmp -Recurse -Force
```

This creates `kw-security.zip` in the current directory with the correct root folder name (`kw-security\`) that WordPress expects when installing the update.

> **Why the folder name matters:** When WordPress extracts the update zip, it uses the root folder name as the plugin directory. It must match the existing installed folder (`kw-security`) — a mismatch creates a duplicate plugin instead of updating the existing one.

### Step 4 — Publish the GitHub release

1. Go to [github.com/Kilowott-HQ/kw-security-plugin/releases/new](https://github.com/Kilowott-HQ/kw-security-plugin/releases/new)
2. **Tag:** enter the version number exactly as in the plugin header (e.g. `26.05.06`) — no `v` prefix
3. **Target:** `main`
4. **Title:** `KW Security 26.05.06`
5. **Release notes:** brief summary of what changed
6. **Attach binaries:** drag and drop `kw-security.zip` from Step 3
7. Click **Publish release**

### Step 5 — Verify on a site

Visit this URL while logged in as admin on any site running the plugin:

```
https://example.com/wp-admin/plugins.php?force-check=1
```

The update notice should appear under KW Security on the Plugins screen within a few seconds.

> **Note:** Without `?force-check=1`, WordPress checks for updates every 12 hours. The force-check bypasses the cache immediately.

---

## Changelog

### Version 26.05.07
- **Login Rate Limiting**: locks out IPs for 1 hour after 5 failed attempts within 15 minutes; generic error message prevents username enumeration
- **File Integrity Monitoring**: daily WP-Cron scan of WP root directory; emails admin when unknown PHP files appear or `index.php`/`wp-config.php` are modified. Manual scan + baseline reset available from Settings → KW Security
- Auto-reset of integrity baseline after WordPress core updates (avoids false positives on legitimate `index.php` changes)
- Plugin deactivation now properly clears scheduled cron jobs
- Both new features address the Preikestolen Basecamp RCA (24 April 2026) findings on brute-force exposure and root-directory file injection

### Version 26.05.06
- **Feature toggle system**: every security feature can now be enabled or disabled from **Settings → KW Security**
- All features ON by default, except Hide Login URL which is opt-in
- Disabled features skip hook registration entirely (zero runtime cost)
- Hide Login URL slug/redirect configuration moved from Settings → General to the new KW Security settings page
- "Settings" link added to the plugin row on the Plugins screen for quick access

### Version 26.05.04
- HTTP security headers (X-Frame-Options, Content-Security-Policy, HSTS, Referrer-Policy, Permissions-Policy, X-Content-Type-Options)
- Block user enumeration via `?author=N` for anonymous visitors
- Restrict `/wp/v2/users` REST endpoint to authenticated users only
- Disable XML-RPC pingback methods
- GitHub-based plugin update notifications via plugin-update-checker v5.6
- Fixed: `allow_security_updates_only` was silently blocking all plugin auto-updates (missing second filter argument)
- Fixed: duplicate hooks in comment disabling frontend logic
- Fixed: dashboard Recent Comments widget removal now fires at correct hook timing

### Version 26.04.07
- Initial release
- Controlled update management
- XML-RPC security disable
- Complete comment system disable
- Pingback and trackback blocking
- Comment REST API endpoint removal
- WordPress file editor disable
- Dangerous file upload blocking
- PHP execution prevention in uploads
- .htaccess upload directory protection
- Core, plugin, and theme update filtering
- **New Feature:** Added Custom Login URL rendering to completely hide the default `wp-login.php` and `wp-admin` workflows.

## License

This plugin is developed by KW Development.

---

**Developed by KW Development**