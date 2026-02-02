# KW Security - WordPress Plugin

A lightweight WordPress security plugin that provides controlled updates and essential security enhancements for WordPress installations.

## Features

- 🔒 **Controlled Updates**: Allows security patches while blocking major updates
- 🛡️ **Security Enhancements**: Disables XML-RPC and other security improvements
- 💬 **Comment Security**: Completely disables comments, pingbacks, and trackbacks
- 🚫 **Update Filtering**: Intelligent filtering of WordPress core, plugin, and theme updates

## Installation

1. Download the plugin zip file
2. Go to **WordPress Admin → Plugins → Add New**
3. Click **Upload Plugin** and select the zip file
4. Click **Install Now**
5. Click **Activate Plugin**

## What This Plugin Does

### Update Management
- ✅ **Allows minor WordPress core updates** (security patches)
- ❌ **Blocks major WordPress core updates** (feature releases)
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

## Technical Details

### Requirements
- **WordPress**: 5.0 or higher
- **PHP**: 7.4 or higher

### File Structure
```
kw-security/
├── kw-security.php                       # Main plugin file
├── classes/
│   └── class-kw-security.php             # Main security class
└── README.md                             # This file
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

## Hooks & Filters

### Actions Added
- `admin_init` - Disables comment admin functionality
- `init` - Disables comment frontend functionality
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

## Changelog

### Version 1.0.0
- Initial release
- Controlled update management
- XML-RPC security disable
- Complete comment system disable
- Pingback and trackback blocking
- Comment REST API endpoint removal
- Core, plugin, and theme update filtering

## License

This plugin is developed by KW Development.

---

**Developed by KW Development**