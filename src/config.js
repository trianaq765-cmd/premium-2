// ============================================================
// ⚙️ CONFIGURATION - v5.1.0 SIMPLIFIED
// ============================================================

module.exports = {
    // Script source URL (required)
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL || '',
    
    // Security keys
    ADMIN_KEY: process.env.ADMIN_KEY || 'change-this-admin-key-in-production',
    SECRET_KEY: process.env.SECRET_KEY || 'change-this-secret-key-in-production',
    
    // Script mode - set to true if script is already obfuscated
    SCRIPT_ALREADY_OBFUSCATED: process.env.SCRIPT_ALREADY_OBFUSCATED === 'true',
    
    // Whitelist user IDs - empty array means allow all
    WHITELIST_USER_IDS: (process.env.WHITELIST_USER_IDS || '')
        .split(',')
        .map(id => parseInt(id.trim()))
        .filter(id => !isNaN(id) && id > 0),
    
    // Owner user IDs - script will stop if owner joins
    OWNER_USER_IDS: (process.env.OWNER_USER_IDS || '')
        .split(',')
        .map(id => parseInt(id.trim()))
        .filter(id => !isNaN(id) && id > 0),
    
    // Allowed place IDs - empty array means allow all games
    ALLOWED_PLACE_IDS: (process.env.ALLOWED_PLACE_IDS || '')
        .split(',')
        .map(id => parseInt(id.trim()))
        .filter(id => !isNaN(id) && id > 0)
};
