// ============================================================
// ⚙️ CONFIGURATION - v5.1.0
// ============================================================

module.exports = {
    // Script source
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL || '',
    
    // Security keys
    ADMIN_KEY: process.env.ADMIN_KEY || 'default-admin-key-change-this',
    SECRET_KEY: process.env.SECRET_KEY || 'default-secret-key-change-this',
    
    // ⭐ NEW: Skip encryption jika script sudah obfuscated
    SCRIPT_ALREADY_OBFUSCATED: process.env.SCRIPT_ALREADY_OBFUSCATED === 'true',
    
    // User lists
    WHITELIST_USER_IDS: (process.env.WHITELIST_USER_IDS || '')
        .split(',')
        .map(id => parseInt(id.trim()))
        .filter(id => !isNaN(id)),
    
    OWNER_USER_IDS: (process.env.OWNER_USER_IDS || '')
        .split(',')
        .map(id => parseInt(id.trim()))
        .filter(id => !isNaN(id)),
    
    ALLOWED_PLACE_IDS: (process.env.ALLOWED_PLACE_IDS || '')
        .split(',')
        .map(id => parseInt(id.trim()))
        .filter(id => !isNaN(id))
};
