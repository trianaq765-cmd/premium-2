module.exports = {
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL || '',
    ADMIN_KEY: process.env.ADMIN_KEY || 'default-admin-key',
    SECRET_KEY: process.env.SECRET_KEY || 'default-secret-key',
    
    // Parse arrays from environment
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
