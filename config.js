module.exports = {
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL || '',
    ADMIN_KEY: process.env.ADMIN_KEY || 'change-this-admin-key',
    SECRET_KEY: process.env.SECRET_KEY || 'change-this-secret-key',
    OWNER_USER_IDS: process.env.OWNER_USER_IDS 
        ? process.env.OWNER_USER_IDS.split(',').map(id => parseInt(id.trim())).filter(id => !isNaN(id)) 
        : [],
    WHITELIST_USER_IDS: process.env.WHITELIST_USER_IDS 
        ? process.env.WHITELIST_USER_IDS.split(',').map(id => parseInt(id.trim())).filter(id => !isNaN(id)) 
        : [],
    ALLOWED_PLACE_IDS: process.env.ALLOWED_PLACE_IDS 
        ? process.env.ALLOWED_PLACE_IDS.split(',').map(id => parseInt(id.trim())).filter(id => !isNaN(id)) 
        : [],
    SCRIPT_ALREADY_OBFUSCATED: process.env.SCRIPT_ALREADY_OBFUSCATED === 'true',
    UPSTASH_REDIS_URL: process.env.UPSTASH_REDIS_REST_URL || '',
    UPSTASH_REDIS_TOKEN: process.env.UPSTASH_REDIS_REST_TOKEN || ''
};
