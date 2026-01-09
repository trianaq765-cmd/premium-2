const { Redis } = require('@upstash/redis');
const config = require('../config');

let redis = null;

if (config.UPSTASH_REDIS_URL && config.UPSTASH_REDIS_TOKEN) {
    redis = new Redis({
        url: config.UPSTASH_REDIS_URL,
        token: config.UPSTASH_REDIS_TOKEN
    });
}

const KEYS = {
    BANS: 'premium:bans',
    LOGS: 'premium:logs',
    CHALLENGES: 'premium:challenges',
    TOKENS: 'premium:tokens',
    SCRIPT_CACHE: 'premium:script'
};

async function addBan(identifier, banData) {
    if (!redis) return false;
    try {
        await redis.hset(KEYS.BANS, { [identifier]: JSON.stringify(banData) });
        return true;
    } catch (e) {
        console.error('[REDIS] addBan error:', e.message);
        return false;
    }
}

async function removeBan(identifier) {
    if (!redis) return false;
    try {
        await redis.hdel(KEYS.BANS, identifier);
        return true;
    } catch (e) {
        console.error('[REDIS] removeBan error:', e.message);
        return false;
    }
}

async function removeBanById(banId) {
    if (!redis) return false;
    try {
        const data = await redis.hgetall(KEYS.BANS);
        if (!data) return false;
        for (const [key, value] of Object.entries(data)) {
            try {
                const parsed = typeof value === 'string' ? JSON.parse(value) : value;
                if (parsed.banId === banId) {
                    await redis.hdel(KEYS.BANS, key);
                    return true;
                }
            } catch (e) {}
        }
        return false;
    } catch (e) {
        console.error('[REDIS] removeBanById error:', e.message);
        return false;
    }
}

async function isBanned(hwid, ip, playerId) {
    if (!redis) return { blocked: false };
    try {
        const checks = [hwid, ip, playerId ? String(playerId) : null].filter(Boolean);
        for (const id of checks) {
            const data = await redis.hget(KEYS.BANS, id);
            if (data) {
                const ban = typeof data === 'string' ? JSON.parse(data) : data;
                return { blocked: true, reason: ban.reason || 'Banned', banId: ban.banId };
            }
        }
        return { blocked: false };
    } catch (e) {
        console.error('[REDIS] isBanned error:', e.message);
        return { blocked: false };
    }
}

async function clearBans() {
    if (!redis) return 0;
    try {
        const bans = await redis.hgetall(KEYS.BANS);
        const count = bans ? Object.keys(bans).length : 0;
        if (count > 0) {
            await redis.del(KEYS.BANS);
        }
        return count;
    } catch (e) {
        console.error('[REDIS] clearBans error:', e.message);
        return 0;
    }
}

async function getAllBans() {
    if (!redis) return [];
    try {
        const data = await redis.hgetall(KEYS.BANS);
        if (!data) return [];
        return Object.entries(data).map(([key, value]) => {
            try {
                const parsed = typeof value === 'string' ? JSON.parse(value) : value;
                return { key, ...parsed };
            } catch (e) {
                return { key, error: 'parse_failed' };
            }
        });
    } catch (e) {
        console.error('[REDIS] getAllBans error:', e.message);
        return [];
    }
}

async function addLog(log) {
    if (!redis) return;
    try {
        await redis.lpush(KEYS.LOGS, JSON.stringify(log));
        await redis.ltrim(KEYS.LOGS, 0, 999);
    } catch (e) {
        console.error('[REDIS] addLog error:', e.message);
    }
}

async function getLogs(limit = 50) {
    if (!redis) return [];
    try {
        const logs = await redis.lrange(KEYS.LOGS, 0, limit - 1);
        if (!logs) return [];
        return logs.map(l => {
            try {
                return typeof l === 'string' ? JSON.parse(l) : l;
            } catch (e) {
                return null;
            }
        }).filter(Boolean);
    } catch (e) {
        console.error('[REDIS] getLogs error:', e.message);
        return [];
    }
}

async function setChallenge(id, data, ttl = 120) {
    if (!redis) return false;
    try {
        await redis.setex(`${KEYS.CHALLENGES}:${id}`, ttl, JSON.stringify(data));
        return true;
    } catch (e) {
        console.error('[REDIS] setChallenge error:', e.message);
        return false;
    }
}

async function getChallenge(id) {
    if (!redis) return null;
    try {
        const data = await redis.get(`${KEYS.CHALLENGES}:${id}`);
        if (!data) return null;
        return typeof data === 'string' ? JSON.parse(data) : data;
    } catch (e) {
        console.error('[REDIS] getChallenge error:', e.message);
        return null;
    }
}

async function deleteChallenge(id) {
    if (!redis) return;
    try {
        await redis.del(`${KEYS.CHALLENGES}:${id}`);
    } catch (e) {
        console.error('[REDIS] deleteChallenge error:', e.message);
    }
}

async function setToken(token, data, ttl = 300) {
    if (!redis) return false;
    try {
        await redis.setex(`${KEYS.TOKENS}:${token}`, ttl, JSON.stringify(data));
        return true;
    } catch (e) {
        console.error('[REDIS] setToken error:', e.message);
        return false;
    }
}

async function getToken(token) {
    if (!redis) return null;
    try {
        const data = await redis.get(`${KEYS.TOKENS}:${token}`);
        if (!data) return null;
        return typeof data === 'string' ? JSON.parse(data) : data;
    } catch (e) {
        console.error('[REDIS] getToken error:', e.message);
        return null;
    }
}

async function getCachedScript() {
    if (!redis) return null;
    try {
        const data = await redis.get(KEYS.SCRIPT_CACHE);
        if (!data) return null;
        const parsed = typeof data === 'string' ? JSON.parse(data) : data;
        if (Date.now() - parsed.timestamp > 300000) {
            await redis.del(KEYS.SCRIPT_CACHE);
            return null;
        }
        return parsed.script;
    } catch (e) {
        console.error('[REDIS] getCachedScript error:', e.message);
        return null;
    }
}

async function setCachedScript(script) {
    if (!redis) return;
    try {
        if (!script) {
            await redis.del(KEYS.SCRIPT_CACHE);
            return;
        }
        await redis.setex(KEYS.SCRIPT_CACHE, 600, JSON.stringify({
            script,
            timestamp: Date.now()
        }));
    } catch (e) {
        console.error('[REDIS] setCachedScript error:', e.message);
    }
}

async function getStats() {
    if (!redis) return { success: 0, failed: 0, challenges: 0, bans: 0, platform: 'memory' };
    try {
        const logs = await getLogs(500);
        const bans = await getAllBans();
        const successLogs = logs.filter(l => l && l.success);
        const failedLogs = logs.filter(l => l && !l.success);
        const challengeLogs = logs.filter(l => l && l.action && l.action.includes('CHALLENGE'));
        return {
            success: successLogs.length,
            failed: failedLogs.length,
            challenges: challengeLogs.length,
            bans: bans.length,
            totalLogs: logs.length,
            platform: 'upstash'
        };
    } catch (e) {
        console.error('[REDIS] getStats error:', e.message);
        return { success: 0, failed: 0, challenges: 0, bans: 0, platform: 'error' };
    }
}

async function clearLogs() {
    if (!redis) return 0;
    try {
        const count = await redis.llen(KEYS.LOGS);
        await redis.del(KEYS.LOGS);
        return count || 0;
    } catch (e) {
        console.error('[REDIS] clearLogs error:', e.message);
        return 0;
    }
}

async function healthCheck() {
    if (!redis) return { status: 'no_redis', connected: false };
    try {
        await redis.ping();
        return { status: 'ok', connected: true, platform: 'upstash' };
    } catch (e) {
        return { status: 'error', connected: false, error: e.message };
    }
}

module.exports = {
    addBan,
    removeBan,
    removeBanById,
    isBanned,
    clearBans,
    getAllBans,
    addLog,
    getLogs,
    clearLogs,
    setChallenge,
    getChallenge,
    deleteChallenge,
    setToken,
    getToken,
    getCachedScript,
    setCachedScript,
    getStats,
    healthCheck
};
