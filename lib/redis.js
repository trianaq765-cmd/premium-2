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

async function getBans() {
    if (!redis) return new Map();
    try {
        const data = await redis.hgetall(KEYS.BANS);
        if (!data) return new Map();
        const map = new Map();
        for (const [key, value] of Object.entries(data)) {
            map.set(key, typeof value === 'string' ? JSON.parse(value) : value);
        }
        return map;
    } catch { return new Map(); }
}

async function addBan(identifier, banData) {
    if (!redis) return false;
    try {
        await redis.hset(KEYS.BANS, { [identifier]: JSON.stringify(banData) });
        return true;
    } catch { return false; }
}

async function removeBan(identifier) {
    if (!redis) return false;
    try {
        await redis.hdel(KEYS.BANS, identifier);
        return true;
    } catch { return false; }
}

async function isBanned(hwid, ip, playerId) {
    if (!redis) return { blocked: false };
    try {
        const checks = [hwid, ip, String(playerId)].filter(Boolean);
        for (const id of checks) {
            const data = await redis.hget(KEYS.BANS, id);
            if (data) {
                const ban = typeof data === 'string' ? JSON.parse(data) : data;
                return { blocked: true, reason: ban.reason, banId: ban.banId };
            }
        }
        return { blocked: false };
    } catch { return { blocked: false }; }
}

async function clearBans() {
    if (!redis) return 0;
    try {
        const bans = await redis.hgetall(KEYS.BANS);
        const count = bans ? Object.keys(bans).length : 0;
        await redis.del(KEYS.BANS);
        return count;
    } catch { return 0; }
}

async function getAllBans() {
    if (!redis) return [];
    try {
        const data = await redis.hgetall(KEYS.BANS);
        if (!data) return [];
        return Object.entries(data).map(([key, value]) => ({
            key,
            ...(typeof value === 'string' ? JSON.parse(value) : value)
        }));
    } catch { return []; }
}

async function addLog(log) {
    if (!redis) return;
    try {
        await redis.lpush(KEYS.LOGS, JSON.stringify(log));
        await redis.ltrim(KEYS.LOGS, 0, 499);
    } catch {}
}

async function getLogs(limit = 50) {
    if (!redis) return [];
    try {
        const logs = await redis.lrange(KEYS.LOGS, 0, limit - 1);
        return logs.map(l => typeof l === 'string' ? JSON.parse(l) : l);
    } catch { return []; }
}

async function setChallenge(id, data, ttl = 60) {
    if (!redis) return false;
    try {
        await redis.setex(`${KEYS.CHALLENGES}:${id}`, ttl, JSON.stringify(data));
        return true;
    } catch { return false; }
}

async function getChallenge(id) {
    if (!redis) return null;
    try {
        const data = await redis.get(`${KEYS.CHALLENGES}:${id}`);
        if (!data) return null;
        return typeof data === 'string' ? JSON.parse(data) : data;
    } catch { return null; }
}

async function deleteChallenge(id) {
    if (!redis) return;
    try { await redis.del(`${KEYS.CHALLENGES}:${id}`); } catch {}
}

async function setToken(token, data, ttl = 300) {
    if (!redis) return false;
    try {
        await redis.setex(`${KEYS.TOKENS}:${token}`, ttl, JSON.stringify(data));
        return true;
    } catch { return false; }
}

async function getToken(token) {
    if (!redis) return null;
    try {
        const data = await redis.get(`${KEYS.TOKENS}:${token}`);
        if (!data) return null;
        return typeof data === 'string' ? JSON.parse(data) : data;
    } catch { return null; }
}

async function deleteToken(token) {
    if (!redis) return;
    try { await redis.del(`${KEYS.TOKENS}:${token}`); } catch {}
}

async function getCachedScript() {
    if (!redis) return null;
    try {
        const data = await redis.get(KEYS.SCRIPT_CACHE);
        if (!data) return null;
        const parsed = typeof data === 'string' ? JSON.parse(data) : data;
        if (Date.now() - parsed.timestamp > 300000) return null;
        return parsed.script;
    } catch { return null; }
}

async function setCachedScript(script) {
    if (!redis) return;
    try {
        if (!script) { await redis.del(KEYS.SCRIPT_CACHE); return; }
        await redis.setex(KEYS.SCRIPT_CACHE, 600, JSON.stringify({ script, timestamp: Date.now() }));
    } catch {}
}

async function getStats() {
    if (!redis) return { totalLogs: 0, blockedDevices: 0, platform: 'memory' };
    try {
        const logsLen = await redis.llen(KEYS.LOGS);
        const bans = await redis.hgetall(KEYS.BANS);
        return { totalLogs: logsLen, blockedDevices: bans ? Object.keys(bans).length : 0, platform: 'upstash' };
    } catch { return { totalLogs: 0, blockedDevices: 0, platform: 'error' }; }
}

module.exports = { redis, getBans, addBan, removeBan, isBanned, clearBans, getAllBans, addLog, getLogs, setChallenge, getChallenge, deleteChallenge, setToken, getToken, deleteToken, getCachedScript, setCachedScript, getStats };
