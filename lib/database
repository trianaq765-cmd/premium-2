/**
 * In-Memory Database
 * WARNING: Data akan hilang saat server restart!
 * Untuk production, gunakan Redis atau database persistent
 */

class InMemoryDB {
    constructor() {
        this.data = new Map();
        this.bans = new Map();
        this.logs = [];
        this.challenges = new Map();
        this.tokens = new Map();
        this.cachedScript = null;
        this.cachedScriptExpiry = 0;
        this.maxLogs = 1000;
        
        // Auto cleanup expired data setiap 60 detik
        setInterval(() => this.cleanup(), 60000);
        
        console.log('📦 Using In-Memory Database (data will be lost on restart)');
    }
    
    cleanup() {
        const now = Date.now();
        
        // Cleanup expired challenges
        for (const [key, value] of this.challenges) {
            if (value.expiry && value.expiry < now) {
                this.challenges.delete(key);
            }
        }
        
        // Cleanup expired tokens
        for (const [key, value] of this.tokens) {
            if (value.expiry && value.expiry < now) {
                this.tokens.delete(key);
            }
        }
        
        // Trim logs
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(-this.maxLogs);
        }
    }
    
    // ==================== CHALLENGES ====================
    async setChallenge(id, data, ttlSeconds = 60) {
        this.challenges.set(id, {
            ...data,
            expiry: Date.now() + (ttlSeconds * 1000)
        });
    }
    
    async getChallenge(id) {
        const challenge = this.challenges.get(id);
        if (!challenge) return null;
        if (challenge.expiry < Date.now()) {
            this.challenges.delete(id);
            return null;
        }
        return challenge;
    }
    
    async deleteChallenge(id) {
        this.challenges.delete(id);
    }
    
    // ==================== TOKENS ====================
    async setToken(token, data, ttlSeconds = 300) {
        this.tokens.set(token, {
            ...data,
            expiry: Date.now() + (ttlSeconds * 1000)
        });
    }
    
    async getToken(token) {
        const tokenData = this.tokens.get(token);
        if (!tokenData) return null;
        if (tokenData.expiry < Date.now()) {
            this.tokens.delete(token);
            return null;
        }
        return tokenData;
    }
    
    // ==================== BANS ====================
    async addBan(identifier, data) {
        this.bans.set(identifier, {
            ...data,
            key: identifier,
            createdAt: Date.now()
        });
    }
    
    async isBanned(hwid, ip, playerId) {
        // Check by HWID
        if (hwid) {
            const ban = this.bans.get(hwid);
            if (ban) return { blocked: true, reason: ban.reason, banId: ban.banId };
        }
        
        // Check by Player ID
        if (playerId) {
            const ban = this.bans.get(String(playerId));
            if (ban) return { blocked: true, reason: ban.reason, banId: ban.banId };
        }
        
        // Check by IP
        if (ip) {
            const ban = this.bans.get(ip);
            if (ban) return { blocked: true, reason: ban.reason, banId: ban.banId };
        }
        
        return { blocked: false };
    }
    
    async getAllBans() {
        return Array.from(this.bans.values());
    }
    
    async removeBan(identifier) {
        this.bans.delete(identifier);
    }
    
    async clearBans() {
        const count = this.bans.size;
        this.bans.clear();
        return count;
    }
    
    // ==================== LOGS ====================
    async addLog(logData) {
        this.logs.push({
            ...logData,
            id: Date.now() + Math.random().toString(36).substr(2, 9)
        });
        
        // Keep only last maxLogs entries
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(-this.maxLogs);
        }
    }
    
    async getLogs(limit = 50) {
        return this.logs.slice(-limit).reverse();
    }
    
    // ==================== SCRIPT CACHE ====================
    async setCachedScript(script, ttlSeconds = 300) {
        if (script === null) {
            this.cachedScript = null;
            this.cachedScriptExpiry = 0;
        } else {
            this.cachedScript = script;
            this.cachedScriptExpiry = Date.now() + (ttlSeconds * 1000);
        }
    }
    
    async getCachedScript() {
        if (!this.cachedScript) return null;
        if (this.cachedScriptExpiry < Date.now()) {
            this.cachedScript = null;
            return null;
        }
        return this.cachedScript;
    }
    
    // ==================== STATS ====================
    async getStats() {
        const now = Date.now();
        const oneHourAgo = now - 3600000;
        const oneDayAgo = now - 86400000;
        
        const recentLogs = this.logs.filter(log => {
            const logTime = new Date(log.ts).getTime();
            return logTime > oneHourAgo;
        });
        
        const dailyLogs = this.logs.filter(log => {
            const logTime = new Date(log.ts).getTime();
            return logTime > oneDayAgo;
        });
        
        return {
            totalBans: this.bans.size,
            totalLogs: this.logs.length,
            activeChallenges: this.challenges.size,
            activeTokens: this.tokens.size,
            logsLastHour: recentLogs.length,
            logsLast24h: dailyLogs.length,
            scriptCached: !!this.cachedScript,
            uptime: process.uptime()
        };
    }
}

module.exports = new InMemoryDB();
