// ============================================================
// 💾 DATABASE & CACHE
// ============================================================

const NodeCache = require('node-cache');

const scriptCache = new NodeCache({ 
    stdTTL: 300,
    checkperiod: 60 
});

const blockedDevices = {
    devices: new Map(),
    
    addBlock(data) {
        const { hwid, ip, playerId, banId } = data;
        const entry = { ...data, blockedAt: Date.now() };
        
        if (hwid) this.devices.set(`hwid:${hwid}`, entry);
        if (ip) this.devices.set(`ip:${ip}`, entry);
        if (playerId) this.devices.set(`pid:${playerId}`, entry);
        if (banId) this.devices.set(`ban:${banId}`, entry);
    },
    
    isBlocked(hwid, ip, playerId) {
        let entry = null;
        
        if (hwid && this.devices.has(`hwid:${hwid}`)) {
            entry = this.devices.get(`hwid:${hwid}`);
        } else if (playerId && this.devices.has(`pid:${playerId}`)) {
            entry = this.devices.get(`pid:${playerId}`);
        } else if (ip && this.devices.has(`ip:${ip}`)) {
            entry = this.devices.get(`ip:${ip}`);
        }
        
        if (entry) {
            return { blocked: true, reason: entry.reason, banId: entry.banId };
        }
        return { blocked: false };
    },
    
    removeByBanId(banId) {
        const entry = this.devices.get(`ban:${banId}`);
        if (entry) {
            if (entry.hwid) this.devices.delete(`hwid:${entry.hwid}`);
            if (entry.ip) this.devices.delete(`ip:${entry.ip}`);
            if (entry.playerId) this.devices.delete(`pid:${entry.playerId}`);
            this.devices.delete(`ban:${banId}`);
            return true;
        }
        return false;
    },
    
    clearAll() {
        this.devices.clear();
    },
    
    getAll() {
        const bans = [];
        const seen = new Set();
        this.devices.forEach((entry) => {
            if (entry.banId && !seen.has(entry.banId)) {
                seen.add(entry.banId);
                bans.push(entry);
            }
        });
        return bans;
    },
    
    count() {
        const seen = new Set();
        this.devices.forEach((entry) => {
            if (entry.banId) seen.add(entry.banId);
        });
        return seen.size;
    }
};

const db = {
    logs: [],
    stats: {
        totalRequests: 0,
        successfulRequests: 0,
        browserBlocked: 0,
        devicesBanned: 0
    },
    
    addLog(log) {
        this.logs.unshift(log);
        if (this.logs.length > 500) {
            this.logs = this.logs.slice(0, 500);
        }
        
        this.stats.totalRequests++;
        if (log.success) this.stats.successfulRequests++;
        if (log.action === 'BROWSER_BLOCKED') this.stats.browserBlocked++;
        if (log.action === 'DEVICE_BANNED') this.stats.devicesBanned++;
    },
    
    getLogs(limit = 50) {
        return this.logs.slice(0, limit);
    },
    
    getStats() {
        return this.stats;
    }
};

module.exports = { db, scriptCache, blockedDevices };
