const crypto = require('crypto');

// In-memory storage
const logs = [];
const blockedDevices = [];
let cachedScript = null;
const challenges = new Map();

// Cleanup expired challenges setiap 30 detik
setInterval(() => {
    const now = Date.now();
    for (const [id, data] of challenges.entries()) {
        if (now - data.createdAt > 60000) {
            challenges.delete(id);
        }
    }
}, 30000);

module.exports = {
    db: {
        addLog(log) {
            logs.unshift(log);
            if (logs.length > 1000) logs.pop();
        },
        getLogs(limit = 50) {
            return logs.slice(0, limit);
        },
        getStats() {
            return {
                totalLogs: logs.length,
                blockedCount: blockedDevices.length,
                activeChallenges: challenges.size,
                hasCachedScript: !!cachedScript
            };
        }
    },
    
    scriptCache: {
        get(key) {
            return cachedScript;
        },
        set(key, value) {
            cachedScript = value;
        },
        has(key) {
            return !!cachedScript;
        },
        flushAll() {
            cachedScript = null;
        }
    },
    
    blockedDevices: {
        isBlocked(hwid, ip, playerId) {
            for (const block of blockedDevices) {
                if (hwid && block.hwid === hwid) {
                    return { blocked: true, reason: block.reason, banId: block.banId };
                }
                if (ip && block.ip === ip) {
                    return { blocked: true, reason: block.reason, banId: block.banId };
                }
                if (playerId && block.playerId == playerId) {
                    return { blocked: true, reason: block.reason, banId: block.banId };
                }
            }
            return { blocked: false };
        },
        addBlock(data) {
            blockedDevices.push(data);
        },
        getAll() {
            return blockedDevices;
        },
        count() {
            return blockedDevices.length;
        },
        removeByBanId(banId) {
            const index = blockedDevices.findIndex(b => b.banId === banId);
            if (index !== -1) {
                blockedDevices.splice(index, 1);
                return true;
            }
            return false;
        },
        clearAll() {
            blockedDevices.length = 0;
        }
    },
    
    challenges: {
        store: challenges,
        
        create(userId, hwid, placeId, ip) {
            const id = crypto.randomBytes(16).toString('hex');
            const a = crypto.randomInt(1, 50);
            const b = crypto.randomInt(1, 50);
            const c = crypto.randomInt(1, 50);
            
            const challenge = {
                id,
                puzzle: { numbers: [a, b, c], operation: 'sum' },
                solution: a + b + c,
                userId,
                hwid,
                placeId,
                ip,
                createdAt: Date.now()
            };
            
            challenges.set(id, challenge);
            return challenge;
        },
        
        get(id) {
            return challenges.get(id);
        },
        
        delete(id) {
            challenges.delete(id);
        },
        
        verify(id, solution, ip) {
            const challenge = challenges.get(id);
            
            if (!challenge) {
                return { valid: false, error: 'Invalid or expired challenge' };
            }
            
            if (Date.now() - challenge.createdAt > 60000) {
                challenges.delete(id);
                return { valid: false, error: 'Challenge expired' };
            }
            
            if (challenge.ip !== ip) {
                challenges.delete(id);
                return { valid: false, error: 'IP mismatch' };
            }
            
            if (parseInt(solution) !== challenge.solution) {
                challenges.delete(id);
                return { valid: false, error: 'Invalid solution' };
            }
            
            challenges.delete(id);
            return { valid: true, challenge };
        }
    }
};
