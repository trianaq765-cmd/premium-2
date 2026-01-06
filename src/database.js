// ============================================================
// 📦 DATABASE - v5.1.0 (In-Memory)
// ============================================================

const crypto = require('crypto');

// Storage
const logs = [];
const blockedList = [];
let cachedScript = null;
const challengeMap = new Map();

// Cleanup expired challenges
setInterval(() => {
    const now = Date.now();
    for (const [id, data] of challengeMap.entries()) {
        if (now - data.createdAt > 60000) {
            challengeMap.delete(id);
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
                blockedCount: blockedList.length,
                activeChallenges: challengeMap.size,
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
            for (const block of blockedList) {
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
            blockedList.push(data);
        },
        getAll() {
            return blockedList;
        },
        count() {
            return blockedList.length;
        },
        removeByBanId(banId) {
            const index = blockedList.findIndex(b => b.banId === banId);
            if (index !== -1) {
                blockedList.splice(index, 1);
                return true;
            }
            return false;
        },
        clearAll() {
            blockedList.length = 0;
        }
    },
    
    challenges: {
        store: challengeMap,
        
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
            
            challengeMap.set(id, challenge);
            return challenge;
        },
        
        get(id) {
            return challengeMap.get(id);
        },
        
        delete(id) {
            challengeMap.delete(id);
        },
        
        verify(id, solution, ip) {
            const challenge = challengeMap.get(id);
            
            if (!challenge) {
                return { valid: false, error: 'Invalid or expired challenge' };
            }
            
            if (Date.now() - challenge.createdAt > 60000) {
                challengeMap.delete(id);
                return { valid: false, error: 'Challenge expired' };
            }
            
            if (challenge.ip !== ip) {
                challengeMap.delete(id);
                return { valid: false, error: 'IP mismatch' };
            }
            
            if (parseInt(solution) !== challenge.solution) {
                challengeMap.delete(id);
                return { valid: false, error: 'Invalid solution' };
            }
            
            challengeMap.delete(id);
            return { valid: true, challenge };
        }
    }
};
