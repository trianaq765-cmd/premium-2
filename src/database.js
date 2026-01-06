// ============================================================
// 📦 DATABASE - v5.1.0 FULL (In-Memory)
// ============================================================

const crypto = require('crypto');
const config = require('./config');

// ============================================================
// STORAGE
// ============================================================

const logs = [];
const blockedList = [];
let cachedScript = null;
let cacheTimestamp = null;
const challengeMap = new Map();

// ============================================================
// CLEANUP INTERVAL - Remove expired challenges
// ============================================================

setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [id, data] of challengeMap.entries()) {
        if (now - data.createdAt > config.CHALLENGE.EXPIRY_MS) {
            challengeMap.delete(id);
            cleaned++;
        }
    }
    
    if (cleaned > 0) {
        console.log(`🧹 [CLEANUP] Removed ${cleaned} expired challenges`);
    }
}, config.CHALLENGE.CLEANUP_INTERVAL_MS);

// ============================================================
// DATABASE MODULE
// ============================================================

module.exports = {
    // ============================================================
    // LOGS
    // ============================================================
    db: {
        addLog(log) {
            logs.unshift({
                ...log,
                id: crypto.randomBytes(4).toString('hex')
            });
            
            // Limit log size
            while (logs.length > config.CACHE.MAX_LOGS) {
                logs.pop();
            }
        },
        
        getLogs(limit = 50) {
            return logs.slice(0, Math.min(limit, logs.length));
        },
        
        getLogsByAction(action, limit = 50) {
            return logs
                .filter(log => log.action === action)
                .slice(0, limit);
        },
        
        getLogsByIP(ip, limit = 50) {
            return logs
                .filter(log => log.ip === ip)
                .slice(0, limit);
        },
        
        getLogsByUserId(userId, limit = 50) {
            return logs
                .filter(log => log.playerId == userId || log.userId == userId)
                .slice(0, limit);
        },
        
        clearLogs() {
            logs.length = 0;
        },
        
        getStats() {
            const now = Date.now();
            const oneHourAgo = now - (60 * 60 * 1000);
            const oneDayAgo = now - (24 * 60 * 60 * 1000);
            
            const recentLogs = logs.filter(l => new Date(l.timestamp).getTime() > oneHourAgo);
            const dailyLogs = logs.filter(l => new Date(l.timestamp).getTime() > oneDayAgo);
            
            return {
                totalLogs: logs.length,
                logsLastHour: recentLogs.length,
                logsLastDay: dailyLogs.length,
                successRate: logs.length > 0 
                    ? Math.round((logs.filter(l => l.success).length / logs.length) * 100) 
                    : 0,
                blockedCount: blockedList.length,
                activeChallenges: challengeMap.size,
                hasCachedScript: !!cachedScript,
                cacheAge: cacheTimestamp ? Math.floor((now - cacheTimestamp) / 1000) + 's' : null
            };
        }
    },
    
    // ============================================================
    // SCRIPT CACHE
    // ============================================================
    scriptCache: {
        get(key) {
            return cachedScript;
        },
        
        set(key, value) {
            cachedScript = value;
            cacheTimestamp = Date.now();
        },
        
        has(key) {
            return !!cachedScript;
        },
        
        flushAll() {
            cachedScript = null;
            cacheTimestamp = null;
        },
        
        getInfo() {
            return {
                cached: !!cachedScript,
                size: cachedScript ? cachedScript.length : 0,
                timestamp: cacheTimestamp,
                age: cacheTimestamp ? Math.floor((Date.now() - cacheTimestamp) / 1000) : null
            };
        }
    },
    
    // ============================================================
    // BLOCKED DEVICES
    // ============================================================
    blockedDevices: {
        isBlocked(hwid, ip, playerId) {
            for (const block of blockedList) {
                // Check HWID
                if (hwid && block.hwid && block.hwid === hwid) {
                    return { 
                        blocked: true, 
                        reason: block.reason, 
                        banId: block.banId,
                        matchedBy: 'hwid'
                    };
                }
                
                // Check IP
                if (ip && block.ip && block.ip === ip) {
                    return { 
                        blocked: true, 
                        reason: block.reason, 
                        banId: block.banId,
                        matchedBy: 'ip'
                    };
                }
                
                // Check Player ID
                if (playerId && block.playerId && block.playerId == playerId) {
                    return { 
                        blocked: true, 
                        reason: block.reason, 
                        banId: block.banId,
                        matchedBy: 'playerId'
                    };
                }
            }
            return { blocked: false };
        },
        
        addBlock(data) {
            // Check if already blocked
            const existing = this.isBlocked(data.hwid, data.ip, data.playerId);
            if (existing.blocked) {
                return { success: false, reason: 'Already blocked', banId: existing.banId };
            }
            
            blockedList.push({
                ...data,
                createdAt: Date.now()
            });
            
            return { success: true, banId: data.banId };
        },
        
        getAll() {
            return blockedList.map(block => ({
                ...block,
                age: Math.floor((Date.now() - block.createdAt) / 1000) + 's'
            }));
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
        
        removeByPlayerId(playerId) {
            const index = blockedList.findIndex(b => b.playerId == playerId);
            if (index !== -1) {
                blockedList.splice(index, 1);
                return true;
            }
            return false;
        },
        
        removeByHWID(hwid) {
            const index = blockedList.findIndex(b => b.hwid === hwid);
            if (index !== -1) {
                blockedList.splice(index, 1);
                return true;
            }
            return false;
        },
        
        clearAll() {
            const count = blockedList.length;
            blockedList.length = 0;
            return count;
        },
        
        search(query) {
            const q = query.toLowerCase();
            return blockedList.filter(block => 
                (block.hwid && block.hwid.toLowerCase().includes(q)) ||
                (block.ip && block.ip.includes(q)) ||
                (block.playerId && block.playerId.toString().includes(q)) ||
                (block.playerName && block.playerName.toLowerCase().includes(q)) ||
                (block.banId && block.banId.toLowerCase().includes(q))
            );
        }
    },
    
    // ============================================================
    // CHALLENGES
    // ============================================================
    challenges: {
        store: challengeMap,
        
        create(userId, hwid, placeId, ip) {
            const id = crypto.randomBytes(16).toString('hex');
            
            // Generate random numbers for puzzle
            const a = crypto.randomInt(1, 50);
            const b = crypto.randomInt(1, 50);
            const c = crypto.randomInt(1, 50);
            
            const challenge = {
                id,
                puzzle: { 
                    numbers: [a, b, c], 
                    operation: 'sum' 
                },
                solution: a + b + c,
                userId,
                hwid,
                placeId,
                ip,
                createdAt: Date.now(),
                attempts: 0
            };
            
            challengeMap.set(id, challenge);
            return challenge;
        },
        
        get(id) {
            return challengeMap.get(id);
        },
        
        delete(id) {
            return challengeMap.delete(id);
        },
        
        verify(id, solution, ip) {
            const challenge = challengeMap.get(id);
            
            // Check if challenge exists
            if (!challenge) {
                return { 
                    valid: false, 
                    error: 'Invalid or expired challenge' 
                };
            }
            
            // Check expiry
            if (Date.now() - challenge.createdAt > config.CHALLENGE.EXPIRY_MS) {
                challengeMap.delete(id);
                return { 
                    valid: false, 
                    error: 'Challenge expired' 
                };
            }
            
            // Check IP match
            if (challenge.ip !== ip) {
                challengeMap.delete(id);
                return { 
                    valid: false, 
                    error: 'IP mismatch - request from different network' 
                };
            }
            
            // Increment attempts
            challenge.attempts++;
            
            // Check max attempts (prevent brute force)
            if (challenge.attempts > 3) {
                challengeMap.delete(id);
                return { 
                    valid: false, 
                    error: 'Too many attempts' 
                };
            }
            
            // Verify solution
            if (parseInt(solution) !== challenge.solution) {
                return { 
                    valid: false, 
                    error: 'Invalid solution',
                    attemptsLeft: 3 - challenge.attempts
                };
            }
            
            // Success - delete challenge (one-time use)
            challengeMap.delete(id);
            
            return { 
                valid: true, 
                challenge 
            };
        },
        
        getCount() {
            return challengeMap.size;
        },
        
        getByUserId(userId) {
            for (const [id, challenge] of challengeMap.entries()) {
                if (challenge.userId === userId) {
                    return challenge;
                }
            }
            return null;
        },
        
        deleteByUserId(userId) {
            for (const [id, challenge] of challengeMap.entries()) {
                if (challenge.userId === userId) {
                    challengeMap.delete(id);
                    return true;
                }
            }
            return false;
        },
        
        clearAll() {
            const count = challengeMap.size;
            challengeMap.clear();
            return count;
        }
    }
};
