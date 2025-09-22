package middleware

import (
    "net/http"
    "sync"
    "time"

    "github.com/gin-gonic/gin"
    "golang.org/x/time/rate"
)

type userLimiter struct {
    limiter *rate.Limiter
    lastSeen time.Time
}

var (
    users = make(map[string]*userLimiter)
    mu sync.Mutex
)

func getLimiter(key string, rps float64, burst int) *rate.Limiter {
    mu.Lock()
    defer mu.Unlock()
    ul, ok := users[key]
    if !ok {
        limiter := rate.NewLimiter(rate.Limit(rps), burst)
        users[key] = &userLimiter{limiter: limiter, lastSeen: time.Now()}
        return limiter
    }
    ul.lastSeen = time.Now()
    return ul.limiter
}

func NewRateLimiter(rps float64, burst int) gin.HandlerFunc {
    go cleanup()
    return func(c *gin.Context) {
        // identify user by header X-User-ID for demo (replace with auth)
        userID := c.GetHeader("X-User-ID")
        if userID == "" {
            userID = c.ClientIP() // fallback to IP for unauthenticated
        }
        limiter := getLimiter(userID, rps, burst)
        if !limiter.Allow() {
            c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
            return
        }
        c.Next()
    }
}

func cleanup() {
    for {
        time.Sleep(time.Minute)
        mu.Lock()
        for k, v := range users {
            if time.Since(v.lastSeen) > 3*time.Minute {
                delete(users, k)
            }
        }
        mu.Unlock()
    }
}
