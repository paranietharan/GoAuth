package middleware

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	apperrors "GoAuth/internal/errors"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	redisClient *redis.Client
	mu          sync.Mutex
	memoryStore map[string][]time.Time
}

func NewRateLimiter(redisClient *redis.Client) *RateLimiter {
	return &RateLimiter{
		redisClient: redisClient,
		memoryStore: make(map[string][]time.Time),
	}
}

func (rl *RateLimiter) Limit(keyPrefix string, maxRequests int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		key := fmt.Sprintf("ratelimit:%s:%s", keyPrefix, clientIP)

		allowed, retryAfter := rl.allow(c.Request.Context(), key, maxRequests, window)
		if !allowed {
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			apperrors.Write(c, apperrors.ErrRateLimitExceeded)
			c.Abort()
			return
		}

		c.Next()
	}
}

func (rl *RateLimiter) allow(ctx context.Context, key string, maxRequests int, window time.Duration) (bool, int) {
	if rl.redisClient != nil {
		allowed, retryAfter, err := rl.allowRedis(ctx, key, maxRequests, window)
		if err == nil {
			return allowed, retryAfter
		}
	}

	return rl.allowMemory(key, maxRequests, window)
}

func (rl *RateLimiter) allowRedis(ctx context.Context, key string, maxRequests int, window time.Duration) (bool, int, error) {
	now := time.Now().UnixMilli()
	windowMs := window.Milliseconds()
	clearBefore := now - windowMs

	pipe := rl.redisClient.TxPipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(clearBefore, 10))
	cardCmd := pipe.ZCard(ctx, key)
	oldestCmd := pipe.ZRangeWithScores(ctx, key, 0, 0)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, err
	}

	current := int(cardCmd.Val())
	if current < maxRequests {
		pipe2 := rl.redisClient.TxPipeline()
		pipe2.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
		pipe2.Expire(ctx, key, window+time.Second)
		_, _ = pipe2.Exec(ctx)
		return true, 0, nil
	}

	retryAfter := int(window.Seconds())
	if len(oldestCmd.Val()) > 0 {
		oldestTime := int64(oldestCmd.Val()[0].Score)
		diff := (oldestTime + windowMs - now) / 1000
		if diff > 0 {
			retryAfter = int(diff)
		} else {
			retryAfter = 1
		}
	}
	return false, retryAfter, nil
}

func (rl *RateLimiter) allowMemory(key string, maxRequests int, window time.Duration) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	timestamps := rl.memoryStore[key]
	var valid []time.Time
	for _, t := range timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) < maxRequests {
		valid = append(valid, now)
		rl.memoryStore[key] = valid
		return true, 0
	}

	rl.memoryStore[key] = valid
	retryAfter := int(valid[0].Add(window).Sub(now).Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	return false, retryAfter
}
