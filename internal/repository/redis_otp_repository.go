package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisOTPRepository struct {
	client *redis.Client
}

func NewRedisOTPRepository(client *redis.Client) *RedisOTPRepository {
	return &RedisOTPRepository{client: client}
}

func (r *RedisOTPRepository) SetEmailVerificationOTP(ctx context.Context, normalizedEmail, otp string, ttl time.Duration) error {
	return r.client.Set(ctx, emailVerifyOTPKey(normalizedEmail), otp, ttl).Err()
}

func (r *RedisOTPRepository) GetEmailVerificationOTP(ctx context.Context, normalizedEmail string) (string, bool, error) {
	value, err := r.client.Get(ctx, emailVerifyOTPKey(normalizedEmail)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (r *RedisOTPRepository) DeleteEmailVerificationOTP(ctx context.Context, normalizedEmail string) error {
	return r.client.Del(ctx, emailVerifyOTPKey(normalizedEmail)).Err()
}

func (r *RedisOTPRepository) SetForgotPasswordOTP(ctx context.Context, normalizedEmail, otp string, ttl time.Duration) error {
	return r.client.Set(ctx, forgotPasswordOTPKey(normalizedEmail), otp, ttl).Err()
}

func (r *RedisOTPRepository) GetForgotPasswordOTP(ctx context.Context, normalizedEmail string) (string, bool, error) {
	value, err := r.client.Get(ctx, forgotPasswordOTPKey(normalizedEmail)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (r *RedisOTPRepository) DeleteForgotPasswordOTP(ctx context.Context, normalizedEmail string) error {
	return r.client.Del(ctx, forgotPasswordOTPKey(normalizedEmail)).Err()
}

func (r *RedisOTPRepository) SetPasswordResetTempToken(ctx context.Context, tokenHash, normalizedEmail string, ttl time.Duration) error {
	return r.client.Set(ctx, passwordResetTempTokenKey(tokenHash), normalizedEmail, ttl).Err()
}

func (r *RedisOTPRepository) GetPasswordResetTempTokenEmail(ctx context.Context, tokenHash string) (string, bool, error) {
	value, err := r.client.Get(ctx, passwordResetTempTokenKey(tokenHash)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (r *RedisOTPRepository) DeletePasswordResetTempToken(ctx context.Context, tokenHash string) error {
	return r.client.Del(ctx, passwordResetTempTokenKey(tokenHash)).Err()
}

func emailVerifyOTPKey(normalizedEmail string) string {
	return fmt.Sprintf("auth:verify-email:otp:%s", normalizedEmail)
}

func forgotPasswordOTPKey(normalizedEmail string) string {
	return fmt.Sprintf("auth:forgot-password:otp:%s", normalizedEmail)
}

func passwordResetTempTokenKey(tokenHash string) string {
	return fmt.Sprintf("auth:forgot-password:temp-token:%s", tokenHash)
}
