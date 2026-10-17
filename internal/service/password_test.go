package service_test

import (
	"testing"

	"GoAuth/internal/service"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHashingAndVerification(t *testing.T) {
	password := "SecureP@ssw0rd123!"

	hash, err := service.HashPassword(password, bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("expected no error hashing password, got %v", err)
	}

	if !service.CheckPasswordHash(password, hash) {
		t.Fatalf("expected password verification to succeed for correct password")
	}

	if service.CheckPasswordHash("WrongPassword", hash) {
		t.Fatalf("expected password verification to fail for wrong password")
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("failed to get bcrypt cost: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("expected bcrypt cost %d, got %d", bcrypt.DefaultCost, cost)
	}
}
