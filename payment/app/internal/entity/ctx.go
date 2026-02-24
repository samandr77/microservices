package entity

import (
	"context"
)

type CtxKey int

const (
	CtxKeyUser CtxKey = iota
	CtxKetJWT
)

func CtxWithUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, CtxKeyUser, user)
}

// UserFromCtx returns user from context or ErrUnauthenticated if user is not found.
func UserFromCtx(ctx context.Context) (User, error) {
	user, ok := ctx.Value(CtxKeyUser).(User)
	if !ok {
		return user, ErrUnauthenticated
	}

	return user, nil
}

func CtxWithJWT(ctx context.Context, jwt string) context.Context {
	return context.WithValue(ctx, CtxKetJWT, jwt)
}

// JWTFromCtx returns JWT from context or empty string if JWT is not found.
func JWTFromCtx(ctx context.Context) string {
	jwt, ok := ctx.Value(CtxKetJWT).(string)
	if !ok {
		return ""
	}

	return jwt
}
