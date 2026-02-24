package entity

import (
	"context"
	"errors"
)

type (
	CtxKeyLogger struct{}
	CtxKeyIP     struct{}
	CtxKeyUser   struct{}
	CtxKeyToken  struct{}
)

func UserFromContext(ctx context.Context) (User, error) {
	id, ok := ctx.Value(CtxKeyUser{}).(User)
	if !ok {
		return User{}, errors.New("data type casting")
	}

	return id, nil
}

func SetUserToContext(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, CtxKeyUser{}, user)
}

func SetTokenToContext(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, CtxKeyToken{}, token)
}

func TokenFromContext(ctx context.Context) (string, error) {
	token, ok := ctx.Value(CtxKeyToken{}).(string)
	if !ok {
		return "", errors.New("data type casting")
	}

	return token, nil
}
