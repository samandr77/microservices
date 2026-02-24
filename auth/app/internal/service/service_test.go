package service_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/samandr77/microservices/auth/internal/service"
	"github.com/samandr77/microservices/auth/pkg/config"
)

func TestValidateEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		email string
		errFn require.ErrorAssertionFunc
	}{
		{"Valid email with special characters", "user@example.com", require.NoError},
		{"Valid email with Cyrillic domain", "test@пример.рф", require.NoError},
		{"Invalid: no domain zone", "abc@mail", require.Error},
		{"Invalid: double @ symbol", "user@@example.com", require.Error},
		{"Invalid: domain starts with dot", "user@.com", require.Error},
		{"Invalid: no domain zone after @", "user@domain", require.Error},
		{"Invalid: two consecutive dots", "user@example.com", require.Error},
		{"Invalid: subdomain with two consecutive dots", "user@example.com", require.Error},
		{"Invalid: exceeds length limit", strings.Repeat("x", service.EmailMaxLen), require.Error},
		{"Invalid: empty email", "", require.Error},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := service.ValidateEmail(test.email)
			test.errFn(t, err)
		})
	}
}

func TestValidateName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		errFn require.ErrorAssertionFunc
	}{
		{"Valid name", "Иван", require.NoError},
		{"Valid name with hyphen", "Анна-Мария", require.NoError},
		{"Valid name with space", "Мария Александра", require.NoError},
		{"Invalid: too short", "А", require.Error},
		{"Invalid: contains digits", "Иван123", require.Error},
		{"Invalid: contains Latin", "Ivan", require.Error},
		{"Invalid: special characters", "Иван@", require.Error},
		{"Invalid: too long", strings.Repeat("А", service.NameMaxLen+1), require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := service.ValidateName(tt.input)
			tt.errFn(t, err)
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
		errFn    require.ErrorAssertionFunc
	}{
		{"Valid email without changes", "user@example.com", "user@example.com", require.NoError},
		{"Email with spaces at start/end", "  user@example.com  ", "user@example.com", require.NoError},
		{"Email with uppercase", "user@example.com", "user@example.com", require.NoError},
		{"Email with parentheses", "(user@example.com)", "user@example.com", require.NoError},
		{"Email with brackets", "[user@example.com]", "user@example.com", require.NoError},
		{"Email with angle brackets", "<user@example.com>", "user@example.com", require.NoError},
		{"Email with multiple spaces", "user  @  example  .  com", "user@example.com", require.NoError},
		{"Email with mixed formatting", "  (user@example.com)  ", "user@example.com", require.NoError},
		{"Email with Cyrillic domain", "test@пример.рф", "test@пример.рф", require.NoError},
		{"Email with Cyrillic domain and spaces", "  test@пример.рф  ", "test@пример.рф", require.NoError},
		{"Invalid email after normalization", "invalid-email", "", require.Error},
		{"Empty email", "", "", require.Error},
		{"Email with only spaces", "   ", "", require.Error},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := service.NormalizeEmail(test.input)
			test.errFn(t, err)

			if err == nil {
				require.Equal(t, test.expected, result)
			}
		})
	}
}

func TestGenerateCode_FormatAndRange(t *testing.T) {
	t.Parallel()

	cfg := config.Config{OTP: config.OTPConfig{CodeTTL: 5 * time.Minute}}
	svc := service.NewService(cfg, nil, nil, nil, nil, nil, nil)

	code := svc.GenerateCode()
	require.Len(t, code, 6)
	require.Regexp(t, regexp.MustCompile(`^\d{6}$`), code)
}

func TestGenerateCode_ProducesLeadingZeros(t *testing.T) {
	t.Parallel()

	cfg := config.Config{OTP: config.OTPConfig{CodeTTL: 5 * time.Minute}}
	svc := service.NewService(cfg, nil, nil, nil, nil, nil, nil)

	hasLeadingZero := false

	for range 200 {
		code := svc.GenerateCode()

		if len(code) > 0 && code[0] == '0' {
			hasLeadingZero = true
			break
		}
	}

	require.True(t, hasLeadingZero, "Expected at least one code with leading zero in 200 attempts")
}

func TestGenerateCode_UniquenessRate(t *testing.T) {
	t.Parallel()

	cfg := config.Config{OTP: config.OTPConfig{CodeTTL: 5 * time.Minute}}
	svc := service.NewService(cfg, nil, nil, nil, nil, nil, nil)

	seen := make(map[string]struct{})
	total := 1000

	for range total {
		code := svc.GenerateCode()

		seen[code] = struct{}{}
	}

	unique := len(seen)
	require.Greater(t, float64(unique)/float64(total)*100.0, 95.0)
}

func TestHashCode_BasicProperties(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	svc := service.NewService(cfg, nil, nil, nil, nil, nil, nil)

	hash, err := svc.HashCode("123456")
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	h2, err := svc.HashCode("123456")
	require.NoError(t, err)
	require.NotEqual(t, hash, h2)
}
