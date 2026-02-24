package service

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/samandr77/microservices/client/internal/entity"
)

const (
	EmailMaxLen           = 255
	NameMinLen            = 2
	NameMaxLen            = 255
	MinPassportAge        = 14
	MaxPersonalInfoLength = 1000
	SberIDMaxLen          = 96
)

var (
	emailRegexp    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	phoneRegexp    = regexp.MustCompile(`^7\d{10}$`)
	cyrillicRegexp = regexp.MustCompile(`^[а-яёА-ЯЁ]+([\s-][а-яёА-ЯЁ]+)*$`)
)

var fieldDisplayNames = map[string]string{
	"first_name":  "имя",
	"last_name":   "фамилия",
	"middle_name": "отчество",
}

func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email не может быть пустым", entity.ErrMissingRequiredField)
	}

	if len(email) > EmailMaxLen {
		return fmt.Errorf("%w: email превышает максимальную длину %d символов", entity.ErrInvalidEmail, EmailMaxLen)
	}

	if !emailRegexp.MatchString(email) {
		return fmt.Errorf("%w: некорректный формат email", entity.ErrInvalidEmail)
	}

	return nil
}

func ValidatePhone(phone *string) error {
	if phone == nil || *phone == "" {
		return nil
	}

	if !phoneRegexp.MatchString(*phone) {
		return fmt.Errorf("%w: телефон должен быть в формате 7XXXXXXXXXX (11 цифр, начиная с 7)", entity.ErrInvalidPhone)
	}

	return nil
}

func ValidateBirthdate(birthdate *time.Time) error {
	if birthdate == nil {
		return nil
	}

	if birthdate.After(time.Now()) {
		return fmt.Errorf("%w: дата рождения не может быть в будущем", entity.ErrInvalidBirthdate)
	}

	minDate := time.Now().AddDate(-150, 0, 0)
	if birthdate.Before(minDate) {
		return fmt.Errorf("%w: дата рождения не может быть более 150 лет назад", entity.ErrInvalidBirthdate)
	}

	return nil
}

func ValidateRequiredString(value *string, fieldName string) error {
	if value == nil || *value == "" {
		return fmt.Errorf("%w: поле '%s' обязательно для заполнения", entity.ErrMissingRequiredField, fieldName)
	}

	return nil
}

func ValidateName(value *string, fieldKey string, required bool) error {
	fieldName := fieldDisplayNames[fieldKey]
	if fieldName == "" {
		fieldName = fieldKey
	}

	if value == nil || strings.TrimSpace(*value) == "" {
		if required {
			return fmt.Errorf("%w: %s обязательно для заполнения", entity.ErrMissingRequiredField, fieldName)
		}

		return nil
	}

	name := strings.TrimSpace(*value)
	nameLen := utf8.RuneCountInString(name)

	if nameLen < NameMinLen || nameLen > NameMaxLen {
		return fmt.Errorf("%w: %s должно содержать от %d до %d символов", entity.ErrInvalidName, fieldName, NameMinLen, NameMaxLen)
	}

	if !cyrillicRegexp.MatchString(name) {
		return fmt.Errorf("%w: %s должно содержать только буквы кириллицы (может содержать пробелы и дефисы)", entity.ErrInvalidName, fieldName)
	}

	return nil
}

func ValidateCity(city *string) error {
	if city == nil || strings.TrimSpace(*city) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*city)
	cityLen := utf8.RuneCountInString(trimmed)

	if cityLen < 2 || cityLen > 100 {
		return fmt.Errorf("%w: город должен содержать от 2 до 100 символов", entity.ErrInvalidCity)
	}

	cityRegexp := regexp.MustCompile(`^[а-яёА-ЯЁa-zA-Z]+([\s-][а-яёА-ЯЁa-zA-Z]+)*$`)
	if !cityRegexp.MatchString(trimmed) {
		return fmt.Errorf("%w: город должен содержать только буквы, пробелы и дефисы", entity.ErrInvalidCity)
	}

	return nil
}

func ValidateSchoolName(schoolName *string) error {
	if schoolName == nil || strings.TrimSpace(*schoolName) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*schoolName)
	schoolLen := utf8.RuneCountInString(trimmed)

	if schoolLen < 3 || schoolLen > 255 {
		return fmt.Errorf("%w: название школы должно содержать от 3 до 255 символов", entity.ErrInvalidSchoolName)
	}

	schoolRegexp := regexp.MustCompile(`^[а-яёА-ЯЁa-zA-Z0-9\s\-«»"'№.]+$`)
	if !schoolRegexp.MatchString(trimmed) {
		return fmt.Errorf("%w: название школы содержит недопустимые символы", entity.ErrInvalidSchoolName)
	}

	return nil
}

func ValidatePlaceOfEducation(placeOfEducation *string) error {
	if placeOfEducation == nil || strings.TrimSpace(*placeOfEducation) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*placeOfEducation)
	placeLen := utf8.RuneCountInString(trimmed)

	if placeLen < 3 || placeLen > 255 {
		return fmt.Errorf("%w: название образовательного учреждения должно содержать от 3 до 255 символов", entity.ErrInvalidPlaceOfEducation)
	}

	eduRegexp := regexp.MustCompile(`^[а-яёА-ЯЁa-zA-Z0-9\s\-«»"'.№]+$`)
	if !eduRegexp.MatchString(trimmed) {
		return fmt.Errorf("%w: название образовательного учреждения содержит недопустимые символы", entity.ErrInvalidPlaceOfEducation)
	}

	return nil
}

func ValidateAddress(address *string) error {
	if address == nil || strings.TrimSpace(*address) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*address)
	addressLen := utf8.RuneCountInString(trimmed)

	if addressLen < 10 || addressLen > 500 {
		return fmt.Errorf("%w: адрес должен содержать от 10 до 500 символов", entity.ErrInvalidAddress)
	}

	addressRegexp := regexp.MustCompile(`^[а-яёА-ЯЁa-zA-Z0-9\s,.\-№/]+$`)
	if !addressRegexp.MatchString(trimmed) {
		return fmt.Errorf("%w: адрес содержит недопустимые символы", entity.ErrInvalidAddress)
	}

	return nil
}

func ValidatePassportSeries(series *string) error {
	if series == nil || strings.TrimSpace(*series) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*series)

	seriesRegexp := regexp.MustCompile(`^\d{4}$`)
	if !seriesRegexp.MatchString(trimmed) {
		return fmt.Errorf("%w: серия паспорта должна содержать ровно 4 цифры", entity.ErrInvalidPassportSeries)
	}

	return nil
}

func ValidatePassportNumber(number *string) error {
	if number == nil || strings.TrimSpace(*number) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*number)

	numberRegexp := regexp.MustCompile(`^\d{6}$`)
	if !numberRegexp.MatchString(trimmed) {
		return fmt.Errorf("%w: номер паспорта должен содержать ровно 6 цифр", entity.ErrInvalidPassportNumber)
	}

	return nil
}

func ValidatePassportCode(code *string) error {
	if code == nil || strings.TrimSpace(*code) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*code)

	codeRegexp := regexp.MustCompile(`^\d{3}-\d{3}$`)
	if !codeRegexp.MatchString(trimmed) {
		return fmt.Errorf("%w: код подразделения должен иметь формат XXX-XXX (например, 770-001)", entity.ErrInvalidPassportCode)
	}

	return nil
}

func ValidateIssuedBy(issuedBy *string) error {
	if issuedBy == nil || strings.TrimSpace(*issuedBy) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*issuedBy)
	issuedByLen := utf8.RuneCountInString(trimmed)

	if issuedByLen < 10 || issuedByLen > 500 {
		return fmt.Errorf("%w: поле 'кем выдан' должно содержать от 10 до 500 символов", entity.ErrInvalidTextField)
	}

	issuedByRegexp := regexp.MustCompile(`^[а-яёА-ЯЁa-zA-Z0-9\s.\-№]+$`)
	if !issuedByRegexp.MatchString(trimmed) {
		return fmt.Errorf("%w: поле 'кем выдан' содержит недопустимые символы", entity.ErrInvalidTextField)
	}

	return nil
}

func ValidateIssuedDate(issuedDate *time.Time, birthdate *time.Time) error {
	if issuedDate == nil {
		return nil
	}

	if issuedDate.After(time.Now()) {
		return fmt.Errorf("%w: дата выдачи паспорта не может быть в будущем", entity.ErrInvalidIssuedDate)
	}

	minDate := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	if issuedDate.Before(minDate) {
		return fmt.Errorf("%w: дата выдачи паспорта не может быть раньше 1900 года", entity.ErrInvalidIssuedDate)
	}

	if birthdate != nil {
		minIssuedDate := birthdate.AddDate(MinPassportAge, 0, 0)
		if issuedDate.Before(minIssuedDate) {
			return fmt.Errorf("%w: паспорт не может быть выдан раньше чем через 14 лет после рождения", entity.ErrInvalidIssuedDate)
		}
	}

	return nil
}

func ValidatePersonalInfo(personalInfo *string) error {
	if personalInfo == nil || strings.TrimSpace(*personalInfo) == "" {
		return nil
	}

	trimmed := strings.TrimSpace(*personalInfo)
	infoLen := utf8.RuneCountInString(trimmed)

	if infoLen > MaxPersonalInfoLength {
		return fmt.Errorf("%w: личная информация не может превышать 1000 символов", entity.ErrInvalidTextField)
	}

	return nil
}

func ValidateSberIDs(sub, subAlt *string) error {
	if sub != nil {
		trimmed := strings.TrimSpace(*sub)
		if trimmed == "" {
			return errors.New("sub не может быть пустым")
		}

		if len(trimmed) > SberIDMaxLen {
			return fmt.Errorf("sub превышает максимально допустимую длину %d символов", SberIDMaxLen)
		}

		*sub = trimmed
	}

	if subAlt != nil {
		trimmed := strings.TrimSpace(*subAlt)
		if trimmed == "" {
			return errors.New("sub_alt не может быть пустым")
		}

		if len(trimmed) > SberIDMaxLen {
			return fmt.Errorf("sub_alt превышает максимально допустимую длину %d символов", SberIDMaxLen)
		}

		*subAlt = trimmed
	}

	return nil
}

//nolint:gocognit
func ValidateProfileFields(data *ProfileUpdateData) error {
	if data.LastName != nil {
		if err := ValidateName(data.LastName, "last_name", false); err != nil {
			return err
		}
	}

	if data.FirstName != nil {
		if err := ValidateName(data.FirstName, "first_name", false); err != nil {
			return err
		}
	}

	if data.MiddleName != nil && *data.MiddleName != "" {
		if err := ValidateName(data.MiddleName, "middle_name", false); err != nil {
			return err
		}
	}

	if data.Phone != nil {
		if err := ValidatePhone(data.Phone); err != nil {
			return err
		}
	}

	if data.City != nil {
		if err := ValidateCity(data.City); err != nil {
			return err
		}
	}

	if data.SchoolName != nil {
		if err := ValidateSchoolName(data.SchoolName); err != nil {
			return err
		}
	}

	if data.PlaceOfEducation != nil {
		if err := ValidatePlaceOfEducation(data.PlaceOfEducation); err != nil {
			return err
		}
	}

	if data.AddressReg != nil {
		if err := ValidateAddress(data.AddressReg); err != nil {
			return err
		}
	}

	if data.Series != nil {
		if err := ValidatePassportSeries(data.Series); err != nil {
			return err
		}
	}

	if data.Number != nil {
		if err := ValidatePassportNumber(data.Number); err != nil {
			return err
		}
	}

	if data.Code != nil {
		if err := ValidatePassportCode(data.Code); err != nil {
			return err
		}
	}

	if data.IssuedBy != nil {
		if err := ValidateIssuedBy(data.IssuedBy); err != nil {
			return err
		}
	}

	if data.PersonalInfo != nil {
		if err := ValidatePersonalInfo(data.PersonalInfo); err != nil {
			return err
		}
	}

	return nil
}
