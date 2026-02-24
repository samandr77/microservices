package entity

type SberIDUser struct {
	Sub         string `json:"sub"`
	SubAlt      string `json:"sub_alt"`
	Email       string `json:"email"`
	FamilyName  string `json:"family_name"`
	GivenName   string `json:"given_name"`
	MiddleName  string `json:"middle_name,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Birthdate   string `json:"birthdate,omitempty"`
}
