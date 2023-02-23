package authgpt

type AuthRod struct {
	loginPage string
}

func NewAuthRod() *AuthRod {
	return &AuthRod{
		loginPage: "https://chat.openai.com/auth/login",
	}
}

func (a *AuthRod) Open() {
}
