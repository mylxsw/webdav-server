package auth

type Auth interface {
	Login(username, password string) (*AuthedUser, error)
	GetUser(username string) (*AuthedUser, error)
	Users() ([]AuthedUser, error)
	CanRegister() bool
	Register(username, password string) (*AuthedUser, error)
}

type AuthedUser struct {
	UUID    string
	Name    string
	Account string
	Status  int8
}
