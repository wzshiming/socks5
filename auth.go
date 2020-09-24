package socks5

// AuthenticationFunc Authentication interface is implemented
type AuthenticationFunc func(username, password string) bool

// Auth authentication processing
func (f AuthenticationFunc) Auth(username, password string) bool {
	return f(username, password)
}

// Authentication proxy authentication
type Authentication interface {
	Auth(username, password string) bool
}

// UserAuth basic authentication
func UserAuth(username, password string) Authentication {
	return AuthenticationFunc(func(u, p string) bool {
		return username == u && password == p
	})
}
