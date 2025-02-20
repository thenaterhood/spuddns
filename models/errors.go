package models

type UnauthorizedError struct{}

func (m UnauthorizedError) Error() string {
	return "request was unauthorized"
}
