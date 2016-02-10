package internal

import (
	"github.com/stretchr/testify/mock"
)

type MockCrypter struct {
	mock.Mock
}

// Name provides a mock function with given fields:
func (_m *MockCrypter) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Encrypt provides a mock function with given fields: _a0, _a1
func (_m *MockCrypter) Encrypt(_a0 string, _a1 EncryptParams) (Ciphertext, DecryptParams, error) {
	ret := _m.Called(_a0, _a1)

	var r0 Ciphertext
	if rf, ok := ret.Get(0).(func(string, EncryptParams) Ciphertext); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(Ciphertext)
	}

	var r1 DecryptParams
	if rf, ok := ret.Get(1).(func(string, EncryptParams) DecryptParams); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Get(1).(DecryptParams)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(string, EncryptParams) error); ok {
		r2 = rf(_a0, _a1)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// Decrypt provides a mock function with given fields: _a0, _a1
func (_m *MockCrypter) Decrypt(_a0 Ciphertext, _a1 DecryptParams) (string, error) {
	ret := _m.Called(_a0, _a1)

	var r0 string
	if rf, ok := ret.Get(0).(func(Ciphertext, DecryptParams) string); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(Ciphertext, DecryptParams) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
