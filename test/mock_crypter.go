package test

import (
	"github.com/Zemanta/go-secretcrypt/internal"
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
func (_m *MockCrypter) Encrypt(_a0 string, _a1 internal.EncryptParams) (internal.Ciphertext, internal.DecryptParams, error) {
	ret := _m.Called(_a0, _a1)

	var r0 internal.Ciphertext
	if rf, ok := ret.Get(0).(func(string, internal.EncryptParams) internal.Ciphertext); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(internal.Ciphertext)
	}

	var r1 internal.DecryptParams
	if rf, ok := ret.Get(1).(func(string, internal.EncryptParams) internal.DecryptParams); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Get(1).(internal.DecryptParams)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(string, internal.EncryptParams) error); ok {
		r2 = rf(_a0, _a1)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// Decrypt provides a mock function with given fields: _a0, _a1
func (_m *MockCrypter) Decrypt(_a0 internal.Ciphertext, _a1 internal.DecryptParams) (string, error) {
	ret := _m.Called(_a0, _a1)

	var r0 string
	if rf, ok := ret.Get(0).(func(internal.Ciphertext, internal.DecryptParams) string); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(internal.Ciphertext, internal.DecryptParams) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
