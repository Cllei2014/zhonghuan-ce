package zhonghuan

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateUserId(t *testing.T) {
	userLabel, userPin := GenerateUser()
	assert.Equal(t, 32, len(userLabel), "Length of userLabel invalid")
	assert.Equal(t, 32, len(userPin), "Length of userPin invalid")
}
