package main

import "testing"

func TestUsernamePattern(t *testing.T) {
	valid := []string{"web001", "client_01", "abc"}
	for _, value := range valid {
		if !usernamePattern.MatchString(value) {
			t.Errorf("expected %q to be accepted", value)
		}
	}
	invalid := []string{"ab", "1client", "Client01", "client-name", "client.name", "client;id", "sixteen_char_name"}
	for _, value := range invalid {
		if usernamePattern.MatchString(value) {
			t.Errorf("expected %q to be rejected", value)
		}
	}
}
