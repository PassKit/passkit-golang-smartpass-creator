package passkit_golang_smartpass_creator

import (
	"testing"
)

func TestGenerateEncryptedSmartPassLink(t *testing.T) {
	fields := map[string]string{
		"field1": "value1",
	}

	distributionUrl := "https://pub1.pskt.io/c/abcdef"
	key := "6147d7def9ed94367a1e09c548c0745faa99aa71e940463d2d82cc0591253781"

	_, err := GenerateEncryptedSmartPassLink(fields, "", key)
	if err == nil {
		t.Errorf("method requires a distribution url")
	}

	_, err = GenerateEncryptedSmartPassLink(fields, "https://google.com", key)

	if err == nil {
		t.Errorf("method requires a valid distribution url")
	}

	if err.Error() != "invalid distribution URL" {
		t.Errorf("Expected %s, Got %s", "invalid distribution URL", err.Error())
	}


	_, err = GenerateEncryptedSmartPassLink(fields, distributionUrl, "")

	if err.Error() != "key cannot be empty" {
		t.Errorf("Expected %s, Got %s", "key cannot be empty", err.Error())
	}

	_, err = GenerateEncryptedSmartPassLink(fields, distributionUrl, key)

	if err != nil {
		t.Errorf("Expected no err, Got: %s", err.Error())
	}
}