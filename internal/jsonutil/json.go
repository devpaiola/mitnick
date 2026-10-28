package jsonutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// RejectDuplicateKeys rejects ambiguous JSON objects and trailing JSON values.
func RejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkValue(decoder); err != nil {
		return errors.New("JSON inválido ou com chaves duplicadas")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON deve conter somente um valor")
	}
	return nil
}

func walkValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("chave JSON inválida")
			}
			if _, exists := keys[key]; exists {
				return errors.New("chave JSON duplicada")
			}
			keys[key] = struct{}{}
			if err := walkValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("objeto JSON inválido")
		}
	case '[':
		for decoder.More() {
			if err := walkValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array JSON inválido")
		}
	default:
		return errors.New("delimitador JSON inválido")
	}
	return nil
}
