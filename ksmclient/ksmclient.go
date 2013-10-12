package ksmclient

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

type KSMResponse struct {
	Message    string
	Counter    uint16
	TstampLow  uint16
	TstampHigh uint8
	Use        uint8
}

type KSMClient struct {
	endpoint string
}

func NewClient(endpoint string) *KSMClient {
	return &KSMClient{endpoint: endpoint}
}

var ErrBadKSMResponse = errors.New("bad response from KSM")

func (k *KSMClient) Decrypt(otp string) (*KSMResponse, error) {

	u := url.Values{
		"otp": {otp},
	}

	resp, err := http.PostForm(k.endpoint, u)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, ErrBadKSMResponse
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(body) < 3 {
		return nil, ErrBadKSMResponse
	}

	if bytes.HasPrefix(body, []byte("ERR")) {
		// check we're not overflowing our slice
		return nil, errors.New(string(body[4:]))
	}

	if bytes.HasPrefix(body, []byte("OK ")) {
		// success!
		ksmr := new(KSMResponse)

		count, err := fmt.Sscanf(string(body), "OK counter=%04x low=%04x high=%02x use=%02x", &ksmr.Counter, &ksmr.TstampLow, &ksmr.TstampHigh, &ksmr.Use)

		if count != 4 || err != nil {
			err = ErrBadKSMResponse
		}

		return ksmr, nil
	}

	// not OK or ERR :(
	return nil, ErrBadKSMResponse
}
