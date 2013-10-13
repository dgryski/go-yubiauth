// A Validation Server for Yubikeys
// https://github.com/Yubico/yubikey-val/wiki/ValidationServerAlgorithm
// https://github.com/Yubico/yubikey-val/wiki/ValidationProtocolV20
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/conformal/yubikey"
	"github.com/dgryski/go-yubiauth/ksmclient"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
)

type Status int

const (
	UNKNOWN_STATUS        Status = iota
	OK                           // The OTP is valid.
	BAD_OTP                      // The OTP is invalid format.
	REPLAYED_OTP                 // The OTP has already been seen by the service.
	BAD_SIGNATURE                // The HMAC signature verification failed.
	MISSING_PARAMETER            // The request lacks a parameter.
	NO_SUCH_CLIENT               // The request id does not exist.
	OPERATION_NOT_ALLOWED        // The request id is not allowed to verify OTPs.
	BACKEND_ERROR                // Unexpected error in our server. Please contact us if you see this error.
	NOT_ENOUGH_ANSWERS           // Server could not get requested number of syncs during before timeout
	REPLAYED_REQUEST             // Server has seen the OTP/Nonce combination before
)

var statusStrings = []string{
	"UNKNOWN_STATUS",
	"OK",
	"BAD_OTP",
	"REPLAYED_OTP",
	"BAD_SIGNATURE",
	"MISSING_PARAMETER",
	"NO_SUCH_CLIENT",
	"OPERATION_NOT_ALLOWED",
	"BACKEND_ERROR",
	"NOT_ENOUGH_ANSWERS",
	"REPLAYED_REQUEST",
}

func (s Status) String() string {
	i := int(s)
	if i < 0 || len(statusStrings) <= i {
		s = 0
	}
	return statusStrings[i]
}

func statusFromString(status string) Status {
	for i, s := range statusStrings {
		if status == s {
			return Status(i)
		}

	}
	return UNKNOWN_STATUS
}

// VerifyRequest is the request from the user, parsed into bits
type VerifyRequest struct {
	ID        string
	OTP       string
	H         string
	Timestamp bool
	Nonce     string
	SL        string
	Timeout   int
}

// VerifyResponse is the response we send back
type VerifyResponse struct {
	OTP            string
	Nonce          string
	H              []byte
	T              time.Time // timestamp in that obnoxious format
	Status         Status
	Timestamp      uint
	SessionCounter uint
	SessionUse     uint
	SL             int
}

// A row(ish) from the database
type OTPRequest struct {
	Counter int
	Use     int
	Low     int
	High    int
	Nonce   string
}

const ksmEndpoint = "http://localhost:8081/wsapi/decrypt"

var YubiDB *sql.DB

func signMap(m map[string]string, key []byte) []byte {

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := hmac.New(sha1.New, key)
	var ampersand []byte
	for _, k := range keys {
		if k == "h" {
			continue
		}
		h.Write(ampersand)
		h.Write([]byte(k))
		h.Write([]byte{'='})
		h.Write([]byte(m[k]))
		ampersand = []byte{'&'}
	}

	return h.Sum(nil)
}

func isValidRequestSignature(form url.Values, key []byte) bool {

	clientSig, err := base64.StdEncoding.DecodeString(form.Get("h"))

	if len(clientSig) != sha1.Size || err != nil {
		return false
	}

	m := make(map[string]string)

	for k, v := range form {
		m[k] = v[0]
	}

	serverSig := signMap(m, key)

	return hmac.Equal(clientSig, serverSig)
}

var requiredRequestParams = []string{"id", "otp", "nonce"}

var optionalRequestParams = map[string]bool{
	"h":         false,
	"timestamp": false,
	"sl":        false,
	"timeout":   false,
}

func (v *VerifyResponse) toMap(key []byte) map[string]string {

	m := make(map[string]string)

	m = map[string]string{
		"otp":    v.OTP,
		"nonce":  v.Nonce,
		"status": v.Status.String(),
	}

	now := time.Now()
	ts := now.Format("2006-01-02T15:04:05Z0")
	milli := now.Format(".000")
	m["t"] = ts + milli[1:]

	if v.Timestamp != 0 || v.SessionUse != 0 || v.SessionCounter != 0 {
		m["timestamp"] = strconv.FormatUint(uint64(v.Timestamp), 10)
		m["sessionuse"] = strconv.FormatUint(uint64(v.SessionUse), 10)
		m["sessioncounter"] = strconv.FormatUint(uint64(v.SessionCounter), 10)
	}

	sig := signMap(m, key)
	m["h"] = base64.StdEncoding.EncodeToString(sig)

	return m
}

func writeResponse(w http.ResponseWriter, resp *VerifyResponse, key []byte, err error) {
	u := resp.toMap(key)

	for k, v := range u {
		fmt.Fprintf(w, "%s=%s\n", k, v)
	}

	if err != nil {
		log.Println("err=", err)
	}
}

var nonceRegex = regexp.MustCompile("^[A-Za-z0-9]{16,40}$")

func verifyHandler(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	// FIXME: check for required params
	clientIDstr := r.FormValue("id")
	otp := r.FormValue("otp")
	nonce := r.FormValue("nonce")

	if clientIDstr == "" || otp == "" || nonce == "" {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: MISSING_PARAMETER}, nil, nil)
		return
	}

	if len(otp) < 32 || len(otp) > 48 || !yubikey.ModHexP([]byte(otp)) {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BAD_OTP}, nil, fmt.Errorf("bad otp: %s", otp))
		return
	}

	var clientID uint64
	var err error
	if clientID, err = strconv.ParseUint(clientIDstr, 10, 64); err != nil {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: MISSING_PARAMETER}, nil, err)
		return
	}

	if !nonceRegex.MatchString(nonce) {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: MISSING_PARAMETER}, nil, fmt.Errorf("bad nonce: %s", nonce))
		return
	}

	// FIXME: check they didn't pass any unknown parameters
	// FIXME: parse request into VerifyRequest?

	// Val X parses validation request, retrieves the client key for the client id from local database and checks the request signature.
	stmt, err := YubiDB.Prepare("SELECT secret FROM clients WHERE id = ? AND active = 1")
	if err != nil {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, nil, err)
		return
	}
	defer stmt.Close()
	var clientSecret string
	err = stmt.QueryRow(clientID).Scan(&clientSecret)
	if err != nil {
		if err == sql.ErrNoRows {
			writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: NO_SUCH_CLIENT}, nil, nil)
		} else {
			writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, nil, err)
		}
		return
	}

	form := r.Form

	keyBytes, _ := base64.StdEncoding.DecodeString(clientSecret)

	// if they provided a hash, it has to verify
	if len(r.FormValue("h")) > 0 && !isValidRequestSignature(form, keyBytes) {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BAD_SIGNATURE}, keyBytes, nil)
		return
	}

	// Val X decrypts the OTP using a KSM and reads out the modified/counters from the internal database -- if the YubiKey identity doesn't exist in the database, add it with counter/use/high/low=-1.
	ksmClient := ksmclient.NewClient(ksmEndpoint)

	ksmResponse, err := ksmClient.Decrypt(otp)
	if err != nil {
		// FIXME: need to check here for "Unknown Yubikey" ->
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, keyBytes, err)
		return
	}

	publicNameLen := len(otp) - 32
	publicName := otp[:publicNameLen]

	stmt, err = YubiDB.Prepare("SELECT yk_counter, yk_use, yk_low, yk_high, nonce FROM yubikeys WHERE yk_publicname = ? AND active = 1")
	if err != nil {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, keyBytes, fmt.Errorf("PREPARE SELECT failed: %s", err))
		return
	}
	defer stmt.Close()
	var lastOTP OTPRequest
	err = stmt.QueryRow(publicName).Scan(&lastOTP.Counter, &lastOTP.Use, &lastOTP.Low, &lastOTP.High, &lastOTP.Nonce)
	var newClient bool
	if err != nil {
		if err != sql.ErrNoRows {
			writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, keyBytes, err)
			return
		}
		newClient = true
	}

	// we need to add client with counter/use/low/high=-1
	if newClient {
		stmt, err := YubiDB.Prepare("INSERT INTO yubikeys(active, created, modified, yk_publicname, yk_counter, yk_use, yk_low, yk_high) VALUES(1, ?, ?, ?, -1, -1, -1, -1)")
		if err != nil {
			writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, keyBytes, fmt.Errorf("PREPARE INSERT failed: %s", err))
			return
		}
		epoch := time.Now().Unix()
		_, err = stmt.Exec(epoch, epoch, publicName)
		if err != nil {
			writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, keyBytes, fmt.Errorf("INSERT failed: %s", err))
			return
		}
	}

	// Val X checks the OTP/Nonce against local database, and replies with REPLAYED_REQUEST if local information is identical.
	if int(ksmResponse.TstampHigh) == lastOTP.High && int(ksmResponse.TstampLow) == lastOTP.Low &&
		int(ksmResponse.Counter) == lastOTP.Counter && int(ksmResponse.Use) == lastOTP.Use && nonce == lastOTP.Nonce {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: REPLAYED_REQUEST}, keyBytes, nil)
		return
	}

	// Val X checks the OTP counters against local counters, and rejects OTP as replayed if local counters are higher than or equal to OTP counters.
	if int(ksmResponse.TstampHigh) < lastOTP.High ||
		int(ksmResponse.TstampHigh) == lastOTP.High && int(ksmResponse.TstampLow) <= lastOTP.Low ||
		int(ksmResponse.Counter) < lastOTP.Counter ||
		int(ksmResponse.Counter) == lastOTP.Counter && int(ksmResponse.Use) <= lastOTP.Use {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: REPLAYED_OTP}, keyBytes, nil)
		return
	}

	// Val X updates the internal database with counters/nonce from request.
	stmt, err = YubiDB.Prepare("UPDATE yubikeys SET yk_counter=?, yk_use=?, yk_low=?, yk_high=?, nonce=? where yk_publicname=?")
	if err != nil {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, keyBytes, fmt.Errorf("PREPARE UPDATE failed: %s", err))
		return
	}
	_, err = stmt.Exec(ksmResponse.Counter, ksmResponse.Use, ksmResponse.TstampLow, ksmResponse.TstampHigh, nonce, publicName)
	if err != nil {
		writeResponse(w, &VerifyResponse{OTP: otp, Nonce: nonce, Status: BACKEND_ERROR}, keyBytes, fmt.Errorf("UPDATE failed: %s", err))
		return
	}

	/* FIXME: sync() protocol not handled not handled
	 * Val X queues a sync request in a sync queue for each validation server in the validation server pool (manually configured).
	 * Val X requests the queued requests (otp, modified, nonce, yk_identity, yk_counter, yk_use, yk_high, yk_low) to be sent out, by sending parallel sync requests to all other validation servers.
	 * Each validation server receiving a sync request updates its own internal database with received information to use the highest counter.
	 * Each remote server responds with a sync response (modified, nonce, yk_identity, yk_counter, yk_use, yk_high, yk_low) using data from its internal database.
	 * Val X waits for a sync response (up until timeout, or when sufficient number of sync responses indicating valid OTP and no sync response indicating invalid OTP) from the other validation servers to which it sent a sync request. For each response that arrives the corresponding entry in the sync queue is removed and the following is checked
	 * If the sync response counters have higher values than val X internal database, the internal database is updated with new information, AND
	 * If the sync response counter have higher values as val X internal database the response is considered to mark the OTP as invalid, AND
	 * If the sync response have equal counter values and nonce as val X internal database the response is considered to mark the OTP as valid, AND
	 * If the sync response have equal counter values and different nonce as val X internal database the response is considered to mark the OTP as invalid, AND
	 * If the sync response counter have smaller values than val X had in its internal database before the validation attempt the server logs a warning, and the response is considered to mark the OTP as valid.
	 */

	//   Val X construct validation response. Validation is successful if the Verification Algorithm below is successful.
	response := &VerifyResponse{
		OTP:    otp,
		Nonce:  nonce,
		Status: OK,
	}

	if form.Get("timestamp") == "1" {
		response.SessionCounter = uint(ksmResponse.Counter)
		response.SessionUse = uint(ksmResponse.Use)
		response.Timestamp = uint(ksmResponse.TstampHigh)<<16 + uint(ksmResponse.TstampLow)
	}

	writeResponse(w, response, keyBytes, nil)

	/*
	 * Val X marks the remaining entries in the sync queue as marked with timestamp=NULL.
	 */
}

func main() {

	dbfile := flag.String("db", "", "file name for verify data")
	flag.Parse()

	if *dbfile == "" {
		log.Fatalf("No database provided (-db)")
	}

	var err error
	YubiDB, err = sql.Open("sqlite3", *dbfile)
	if err != nil {
		log.Fatalf("can't open sqlite3://%s: %s\n", *dbfile, err)
	}

	http.HandleFunc("/wsapi/2.0/verify", verifyHandler)

	port := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		port = ":" + p
	}
	log.Println("listening on port", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
