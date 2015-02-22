// A Key Storage Module for Yubikeys
// https://github.com/Yubico/yubikey-ksm/wiki/DecryptionProtocol
package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"expvar"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/conformal/yubikey"
	"github.com/golang/glog"
	_ "github.com/mattn/go-sqlite3"
)

var Metrics = struct {
	Requests *expvar.Int
	Errors   *expvar.Int
}{
	Requests: expvar.NewInt("requests"),
	Errors:   expvar.NewInt("errors"),
}

var KeysDB *sql.DB

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	Metrics.Requests.Add(1)

	otp := r.FormValue("otp")

	if otp == "" {
		Metrics.Errors.Add(1)
		glog.Info("ERR No OTP provided")
		http.Error(w, "ERR No OTP provided", http.StatusOK)
		return
	}

	if len(otp) < 32 || len(otp) > 48 || !yubikey.ModHexP([]byte(otp)) {
		Metrics.Errors.Add(1)
		glog.Info("ERR Invalid OTP format: ", otp)
		http.Error(w, "ERR Invalid OTP format", http.StatusOK)
		return
	}

	pubid, yotp, err := yubikey.ParseOTPString(otp)

	stmt, err := KeysDB.Prepare("SELECT aeskey, internalname FROM yubikeys WHERE publicname = ? AND active = 1")
	if err != nil {
		Metrics.Errors.Add(1)
		glog.Error("ERR DB error during Prepare(): ", err)
		http.Error(w, "ERR Database error", http.StatusOK)
		return
	}
	defer stmt.Close()
	var aeskeyHex string
	var name string
	err = stmt.QueryRow(string(pubid)).Scan(&aeskeyHex, &name)
	if err != nil {
		Metrics.Errors.Add(1)
		if err == sql.ErrNoRows {
			glog.Info("ERR Unknown yubikey: ", string(pubid))
			http.Error(w, "ERR Unknown yubikey", http.StatusOK)
		} else {
			glog.Error("ERR DB error during SELECT: ", err)
			http.Error(w, "ERR Database error", http.StatusOK)
		}
		return
	}

	var aesKey yubikey.Key

	hex.Decode(aesKey[:], []byte(aeskeyHex)) // error ignored, we trust the database

	token, err := yotp.Parse(aesKey)
	if err != nil {
		Metrics.Errors.Add(1)
		glog.Info("ERR Corrupt OTP (Parse failed): ", otp)
		http.Error(w, "ERR Corrupt OTP", http.StatusOK)
		return
	}

	nameBytes, _ /* err */ := hex.DecodeString(name) // error ignored, we trust the database

	if !bytes.Equal(nameBytes, token.Uid[:]) {
		Metrics.Errors.Add(1)
		glog.Warning("ERR Corrupt OTP (UID mismatch): ", otp)
		http.Error(w, "ERR Corrupt OTP", http.StatusOK)
		return
	}

	response := fmt.Sprintf("OK counter=%04x low=%04x high=%02x use=%02x", token.Ctr, token.Tstpl, token.Tstph, token.Use)

	glog.Info(response)
	fmt.Fprintf(w, response)
}

func main() {

	dbfile := flag.String("db", "", "file name for ksm data")
	flag.Parse()

	if *dbfile == "" {
		glog.Fatal("No database provided (-db)")
	}

	var err error
	KeysDB, err = sql.Open("sqlite3", *dbfile)
	if err != nil {
		glog.Fatalf("can't open sqlite3://%s: %s\n", *dbfile, err)
	}

	http.HandleFunc("/wsapi/decrypt", decryptHandler)

	port := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		port = ":" + p
	}
	glog.Info("listening on port ", port)
	glog.Fatal(http.ListenAndServe(port, nil))
}
