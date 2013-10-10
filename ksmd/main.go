// A Key Storage Module for Yubikeys
// https://github.com/Yubico/yubikey-ksm/wiki/DecryptionProtocol
package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/conformal/yubikey"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"os"
)

var KeysDB *sql.DB

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	otp := r.FormValue("otp")

	if otp == "" {
		log.Println("ERR No OTP provided")
		http.Error(w, "ERR No OTP provided", http.StatusOK)
		return
	}

	if len(otp) < 32 || len(otp) > 48 || !yubikey.ModHexP([]byte(otp)) {
		log.Println("ERR Invalid OTP format:", otp)
		http.Error(w, "ERR Invalid OTP format", http.StatusOK)
		return
	}

	idlen := len(otp) - 32

	yid, yctxt := otp[:idlen], otp[idlen:]

	yotp := yubikey.NewOtp(yctxt)

	stmt, err := KeysDB.Prepare("SELECT aeskey, internalname FROM yubikeys WHERE publicname = ? AND active = 1")
	if err != nil {
		log.Println("ERR Database error:", err)
		http.Error(w, "ERR Database error", http.StatusOK)
		return
	}
	defer stmt.Close()
	var aeskeyHex string
	var name string
	err = stmt.QueryRow(yid).Scan(&aeskeyHex, &name)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("ERR Unknown yubikey:", yid)
			http.Error(w, "ERR Unknown yubikey", http.StatusOK)
		} else {
			log.Println("ERR Database error:", err)
			http.Error(w, "ERR Database error", http.StatusOK)
		}
		return
	}

	var aesKey yubikey.Key

	hex.Decode(aesKey[:], []byte(aeskeyHex)) // error ignored, we trust the database

	token, err := yotp.Parse(aesKey)
	if err != nil {
		log.Println("ERR Corrupt OTP:", otp)
		http.Error(w, "ERR Corrupt OTP", http.StatusOK)
		return
	}

	nameBytes, _ /* err */ := hex.DecodeString(name) // error ignored, we trust the database

	if !bytes.Equal(nameBytes, token.Uid[:]) {
		log.Println("ERR Corrupt OTP:", otp)
		http.Error(w, "ERR Corrupt OTP", http.StatusOK)
		return
	}

	response := fmt.Sprintf("OK counter=%04x low=%04x high=%02x use=%02x", token.Ctr, token.Tstpl, token.Tstph, token.Use)

	log.Println(response)
	fmt.Fprintf(w, response)
}

func main() {

	dbfile := flag.String("db", "", "file name for ksm data")
	flag.Parse()

	if *dbfile == "" {
		log.Fatalf("No database provided (-db)")
	}

	var err error
	KeysDB, err = sql.Open("sqlite3", *dbfile)
	if err != nil {
		log.Fatalf("can't open sqlite3://%s: %s\n", *dbfile, err)
	}

	http.HandleFunc("/wsapi/decrypt", decryptHandler)

	port := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		port = ":" + p
	}
	log.Println("listening on port", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
