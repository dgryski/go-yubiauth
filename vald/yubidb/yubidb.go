// Package yubidb provides an abstraction layer to the database for the validation server

package yubidb

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"time"
)

type Client struct {
	ID      int
	Active  bool
	Created int
	Secret  string
	Email   string
	Notes   string
	OTP     string
}

func (c *Client) Load(ydb *sql.DB, id int) error {
	stmt, err := ydb.Prepare("SELECT id, active, created, secret, email,  notes, otp FROM clients WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	err = stmt.QueryRow(id).Scan(&c.ID, &c.Active, &c.Created, &c.Secret, &c.Email, &c.Notes, &c.OTP)
	return err
}

type Yubikey struct {
	Active     bool
	Created    int64
	Modified   int64
	PublicName string
	Counter    int
	Use        int
	Low        int
	High       int
	Nonce      string
	Notes      string
}

func (y *Yubikey) Load(ydb *sql.DB, publicName string) error {
	stmt, err := ydb.Prepare("SELECT active, created, modified, yk_publicname, yk_counter, yk_use, yk_low, yk_high, nonce, notes FROM yubikeys WHERE yk_publicname = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	err = stmt.QueryRow(publicName).Scan(&y.Active, &y.Created, &y.Modified, &y.PublicName, &y.Counter, &y.Use, &y.Low, &y.High, &y.Nonce, &y.Notes)
	return err
}

func (y *Yubikey) Insert(ydb *sql.DB) error {
	stmt, err := ydb.Prepare("INSERT INTO yubikeys(active, created, modified, yk_publicname, yk_counter, yk_use, yk_low, yk_high, nonce, notes) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	epoch := time.Now().Unix()
	y.Created = epoch
	y.Modified = epoch
	_, err = stmt.Exec(y.Active, y.Created, y.Modified, y.PublicName, y.Counter, y.Use, y.Low, y.High, y.Nonce, y.Notes)
	return err
}

func (y *Yubikey) UpdateCounters(ydb *sql.DB) error {
	stmt, err := ydb.Prepare("UPDATE yubikeys SET yk_counter=?, yk_use=?, yk_low=?, yk_high=?, nonce=? where yk_publicname=?")
	if err != nil {
		return err
	}
	_, err = stmt.Exec(y.Counter, y.Use, y.Low, y.High, y.Nonce, y.PublicName)
	return err
}
