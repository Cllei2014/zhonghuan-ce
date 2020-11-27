package common

import (
	"database/sql"
	"log"
	"os"
	"path"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

const dbFileName = "keys.db"

var dbFilePath string

const logHeader = "Mock ce db: "

var keyDb *sql.DB

func init() {
	dbFilePath = getDbPath()
	if _, err := os.Stat(dbFilePath); err == nil {
		keyDb, _ = sql.Open("sqlite3", dbFilePath)
		return
	}

	file, err := os.Create(dbFilePath)
	if err != nil {
		log.Fatalf("unable create path %s %s", dbFileName, err)
	}
	file.Close()
	log.Println(logHeader, "Create db file:", dbFilePath)
	keyDb, _ = sql.Open("sqlite3", dbFilePath)
	_ = createSm2Table()
	_ = createSm4Table()
}

func getDbPath() string {
	return path.Join("/tmp", dbFileName)
}

func createSm2Table() error {
	createSm2TableSQL := `CREATE TABLE sm2 (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"key" TEXT
	);`

	log.Println(logHeader, "Create sm2 table...")
	statement, err := keyDb.Prepare(createSm2TableSQL)
	if err != nil {
		return err
	}
	_, _ = statement.Exec()
	log.Println(logHeader, "sm2 table created")
	return nil
}

func AddSm2Key(key string) (id int64, err error) {
	insertSm2SQL := `INSERT INTO sm2(key) VALUES (?)`
	statement, err := keyDb.Prepare(insertSm2SQL)
	if err != nil {
		return 0, err
	}
	res, err := statement.Exec(key)
	if err != nil {
		return 0, err
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

func GetSm2Key(id int64) (key string, err error) {
	row := keyDb.QueryRow("SELECT * FROM sm2 WHERE id = ?", id)
	switch err := row.Scan(&id, &key); err {
	case nil:
		return key, nil
	default:
		return "", err
	}
}

func createSm4Table() error {
	createSm2TableSQL := `CREATE TABLE sm4 (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"key" TEXT
	);`

	log.Println(logHeader, "Create sm4 table...")
	statement, err := keyDb.Prepare(createSm2TableSQL)
	if err != nil {
		return err
	}
	_, _ = statement.Exec()
	return nil
}

func AddSm4Key(key string) (id int64, err error) {
	insertSm2SQL := `INSERT INTO sm4(key) VALUES (?)`
	statement, err := keyDb.Prepare(insertSm2SQL)
	if err != nil {
		return 0, err
	}
	res, err := statement.Exec(key)
	if err != nil {
		return 0, err
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

func GetSm4Key(id int64) (key string, err error) {
	row := keyDb.QueryRow("SELECT * FROM sm4 WHERE id = ?", id)
	switch err := row.Scan(&id, &key); err {
	case nil:
		return key, nil
	default:
		return "", err
	}
}

func KeyIdFrom(keyDbId int64) string {
	return strconv.FormatInt(keyDbId, 10)
}

func KeyDbIdFrom(keyId string) int64 {
	keyDbId, _ := strconv.ParseInt(keyId, 10, 64)
	return keyDbId
}
