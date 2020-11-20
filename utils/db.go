package utils

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"path"
	"runtime"
)

const dbFileName = "keys.db"

var dbFilePath string

const logHeader = "Mock ce sm2: "

var keyDb *sql.DB

func init() {
	dbFilePath = getDbPath()
	if _, err := os.Stat(dbFilePath); err == nil {
		keyDb, _ = sql.Open("sqlite3", dbFilePath)
		return
	}

	file, _ := os.Create(dbFilePath)
	file.Close()
	log.Println(logHeader, "Create db file:", dbFilePath)
	keyDb, _ = sql.Open("sqlite3", dbFilePath)
	_ = createSm2Table()
}

func getDbPath() string {
	_, currentFilename, _, _ := runtime.Caller(0)
	return path.Join(path.Dir(currentFilename), "..", dbFileName)
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
	statement.Exec()
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
	log.Println(logHeader, "Add new key at id:", id)
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
