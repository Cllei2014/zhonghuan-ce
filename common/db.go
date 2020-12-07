package common

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"os"
	"path"
	"runtime"
	"strconv"
)

const dbFileName = "keys.db"

var dbFilePath string

var zhLog = log.WithFields(log.Fields{"lib": "tjfoc sm4 in ZhongHuan-CE"})

var keyDb *sql.DB

func init() {
	dbFilePath = getDbPath()
	if _, err := os.Stat(dbFilePath); err == nil {
		keyDb, _ = sql.Open("sqlite3", dbFilePath)
		return
	}

	file, _ := os.Create(dbFilePath)
	file.Close()
	zhLog.Debug("Create db file:", dbFilePath)
	keyDb, _ = sql.Open("sqlite3", dbFilePath)
	_ = createSm2Table()
	_ = createSm4Table()
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

	zhLog.Debug("Create sm2 table...")
	statement, err := keyDb.Prepare(createSm2TableSQL)
	if err != nil {
		return err
	}
	_, _ = statement.Exec()
	zhLog.Debug("sm2 table created")
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

	zhLog.Debug("Create sm4 table...")
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
