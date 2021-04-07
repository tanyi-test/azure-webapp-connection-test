package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

func get(c *gin.Context) {
	c.HTML(200, "index.html", nil)
}

func post(c *gin.Context) {
	tp := c.PostForm("type")
	conn := c.PostForm("connection")

	db, err := sql.Open(tp, conn)
	if err != nil {
		c.String(500, "Connect Error: %s", err.Error())
		return
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		c.String(500, "Ping Error: %s", err.Error())
		return
	}
	c.String(200, "Connect to %s with %s Success!", tp, conn)
}

func main() {
	route := gin.Default()
	route.LoadHTMLFiles("index.html")

	route.GET("/", get)
	route.POST("/", post)

	if err := route.Run(":80"); err != nil {
		panic(err)
	}
}

func init() {
	caCerts, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	mysql.RegisterTLSConfig("custom", &tls.Config{
		RootCAs: caCerts,
	})
}
