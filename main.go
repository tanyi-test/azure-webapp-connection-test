package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

func get(c *gin.Context) {
	c.HTML(200, "index.html", nil)
}

func post(c *gin.Context) {
	tp := strings.TrimSpace(c.PostForm("type"))
	conn := strings.TrimSpace(c.PostForm("connection"))

	if tp == "keyvault" {
		keyvaultConnect(conn, c)
	} else {
		dbConnect(tp, conn, c)
	}

}

func keyvaultConnect(name string, c *gin.Context) {
	authorizer, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		c.String(500, "Auth Error: %s", err.Error())
		return
	}

	client := keyvault.New()
	client.Authorizer = authorizer

	secrets, err := client.GetSecrets(context.Background(), fmt.Sprintf("https://%s.vault.azure.net", name), nil)
	if err != nil {
		c.String(500, "List Secrets Error: %s", err.Error())
		return
	}

	for _, secret := range secrets.Values() {
		c.String(200, "First Secret ID: %s", *secret.ID)
		return
	}

	c.String(202, "Not Secret Found")
}

func dbConnect(tp, conn string, c *gin.Context) {
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
