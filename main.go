package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/azure-storage-blob-go/azblob"
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

	if tp == "nslookup" {
		nslookup(conn, c)
	} else if tp == "keyvault" {
		keyvaultConnect(conn, c)
	} else if tp == "cosmos" {
		cosmosDBConnect(conn, c)
	} else if tp == "storage" {
		storageConnect(conn, c)
	} else if tp == "insights" {
		insightsConnect(conn, c)
	} else {
		dbConnect(tp, conn, c)
	}

}

func request(req *http.Request, c *gin.Context) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.String(500, "Request Error: %s", err.Error())
		return
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.String(500, "Read Body Error: %s", err.Error())
		return
	}
	c.String(resp.StatusCode, "Body: %s", string(b))
}

func nslookup(name string, c *gin.Context) {
	ips, err := net.LookupIP(name)
	if err != nil {
		c.String(500, "Lookup Error: %s", err.Error())
		return
	}

	allIP := ""
	for _, ip := range ips {
		allIP += ip.String() + " "
	}
	c.String(200, "LookupIP: %s -> %s", name, allIP)
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
		c.String(200, "KeyVault %s: First Secret ID: %s", name, *secret.ID)
		return
	}

	c.String(204, "KeyVault %s: Secret Not Found", name)
}

func cosmosDBConnect(conn string, c *gin.Context) {
	endpoint := ""
	key := ""
	for _, s := range strings.Split(conn, ";") {
		endpoint = trimPrefix(s, "AccountEndpoint=")
		key = trimPrefix(s, "AccountKey=")
	}
	if endpoint == "" {
		c.String(400, "Unknown AccountEndpoint")
		return
	}
	if key == "" {
		c.String(400, "Unknown AccountKey")
		return
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		c.String(500, "Parse Endpoint Error: %s", err.Error())
		return
	}

	verb := "GET"
	resourceType := "dbs"
	resourceId := ""
	u.Path = "/dbs"
	date := time.Now().UTC().Format(http.TimeFormat)

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		c.String(500, "Master Key Decode Error: %s", err.Error())
		return
	}

	sha256Hash := hmac.New(sha256.New, keyBytes)
	body := fmt.Sprintf("%s\n%s\n%s\n%s\n\n", strings.ToLower(verb), strings.ToLower(resourceType), resourceId, strings.ToLower(date))

	n, err := sha256Hash.Write([]byte(body))
	if n < len(body) || err != nil {
		c.String(500, "Write Hash %d, body size %d, Error: %s", n, len(body), err.Error())
		return
	}

	auth := fmt.Sprintf("type=master&ver=1.0&sig=%s", base64.StdEncoding.EncodeToString(sha256Hash.Sum(nil)))
	auth = url.QueryEscape(auth)

	req, _ := http.NewRequest(verb, u.String(), nil)
	req.Header.Add("Authorization", auth)
	req.Header.Add("x-ms-date", date)
	req.Header.Add("x-ms-version", "2018-12-31")

	request(req, c)
}

func trimPrefix(s, prefix string) string {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return ""
}

func storageConnect(conn string, c *gin.Context) {
	name := ""
	key := ""
	for _, s := range strings.Split(conn, ";") {
		name = trimPrefix(s, "AccountName=")
		key = trimPrefix(s, "AccountKey=")
	}
	if name == "" {
		c.String(400, "Unknown AccountName")
		return
	}
	if key == "" {
		c.String(400, "Unknown AccountKey")
		return
	}

	credential, err := azblob.NewSharedKeyCredential(name, key)
	if err != nil {
		c.String(500, "Invalid Credential: %s", err.Error())
		return
	}

	u, err := url.Parse(fmt.Sprintf("https://%s.blob.core.windows.net/", name))
	if err != nil {
		c.String(500, "URL Parse Error: %s", err.Error())
		return
	}
	blob := azblob.NewBlobURL(*u, azblob.NewPipeline(credential, azblob.PipelineOptions{}))
	info, err := blob.GetAccountInfo(context.Background())
	if err != nil {
		c.String(500, "Get Account %s Info Error: %s", err.Error())
		return
	}
	c.String(200, "Account %s Info: %s", name, info.SkuName())
}

func insightsConnect(conn string, c *gin.Context) {
	conns := strings.Split(conn, ";")
	if len(conn) < 2 {
		c.String(400, "Unexpected Connection String Format, should be \"<app-id>;<app-key>\"")
		return
	}
	appId := conns[0]
	appKey := strings.Join(conns[1:], ";")

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://api.applicationinsights.io/v1/apps/%s/metrics/requests/duration", appId), nil)
	req.Header.Add("X-Api-Key", appKey)

	request(req, c)
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
