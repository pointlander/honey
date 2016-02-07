package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
)

func handler(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(time.Second))
	buffer, request, line := make([]byte, 1024), bytes.Buffer{}, bytes.Buffer{}
	contentLength, bodyLength, inBody := 0, 0, false
	request.WriteString(conn.RemoteAddr().String())
	request.WriteString("\r\n")
	n, err := conn.Read(buffer)
process:
	for err == nil {
		for _, b := range buffer[:n] {
			if inBody {
				request.WriteByte(b)
				bodyLength++
				if bodyLength >= contentLength {
					break process
				}
			} else {
				line.WriteByte(b)
				request.WriteByte(b)
				if b == '\n' {
					header := line.String()
					length := len(header)
					if header == "\r\n" {
						if contentLength == 0 {
							break process
						}
						inBody = true
					} else if length > 2 {
						parts := strings.Split(header[:length-2], ":")
						if len(parts) == 2 && strings.TrimSpace(parts[0]) == "Content-Length" {
							contentLength, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
						}
					}
					line.Reset()
				}
			}
		}
		n, err = conn.Read(buffer)
	}

	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	conn.Close()

	fmt.Print(request.String())
	tx, err := db.Begin(true)
	if err != nil {
		log.Println(err)
	}
	defer tx.Rollback()

	traffic, err := tx.CreateBucketIfNotExists([]byte("traffic"))
	if err != nil {
		log.Println(err)
	}

	key := bytes.Buffer{}
	stamp := time.Now()
	key.Write(itob(uint64(stamp.Unix())))
	key.Write(itob(uint64(stamp.Nanosecond())))

	err = traffic.Put(key.Bytes(), request.Bytes())
	if err != nil {
		log.Println(err)
	}

	err = tx.Commit()
	if err != nil {
		log.Println(err)
	}
}

func httpListener() {
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handler(conn)
	}
}

//http://golang.org/src/pkg/crypto/tls/generate_cert.go
func generateCertificate(hosts []string) (cert, key []byte) {
	private, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	before := time.Now()
	after := before.Add(10 * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             before,
		NotAfter:              after,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &private.PublicKey, private)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut := bytes.Buffer{}
	pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut := bytes.Buffer{}
	pem.Encode(&keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})

	return certOut.Bytes(), keyOut.Bytes()
}

//https://gist.github.com/denji/12b3a568f092ab951456
func httpsListener() {
	cert, key := generateCertificate([]string{"pointlander.info", "pointlander.net"})

	cer, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatal(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	listener, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handler(conn)
	}
}

var db *bolt.DB

func itob(i uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	return b
}

func btoi(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

func main() {
	var err error
	db, err = bolt.Open("traffic.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}

	go httpListener()
	httpsListener()
}
