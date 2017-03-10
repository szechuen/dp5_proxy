package main

import (
    "bufio"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "flag"
    "fmt"
    "golang.org/x/net/proxy"
    "log"
    "math/big"
    "net"
    "regexp"
    "strings"
    "time"
)

var no_color bool
var verbose bool

var conf_dir string

var proxy_port string
var tor_server string
var tor_port string

var reg_server string
var lookup_server1 string
var lookup_server2 string

var epoch_len int
var dataenc_bytes int

var c_clear string
var c_client string
var c_server string
var c_arrow string
var c_plt string
var c_tls string
var c_contacts string
var c_online string
var c_offline string
var c_alias string

var tor_dialer proxy.Dialer

var user_server string

func main() {
    flag.BoolVar(&no_color, "nc", false, "Disable colored logging")
    flag.BoolVar(&verbose, "v", false, "Enable Verbose logging")

    flag.StringVar(&conf_dir, "c", "dp5_conf", "Configuration directory")

    flag.StringVar(&proxy_port, "p", "8080", "Proxy port")
    flag.StringVar(&tor_server, "ts", "localhost", "Tor server")
    flag.StringVar(&tor_port, "tp", "9050", "Tor port")

    flag.StringVar(&reg_server, "r", "dp5.szechuen.com:8443", "Registration Server")
    flag.StringVar(&lookup_server1, "l1", "dp5-lu1.szechuen.com:8443", "Lookup Server 1")
    flag.StringVar(&lookup_server2, "l2", "dp5-lu2.szechuen.com:8443", "Lookup Server 2")

    flag.IntVar(&epoch_len, "e", 30, "Epoch length")
    flag.IntVar(&dataenc_bytes, "d", 48, "Ciphertext length")

    flag.Parse()

    if !no_color {
        c_clear = "\033[0m"
        c_client = "\033[1m\033[94m"
        c_server = "\033[1m\033[95m"
        c_arrow = "\033[1m"
        c_plt = "\033[91m"
        c_tls = "\033[92m"
        c_contacts = "\033[1m"
        c_online = "\033[1m\033[92m"
        c_offline = "\033[1m\033[91m"
        c_alias = "\033[92m"
    } else {
        c_clear = ""
        c_client = ""
        c_server = ""
        c_arrow = ""
        c_plt = ""
        c_tls = ""
        c_contacts = ""
        c_online = ""
        c_offline = ""
        c_alias = ""
    }

    td, err := proxy.SOCKS5("tcp", tor_server + ":" + tor_port, nil, proxy.Direct)
    if err != nil { log.Fatal(err) }

    tor_dialer = td

    user_server = ""

    dp5_init()
    go dp5_loop()

    l, err := net.Listen("tcp", ":" + proxy_port)
    if err != nil { log.Fatal(err) }

    log.Println("Proxy listening on TCP *:" + proxy_port + " (HTTP)...")

    for {
        conn, err := l.Accept()
        if err != nil {
            log.Println(err)
            continue
        }

        if verbose { log.Println("Accepted TCP connection") }

        handle_conn(conn)
    }

    l.Close()
    dp5_cleanup()
}

func handle_conn(client net.Conn) {
    client_r := bufio.NewReader(client)

    proxy_req, err := client_r.ReadString('\n')
    if err != nil {
        log.Println(err)

        client.Close()
        return
    }

    var host string
    var http_ver string

    n, err := fmt.Sscanf(proxy_req, "CONNECT %s HTTP/%s\r\n", &host, &http_ver)
    if err != nil {
        log.Println(err)

        client.Close()
        return
    } else if n != 2 {
        log.Println("Incorrect proxy protocol")

        client.Close()
        return
    }

    if verbose { log.Printf("Received CONNECT request for %s", host) }

    server, err := tor_dialer.Dial("tcp", host)
    if err != nil {
        fmt.Fprintf(client, "HTTP/%s 502 Bad Gateway\r\n\r\n", http_ver)
        client.Close()

        log.Printf("Failed to dial for %s, rejecting CONNECT request...", host)
        log.Println(err)
        return
    }

    fmt.Fprintf(client, "HTTP/%s 200 OK\r\n\r\n", http_ver)
    client_r.Reset(client)

    if verbose { log.Printf("Successfully dialed for %s, accepting CONNECT request...", host) }

    server_r := bufio.NewReader(server)

    client_en := true
    client_tls_en := false

    server_en := true
    server_tls_en := false

    var client_tls, server_tls *tls.Conn
    var client_tls_r, server_tls_r *bufio.Reader

    spoof_client := strings.NewReplacer()
    spoof_server := strings.NewReplacer()

    var pass_server string
    var userpass_server_b64 string
    var reg_id string

    reg_success := false

    go func() {
        var req string

        for {
            if client_en {
                req, err = client_r.ReadString('>')
                if err != nil {
                    log.Println(err)

                    user_server = ""
                    client.Close()
                    server.Close()

                    return
                }

                if len(req) == 0 { continue }
            } else {
                for !client_tls_en {}

                req, err = client_tls_r.ReadString('>')
                if err != nil {
                    log.Println(err)

                    user_server = ""
                    client_tls.Close()
                    server_tls.Close()

                    return
                }

                if len(req) == 0 { continue }
            }

            if server_en {
                if verbose { log.Printf("%sClient%s %s-->%s %sServer%s %s[PLT]%s  %s", c_client, c_clear, c_arrow, c_clear, c_server, c_clear, c_plt, c_clear, req) }
                fmt.Fprintf(server, req)

                if req == "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" || req == "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>" {
                  for !client_tls_en {}
                }
            } else {
                for !server_tls_en {}

                auth, _ := regexp.MatchString("<auth.*", req)

                if auth {
                    b := make([]byte, 32)
                    rand.Read(b)
                    user_server = (base64.RawURLEncoding.EncodeToString(b))[:32]

                    b = make([]byte, 32)
                    rand.Read(b)
                    pass_server = base64.RawURLEncoding.EncodeToString(b)[:32]

                    userpass_server_b64 = base64.StdEncoding.EncodeToString([]byte("\x00" + user_server + "\x00" + pass_server))

                    b = make([]byte, 16)
                    rand.Read(b)
                    reg_id = base64.RawURLEncoding.EncodeToString(b)[:16]

                    reg_req := fmt.Sprintf("<iq type='set' id='%s'><query xmlns='jabber:iq:register'><x xmlns='jabber:x:data' type='submit'><field var='username'><value>%s</value></field><field var='password'><value>%s</value></field></x></query></iq>", reg_id, user_server, pass_server)

                    if verbose { log.Printf("%sClient%s %sxxx%s %sServer%s %s[TLS]%s  %s", c_client, c_clear, c_arrow, c_clear, c_server, c_clear, c_tls, c_clear, reg_req) }
                    fmt.Fprintf(server_tls, reg_req)

                    for !reg_success {}
                    if verbose { log.Println("Successfully registered userpass") }
                }

                re := regexp.MustCompile("(.*?)</auth>")
                userpass_client_b64 := re.FindStringSubmatch(req)

                if userpass_client_b64 != nil {
                    userpass_client, _ := base64.StdEncoding.DecodeString(userpass_client_b64[1])
                    user_client := strings.Split(string(userpass_client), string('\x00'))[1]


                    spoof_client = strings.NewReplacer(userpass_client_b64[1], userpass_server_b64, user_client, user_server, strings.ToLower(user_client), strings.ToLower(user_server))
                    spoof_server = strings.NewReplacer(user_server, user_client, strings.ToLower(user_server), strings.ToLower(user_client))

                    if verbose { log.Printf("Updated spoof replacers") }
                }

                req_replace := spoof_client.Replace(req)

                for _, v := range dp5_spoof_client {
                  req_replace = v.Replace(req_replace)
                }

                if req != req_replace {
                    if verbose { log.Printf("%sClient%s %sxxx%s %sServer%s %s[TLS]%s  %s", c_client, c_clear, c_arrow, c_clear, c_server, c_clear, c_tls, c_clear, req_replace) }
                } else {
                    if verbose { log.Printf("%sClient%s %s-->%s %sServer%s %s[TLS]%s  %s", c_client, c_clear, c_arrow, c_clear, c_server, c_clear, c_tls, c_clear, req) }
                }

                fmt.Fprintf(server_tls, req_replace)
            }
        }
    }()

    go func() {
        var res string

        for {
            if server_en {
                res, err = server_r.ReadString('>')
                if err != nil {
                    log.Println(err)

                    user_server = ""
                    server.Close()
                    client.Close()

                    return
                }

                if len(res) == 0 { continue }
            } else {
                for !server_tls_en {}

                res, err = server_tls_r.ReadString('>')
                if err != nil {
                    log.Println(err)

                    user_server = ""
                    server_tls.Close()
                    client_tls.Close()

                    return
                }

                if len(res) == 0 { continue }
            }

            if client_en {
                if verbose { log.Printf("%sServer%s %s-->%s %sClient%s %s[PLT]%s  %s", c_server, c_clear, c_arrow, c_clear, c_client, c_clear, c_plt, c_clear, res) }
                fmt.Fprintf(client, res)

                if res == "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" || res == "<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>" {
                    client_en = false
                    server_en = false

                    if verbose { log.Println("Starting TLS with server...") }

                    server_tls = tls.Client(server, &tls.Config{
                        ServerName: strings.Split(host, ":")[0],
                    })

                    server_tls_r = bufio.NewReader(server_tls)

                    if(verbose) { log.Print("Started TLS with server") }

                    if(verbose) { log.Print("Starting TLS with client...") }

                    client_tls = tls.Server(client, &tls.Config{
                        GetCertificate: SelfCertificate,
                    })

                    client_tls_r = bufio.NewReader(client_tls)

                    if(verbose) { log.Print("Started TLS with client") }

                    client_tls_en = true
                    server_tls_en = true
                }
            } else {
                for !client_tls_en {}

                mech_start, _ := regexp.MatchString("<mechanism>", res)
                mech_end, _ := regexp.MatchString(".*</mechanism>", res)

                if mech_start || mech_end {
                    if res == "PLAIN</mechanism>" {
                        if verbose { log.Printf("%sServer%s %sxxx%s %sClient%s %s[TLS]%s  %s", c_server, c_clear, c_arrow, c_clear, c_client, c_clear, c_tls, c_clear, "<mechanism>PLAIN</mechanism>") }
                        fmt.Fprintf(client_tls, "<mechanism>PLAIN</mechanism>")

                        continue
                    } else {
                        if verbose { log.Printf("%sServer%s %sxxx%s %sClient%s %s[TLS]%s  %s %s", c_server, c_clear, c_arrow, c_clear, c_client, c_clear, c_tls, c_clear, "[DROPPED]", res) }

                        continue
                    }
                }

                auth, _ := regexp.MatchString("<iq id='" + reg_id + "'.*", res)

                if auth {
                    if verbose { log.Printf("%sServer%s %sxxx%s %sClient%s %s[TLS]%s  %s %s", c_server, c_clear, c_arrow, c_clear, c_client, c_clear, c_tls, c_clear, "[DROPPED]", res) }
                    reg_success = true

                    continue
                }

                res_replace := spoof_server.Replace(res)

                for _, v := range dp5_spoof_server {
                    res_replace = v.Replace(res_replace)
                }

                if res != res_replace {
                    if verbose { log.Printf("%sServer%s %sxxx%s %sClient%s %s[TLS]%s  %s", c_server, c_clear, c_arrow, c_clear, c_client, c_clear, c_tls, c_clear, res_replace) }
                } else {
                    if verbose { log.Printf("%sServer%s %s-->%s %sClient%s %s[TLS]%s  %s", c_server, c_clear, c_arrow, c_clear, c_client, c_clear, c_tls, c_clear, res) }
                }

                fmt.Fprintf(client_tls, res_replace)
            }
        }
    }()
}

// Adapted from src/crypto/tls/generate_cert.go
func SelfCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    priv, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }

    notBefore := time.Now()
    notAfter := notBefore.Add(365*24*time.Hour)

    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil {
        return nil, err
    }

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"DP5 Proxy"},
        },
        NotBefore: notBefore,
        NotAfter:  notAfter,

        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    h := clientHello.ServerName
    if ip := net.ParseIP(h); ip != nil {
        template.IPAddresses = append(template.IPAddresses, ip)
    } else {
        template.DNSNames = append(template.DNSNames, h)
    }

    // template.IsCA = true
    // template.KeyUsage |= x509.KeyUsageCertSign

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
    if err != nil {
        return nil, err
    }

    cert := tls.Certificate{
        Certificate: [][]byte{derBytes},
        PrivateKey: priv,
    }

    cert_x509, err := x509.ParseCertificate(derBytes)
    if err != nil {
        return nil, err
    }

    log.Printf("Certificate Fingerprint: %X", sha1.Sum(cert_x509.Raw))

    return &cert, nil
}
