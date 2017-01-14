package main

import (
    // #cgo CXXFLAGS: -I /usr/local/opt/openssl/include -I /usr/local/include -I /usr/local/include/NTL -I dp5/build/Relic-prefix/include  -I dp5/build/RelicWrapper-prefix/src/RelicWrapper -I dp5/build/Percy++-prefix/src/Percy++ -I dp5
    // #cgo LDFLAGS: -L /usr/local/opt/openssl/lib -l ssl -L /usr/local/opt/openssl/lib -l crypto -L /usr/lib/ -l pthread -L /usr/local/lib/ -l gmp -L /usr/local/lib/ -l ntl -L dp5/build/Relic-prefix/lib/ -l relic_s -L dp5/build/RelicWrapper-prefix/src/RelicWrapper-build/ -l relicwrapper -L dp5/build/Percy++-prefix/src/Percy++-build/ -l percyserver -L dp5/build/Percy++-prefix/src/Percy++-build/ -l percyclient -L dp5/build -l dp5
    // #include "dp5_bind.h"
    "C"

    "bytes"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"
    "unsafe"
)

var dp5_init_ptr unsafe.Pointer
var dp5_config_ptr *C.struct__DP5Config

var dp5_dhkey_ptr *C.DHKey

var dp5_regclient_ptr *C.struct__DP5RegClient
var dp5_lookupclient_ptr *C.struct__DP5LookupClient

var dp5_friends map[string][]byte

var dp5_spoof_client map[string]*strings.Replacer
var dp5_spoof_server map[string]*strings.Replacer

var client *http.Client

func stat(path string, dir bool, mk bool) bool {
    info, err := os.Stat(path)
    if err != nil {
        if os.IsNotExist(err) {
            if dir && mk {
                err = os.MkdirAll(path, os.ModePerm)
                if err != nil { log.Fatal(err) }
                return true
            }
            return false
        } else {
            log.Fatal(err)
            return false
        }
    } else {
        if dir && !info.IsDir() {
            log.Fatal(path + " is not a directory")
        } else if !dir && info.IsDir() {
            log.Fatal(path + " is not a file")
        }
        return true
    }
}

func dp5_init() {
    dp5_friends = make(map[string][]byte)
    dp5_spoof_client = make(map[string]*strings.Replacer)
    dp5_spoof_server = make(map[string]*strings.Replacer)

    dp5_init_ptr, _ = C.Init_init()
    dp5_config_ptr, _ = C.Config_alloc(C.uint(epoch_len), C.uint(dataenc_bytes), false)

    stat(conf_dir, true, true)

    dhkey_path := filepath.Join(conf_dir, "id.key")
    dhkey_pub_path := filepath.Join(conf_dir, "id.pub")

    if !stat(dhkey_path, false, false) {
        dp5_dhkey_ptr, _ = C.DHKey_alloc()
        _, _ = C.DHKey_keygen(dp5_dhkey_ptr)

        dhkey_gob := C.GoBytes(unsafe.Pointer(dp5_dhkey_ptr), C.int(C.DHKey_size()))
        err := ioutil.WriteFile(dhkey_path, dhkey_gob, 0644)
        if err != nil { log.Fatal(err) }

        dhkey_pub_gob := C.GoBytes(unsafe.Pointer(dp5_dhkey_ptr), C.int(C.DHKey_pubsize()))
        err = ioutil.WriteFile(dhkey_pub_path, dhkey_pub_gob, 0777)
        if err != nil { log.Fatal(err) }
    } else {
        dhkey_gob, _ := ioutil.ReadFile(dhkey_path)
        dp5_dhkey_ptr = (*C.DHKey)(C.CBytes(dhkey_gob))
    }

    dp5_regclient_ptr, _ = C.RegClient_alloc(dp5_config_ptr, dp5_dhkey_ptr)
    dp5_lookupclient_ptr, _ = C.LookupClient_alloc(dp5_dhkey_ptr)

    friends_path := filepath.Join(conf_dir, "friends")
    stat(friends_path, true, true)

    friends_files, err := ioutil.ReadDir(friends_path)
    if err != nil { log.Fatal(err) }

    for _, f := range friends_files {
        if !f.IsDir() && (filepath.Ext(f.Name()) == ".pub") {
            f_name := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
            dp5_friends[f_name], err = ioutil.ReadFile(filepath.Join(friends_path, f.Name()))
            if err != nil { log.Fatal(err) }
            dp5_spoof_client[f_name] = strings.NewReplacer()
            dp5_spoof_server[f_name] = strings.NewReplacer()
        }
    }

    tr := &http.Transport{
        // TODO: Remove insecure config, might need own CA pool
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        Dial: tor_dialer.Dial,
    }
    client = &http.Client{Transport: tr}
}

func dp5_cleanup() {
    _, _ = C.Config_delete(dp5_config_ptr)

    _, _ = C.DHKey_free(dp5_dhkey_ptr)

    _, _ = C.RegClient_delete(dp5_regclient_ptr)
    _, _ = C.LookupClient_delete(dp5_lookupclient_ptr)
}

func dp5_sendreg_req(server string, epoch int, msg []byte) []byte {
    url := "https://" + server + "/register?epoch=" + strconv.Itoa(epoch)

    resp, err := client.Post(url, "text/html", bytes.NewReader(msg))
    if err != nil { log.Fatal(err) }

    body, _ := ioutil.ReadAll(resp.Body)

    return body
}

func dp5_sendreg(username string) {
    var msg C.nativebuffer
    var reply C.nativebuffer

    if len(dp5_friends) > 0 {
        data_slice := make([][]byte, 0, len(dp5_friends))

        for _, v := range dp5_friends {
            data_slice = append(data_slice, bytes.Join([][]byte{v, []byte(username)}, []byte("")))
        }

        data := (*C.char)(C.CBytes(bytes.Join(data_slice, []byte(""))))
        epoch := C.Config_current_epoch(dp5_config_ptr)

        if verbose { log.Println("dp5_sendreg epoch: " + strconv.Itoa(int(epoch))) }

        _, _ = C.RegClient_start(dp5_regclient_ptr, dp5_config_ptr, epoch + 1, C.uint(len(dp5_friends)), data, &msg)

        msg_gob := C.GoBytes(unsafe.Pointer(msg.buf), C.int(msg.len))

        reply_gob := dp5_sendreg_req(reg_server, int(epoch), msg_gob)

        reply.buf = (*C.char)(C.CBytes(reply_gob))
        reply.len = C.size_t(len(reply_gob))

        ret, _ := C.RegClient_complete(dp5_regclient_ptr, epoch + 1, reply)

        if verbose { log.Println("dp5_sendreg ret: " + strconv.Itoa(int(ret))) }

        _, _ = C.free(unsafe.Pointer(data))
        _, _ = C.nativebuffer_purge(msg)
    }
}

func dp5_sendlookup_req(server string, epoch int, msg []byte) []byte {
    url := "https://" + server + "/lookup?epoch=" + strconv.Itoa(epoch)

    resp, err := client.Post(url, "text/html", bytes.NewReader(msg))
    if err != nil { log.Fatal(err) }

    body, _ := ioutil.ReadAll(resp.Body)

    return body
}

func dp5_sendlookup() map[string]string {
    var md_msg C.nativebuffer
    var md_reply C.nativebuffer
    var req_msg [2]C.nativebuffer
    var req_reply [2]C.nativebuffer

    friends_alias := make(map[string]string)

    if len(dp5_friends) > 0 {
        req_data_slice := make([][]byte, 0, len(dp5_friends))
        friends_slice := make([]string, 0, len(dp5_friends))

        for k, v := range dp5_friends {
            friends_alias[k] = ""
            req_data_slice = append(req_data_slice, v)
            friends_slice = append(friends_slice, k)
        }

        req_data := (*C.char)(C.CBytes(bytes.Join(req_data_slice, []byte(""))))
        epoch := C.Config_current_epoch(dp5_config_ptr)

        if verbose { log.Println("dp5_sendlookup epoch: " + strconv.Itoa(int(epoch))) }

        _, _ = C.LookupClient_metadata_req(dp5_lookupclient_ptr, epoch, &md_msg)

        md_msg_gob := C.GoBytes(unsafe.Pointer(md_msg.buf), C.int(md_msg.len))

        md_reply_gob := dp5_sendlookup_req(lookup_server1, int(epoch), md_msg_gob)

        md_reply.buf = (*C.char)(C.CBytes(md_reply_gob))
        md_reply.len = C.size_t(len(md_reply_gob))

        md_ret, _ := C.LookupClient_metadata_rep(dp5_lookupclient_ptr, md_reply)

        if(verbose) { log.Println("dp5_sendlookup md ret: " + strconv.Itoa(int(md_ret))) }
        if int(md_ret) != 0 { return friends_alias }

        dp5_lookupclient_req_ptr, _ := C.LookupRequest_lookup(dp5_lookupclient_ptr, C.uint(len(dp5_friends)), unsafe.Pointer(req_data), 2, &(req_msg[0]))

        req_msg1_gob := C.GoBytes(unsafe.Pointer(req_msg[0].buf), C.int(req_msg[0].len))
        req_msg2_gob := C.GoBytes(unsafe.Pointer(req_msg[1].buf), C.int(req_msg[1].len))

        req_reply1_gob := dp5_sendlookup_req(lookup_server1, int(epoch), req_msg1_gob)

        req_reply2_gob := dp5_sendlookup_req(lookup_server2, int(epoch), req_msg2_gob)

        req_reply[0].buf = (*C.char)(C.CBytes(req_reply1_gob))
        req_reply[0].len = C.size_t(len(req_reply1_gob))

        req_reply[1].buf = (*C.char)(C.CBytes(req_reply2_gob))
        req_reply[1].len = C.size_t(len(req_reply2_gob))

        status_msg := make([]C.nativebuffer, len(dp5_friends))

        req_ret, _ := C.LookupRequest_reply(dp5_lookupclient_req_ptr, 2, &(req_reply[0]), &(status_msg[0]))

        if verbose { log.Println("dp5_sendlookup req ret: " + strconv.Itoa(int(req_ret))) }
        if int(req_ret) != 0 { return friends_alias }

        for i, f := range friends_slice {
            friends_alias[f] = string(C.GoBytes(unsafe.Pointer(status_msg[i].buf), C.int(status_msg[i].len)))
        }

        _, _ = C.free(unsafe.Pointer(req_data))
        _, _ = C.nativebuffer_purge(md_msg)
        // TODO: Free buffers
    }

    return friends_alias
}

func dp5_checkepoch(server string) int {
    url := "https://" + server + "/"

    resp, err := client.Get(url)
    if err != nil {
        log.Println(err)
        return -1
    }

    body, _ := ioutil.ReadAll(resp.Body)

    var body_map map[string]interface{}
    err = json.Unmarshal(body, &body_map)
    if err != nil { log.Fatal(err) }

    return int(body_map["epoch"].(float64))
}

func dp5_refreshepoch() {
    last_epoch := dp5_checkepoch(reg_server)
    for last_epoch == -1 { last_epoch = dp5_checkepoch(reg_server) }
    current_epoch := dp5_checkepoch(reg_server)
    for current_epoch == -1 { current_epoch = dp5_checkepoch(reg_server) }

    if current_epoch > last_epoch { log.Println("Refreshing epoch...") }

    for current_epoch > last_epoch {
        last_epoch = current_epoch
        current_epoch = dp5_checkepoch(reg_server)
        for current_epoch == -1 { current_epoch = dp5_checkepoch(reg_server) }
    }
}

func dp5_loop() {
    last_check := int(time.Now().Unix())

    for {
        if int(time.Now().Unix()) > (last_check + (epoch_len/2)) {
            last_check = int(time.Now().Unix())

            dp5_refreshepoch()

            if user_server != "" { dp5_sendreg(user_server) }

            friend_alias := dp5_sendlookup()

            log_msg := fmt.Sprintf("%sContacts:%s ", c_contacts, c_clear)

            for k, v := range friend_alias {
                if v != "" {
                    log_msg = log_msg + fmt.Sprintf("%s● %s%s %s(%s)%s ", c_online, k, c_clear, c_alias, v, c_clear)

                    dp5_spoof_client[k] = strings.NewReplacer(k, v, strings.ToLower(k), strings.ToLower(v))
                    dp5_spoof_server[k] = strings.NewReplacer(v, k, strings.ToLower(v), strings.ToLower(k))
                } else {
                    log_msg = log_msg + fmt.Sprintf("%s● %s%s ", c_offline, k, c_clear)
                }
            }

            log.Println(log_msg)
        }

        time.Sleep(time.Second)
    }
}
