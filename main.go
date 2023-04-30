package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

type Config struct {
	Token     string  `json:"token"`
	Debug     bool    `json:"debug,omitempty"`
	Admin     string  `json:"admin,omitempty"`
	Timeout   string  `json:"timeout,omitempty"`
	Rate      float64 `json:"rate,omitempty"`
	Bucket    int     `json:"bucket,omitempty"`
	LocalAddr string  `json:"local_addr,omitempty"`
	SOCKS5    string  `json:"socks5,omitempty"`
}

func main() {
	// read config
	configPtr := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	configFile, err := os.Open(*configPtr)
	if err != nil {
		log.Fatal(err)
	}

	config := Config{
		Debug:     false,
		Admin:     "",
		Timeout:   "5s",
		Rate:      1,
		Bucket:    5,
		LocalAddr: "0.0.0.0",
		SOCKS5:    "",
	}

	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatal(err)
	}

	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		log.Fatal(err)
	}

	// init bot
	bot, err := tgbotapi.NewBotAPI(config.Token)
	if err != nil {
		log.Fatal(err)
	}

	bot.Debug = config.Debug

	_, err = bot.Request(tgbotapi.NewSetMyCommands(
		tgbotapi.BotCommand{Command: "tlscan", Description: "usage: /tlscan example.com(:443)"},
	))
	if err != nil {
		log.Fatal(err)
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = int(timeout.Seconds())

	updates := bot.GetUpdatesChan(u)

	limiter := rate.NewLimiter(rate.Limit(config.Rate), config.Bucket)

	// message loop
	for update := range updates {
		if update.Message == nil {
			continue
		}
		msg := update.Message

		if !msg.IsCommand() {
			continue
		}

		if config.Debug {
			if msg.From == nil {
				continue
			} else if msg.From.UserName != config.Admin {
				continue
			}
		}

		go func() {
			reply_msg := tgbotapi.NewMessage(msg.Chat.ID, "")

			reply := func(text string) {
				reply_msg.Text = text
				if _, err := bot.Send(reply_msg); err != nil {
					fmt.Println("Send message failed", err)
				}
			}

			switch msg.Command() {
			case "start":
				reply("Hello.\nRepo at https://github.com/Cl-He-O/RealiTLScanner_bot")
			case "tlscan":
				if limiter.Allow() {
					r := limiter.Reserve()
					reply(tlscan(msg.CommandArguments(), timeout, config.SOCKS5, config.LocalAddr))
					r.Cancel()
				} else {
					reply("Rate limit exceeded, please try again later.")
				}
			}
		}()
	}
}

// from https://github.com/XTLS/RealiTLScanner

var TlsDic = map[uint16]string{
	0x0301: "1.0",
	0x0302: "1.1",
	0x0303: "1.2",
	0x0304: "1.3",
}

type DialerTimeout struct {
	timeout    time.Duration
	local_addr string
}

func (dialer DialerTimeout) Dial(network, addr string) (c net.Conn, err error) {
	var dialer_t net.Dialer
	if dialer.local_addr == "" {
		dialer_t = net.Dialer{Timeout: dialer.timeout}
	} else {
		local_addr, _ := net.ResolveTCPAddr("tcp", dialer.local_addr)
		dialer_t = net.Dialer{Timeout: dialer.timeout, LocalAddr: local_addr}
	}

	return dialer_t.Dial(network, addr)
}

func tlscan(addr string, timeout time.Duration, socks5_addr string, local_addr string) string {
	if strings.LastIndex(addr, ":") < 0 {
		addr += ":443"
	}

	var dialer proxy.Dialer = DialerTimeout{timeout, local_addr}

	if socks5_addr != "" {
		var err error
		dialer, err = proxy.SOCKS5("tcp", socks5_addr, nil, dialer)
		if err != nil {
			panic("Error creating SOCKS5 dialer")
		}
	}

	ipaddr, err := net.ResolveTCPAddr("tcp", addr)

	if err != nil {
		return fmt.Sprint("TCP connection failed: ", err.Error())
	}

	conn, err := dialer.Dial("tcp", ipaddr.String())
	if err != nil {
		err := err.Error()
		return fmt.Sprint("TCP connection failed: ", err)
	} else {
		line := "Addr: " + ipaddr.String() + "\n"
		conn.SetDeadline(time.Now().Add(timeout))
		c := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		err = c.Handshake()
		if err != nil {
			err := err.Error()
			return fmt.Sprint(line, "TLS handshake failed: ", err)
		} else {
			defer c.Close()
			state := c.ConnectionState()
			alpn := state.NegotiatedProtocol
			return fmt.Sprint(line, "Found TLSv", TlsDic[state.Version], ", ALPN: ", alpn, "\nCertificate subject: ", state.PeerCertificates[0].Subject)
		}
	}
}
