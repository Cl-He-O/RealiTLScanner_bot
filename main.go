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
	"golang.org/x/time/rate"
)

type Config struct {
	Token   string  `json:"token"`
	Debug   bool    `json:"debug,omitempty"`
	Admin   string  `json:"admin,omitempty"`
	Timeout string  `json:"timeout,omitempty"`
	Rate    float64 `json:"rate,omitempty"`
	Bucket  int     `json:"bucket,omitempty"`
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
		Debug:   false,
		Admin:   "",
		Timeout: "5s",
		Rate:    1,
		Bucket:  5,
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
				reply("Hello")
			case "tlscan":
				if limiter.Allow() {
					r := limiter.Reserve()
					reply(tlscan(msg.CommandArguments(), timeout))
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

func tlscan(addr string, timeout time.Duration) string {
	if strings.LastIndex(addr, ":") < 0 {
		addr += ":443"
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		err := err.Error()
		return fmt.Sprint("TCP connection failed", err[strings.LastIndex(err, ":"):])
	} else {
		line := "Addr: " + conn.RemoteAddr().String() + "\n"
		conn.SetDeadline(time.Now().Add(timeout))
		c := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		err = c.Handshake()
		if err != nil {
			err := err.Error()
			return fmt.Sprint(line, "TLS handshake failed", err[strings.LastIndex(err, ":"):])
		} else {
			defer c.Close()
			state := c.ConnectionState()
			alpn := state.NegotiatedProtocol
			return fmt.Sprint(line, "Found TLSv", TlsDic[state.Version], ", ALPN: ", alpn, "\nCertificate subject: ", state.PeerCertificates[0].Subject)
		}
	}
}
