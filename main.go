package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type Config struct {
	Token       string `json:"token"`
	Debug       bool   `json:"debug"`
	Timeout     string `json:"timeout"`
	MinDuration string `json:"min_duration"`
}

func main() {
	// read config
	configPtr := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	configFile, err := os.Open(*configPtr)
	if err != nil {
		log.Fatal(err)
	}

	var config Config
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatal(err)
	}

	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		log.Fatal(err)
	}
	min_duration, err := time.ParseDuration(config.MinDuration)
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
		tgbotapi.BotCommand{Command: "tlscan", Description: "usage: /tlscan example.com:443"},
	))
	if err != nil {
		log.Fatal(err)
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = int(timeout.Seconds())

	updates := bot.GetUpdatesChan(u)

	// message loop

	msg_last := time.Now()
	for update := range updates {
		if update.Message == nil {
			continue
		}
		if !update.Message.IsCommand() {
			continue
		}

		addr := update.Message.CommandArguments()

		msg := tgbotapi.NewMessage(update.Message.Chat.ID, "")

		switch update.Message.Command() {
		case "tlscan":
			if time.Since(msg_last) > min_duration {
				msg_last = time.Now()

				go func() {
					msg.Text = tlscan(addr, timeout)

					if _, err := bot.Send(msg); err != nil {
						fmt.Println("Send message failed", err)
					}
				}()
			}
		default:
			{
				continue
			}
		}
	}
}

var TlsDic = map[uint16]string{
	0x0301: "1.0",
	0x0302: "1.1",
	0x0303: "1.2",
	0x0304: "1.3",
}

func tlscan(addr string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Sprint("TCP connection failed: ", err)
	} else {
		line := "Addr: " + conn.RemoteAddr().String() + "\n"
		conn.SetDeadline(time.Now().Add(timeout))
		c := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		err = c.Handshake()
		if err != nil {
			return fmt.Sprint(line, "TLS handshake failed: ", err)
		} else {
			defer c.Close()
			state := c.ConnectionState()
			alpn := state.NegotiatedProtocol
			return fmt.Sprint(line, "Found TLSv", TlsDic[state.Version], "\nALPN: ", alpn, "\nCertificate subject: ", state.PeerCertificates[0].Subject)
		}
	}
}
