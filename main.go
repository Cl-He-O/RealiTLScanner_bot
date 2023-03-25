package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func main() {
	bot, err := tgbotapi.NewBotAPI(os.Getenv("TELEGRAM_APITOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	bot.Debug = true

	_, err = bot.Request(tgbotapi.NewSetMyCommands(
		tgbotapi.BotCommand{Command: "tlscan", Description: "check if the specified server is REALITY compatible"},
	))
	if err != nil {
		log.Fatal(err)
	}

	const timeout = 10

	u := tgbotapi.NewUpdate(0)
	u.Timeout = timeout

	updates := bot.GetUpdatesChan(u)

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
			{
				go func() {
					msg.Text = tlscan(addr, time.Second*timeout)
				}()
			}
		default:
			{
				msg.Text = "unknown command"
			}
		}

		if _, err := bot.Send(msg); err != nil {
			log.Fatal(err)
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
		return fmt.Sprint("", "TCP connection failed: ", err)
	} else {
		line := "" + conn.RemoteAddr().String() + " \t"
		conn.SetDeadline(time.Now().Add(timeout))
		c := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		err = c.Handshake()
		if err != nil {
			return fmt.Sprint("", line, "TLS handshake failed: ", err)
		} else {
			defer c.Close()
			state := c.ConnectionState()
			alpn := state.NegotiatedProtocol
			if alpn == "" {
				alpn = "  "
			}
			return fmt.Sprint("", line, "----- Found TLS v", TlsDic[state.Version], "\tALPN", alpn, "\t", state.PeerCertificates[0].Subject)
		}
	}
}
