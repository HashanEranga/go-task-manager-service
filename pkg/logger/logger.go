package logger

import (
	"github.com/rs/zerolog"
	"os"
)

var Log zerolog.Logger

func Init(level string) {
	logLevel, err := zerolog.ParseLevel(level)

	if err != nil {
		logLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(logLevel)

	Log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).
		With().
		Timestamp().
		Caller().
		Logger()
}

func Info(msg string) {
	Log.Info().Msg(msg)
}

func Error(msg string, err error) {
	Log.Error().Err(err).Msg(msg)
}

func Debug(msg string) {
	Log.Debug().Msg(msg)
}
