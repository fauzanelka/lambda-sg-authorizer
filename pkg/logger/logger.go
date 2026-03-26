package logger

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus.Logger with custom configuration
type Logger struct {
	*logrus.Logger
}

// LogLevel represents the logging level
type LogLevel string

const (
	DebugLevel LogLevel = "DEBUG"
	InfoLevel  LogLevel = "INFO"
	WarnLevel  LogLevel = "WARN"
	ErrorLevel LogLevel = "ERROR"
	FatalLevel LogLevel = "FATAL"
	PanicLevel LogLevel = "PANIC"
)

// New creates a new logger instance with the specified level
func New() *Logger {
	log := logrus.New()

	// Set output to stdout (which goes to CloudWatch in Lambda)
	log.SetOutput(os.Stdout)

	// Set JSON formatter for structured logging in CloudWatch
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Set log level from environment variable
	level := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	if level == "" {
		level = "INFO"
	}

	switch level {
	case "DEBUG":
		log.SetLevel(logrus.DebugLevel)
	case "INFO":
		log.SetLevel(logrus.InfoLevel)
	case "WARN":
		log.SetLevel(logrus.WarnLevel)
	case "ERROR":
		log.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		log.SetLevel(logrus.FatalLevel)
	case "PANIC":
		log.SetLevel(logrus.PanicLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}

	return &Logger{Logger: log}
}

// WithFields adds fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields(fields))
}

// WithField adds a single field to the logger
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

// WithError adds an error field to the logger
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	l.Logger.Debug(msg)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.Logger.Info(msg)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.Logger.Warn(msg)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logger.Warnf(format, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.Logger.Error(msg)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string) {
	l.Logger.Fatal(msg)
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Logger.Fatalf(format, args...)
}

// Panic logs a panic message and panics
func (l *Logger) Panic(msg string) {
	l.Logger.Panic(msg)
}

// Panicf logs a formatted panic message and panics
func (l *Logger) Panicf(format string, args ...interface{}) {
	l.Logger.Panicf(format, args...)
}

// LogAction logs an action with contextual information
func (l *Logger) LogAction(action string, fields map[string]interface{}) {
	entry := l.WithField("action", action)
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Info("Action executed")
}

// LogError logs an error with contextual information
func (l *Logger) LogError(action string, err error, fields map[string]interface{}) {
	entry := l.WithError(err).WithField("action", action)
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Error("Action failed")
}

// LogHTTPRequest logs HTTP request information
func (l *Logger) LogHTTPRequest(method, path, clientIP string, statusCode int) {
	l.WithFields(map[string]interface{}{
		"method":      method,
		"path":        path,
		"client_ip":   clientIP,
		"status_code": statusCode,
	}).Info("HTTP request processed")
}

// LogAWSAction logs AWS API actions
func (l *Logger) LogAWSAction(service, action string, fields map[string]interface{}) {
	entry := l.WithFields(map[string]interface{}{
		"aws_service": service,
		"aws_action":  action,
	})
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Info("AWS API action executed")
}
