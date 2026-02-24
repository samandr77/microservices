package entity

type Message struct {
	Type        string   // "email"
	Subject     string   // тема письма
	Message     string   // текст письма
	Recipients  []string // список получателей
	ContentType string   // "text/plain" или "text/html"
}
