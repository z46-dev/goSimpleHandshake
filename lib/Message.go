package lib

import "fmt"

type Message struct {
	length int
	body   []byte
}

func NewMessage(length int) *Message {
	var message *Message = new(Message)
	message.length = length
	message.body = make([]byte, length)

	return message
}

func NewMessageFromBytes(body []byte) *Message {
	var message *Message = new(Message)
	message.length = len(body)
	message.body = body

	return message
}

func (m *Message) GetLength() int {
	return m.length
}

func (m *Message) GetBody() []byte {
	return m.body
}

func (m *Message) SetU8(offset int, value uint8) error {
	if offset >= m.length {
		return fmt.Errorf("offset %d is out of range", offset)
	}

	m.body[offset] = value
	return nil
}

func (m *Message) GetU8(offset int) (uint8, error) {
	if offset >= m.length {
		return 0, fmt.Errorf("offset %d is out of range", offset)
	}

	return m.body[offset], nil
}

func (m *Message) SetU16(offset int, value uint16) error {
	if offset+1 >= m.length {
		return fmt.Errorf("offset %d is out of range", offset)
	}

	m.body[offset] = uint8(value >> 8)
	m.body[offset+1] = uint8(value)
	return nil
}

func (m *Message) GetU16(offset int) (uint16, error) {
	if offset+1 >= m.length {
		return 0, fmt.Errorf("offset %d is out of range", offset)
	}

	return uint16(m.body[offset])<<8 | uint16(m.body[offset+1]), nil
}

func (m *Message) SetStringUTF8(offset int, value string) error {
	if offset+len(value) >= m.length {
		return fmt.Errorf("offset %d is out of range", offset)
	}

	for i, c := range value {
		m.body[offset+i] = byte(c)
	}

	return nil
}

func (m *Message) GetStringUTF8(offset int, length int) (string, error) {
	if offset+length >= m.length {
		return "", fmt.Errorf("offset %d is out of range", offset)
	}

	return string(m.body[offset : offset+length]), nil
}
