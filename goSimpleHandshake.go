package goSimpleHandshake

import (
	"encoding/json"
	"os"

	"github.com/z46-dev/goSimpleHandshake/lib"
)

// Structure of a message:
// 1 byte: 1st XOR key
// 2 bytes: body length as a big-endian 16-bit unsigned integer
// ...: message body
// 2 bytes: CRC-16 checksum of the message body XORed with the 1st XOR key
// 2 bytes: 2nd XOR key and 2nd XOR key XORed with the body length

func CRC16(bytes []byte) uint16 {
	var crc uint16 = 0xFFFF

	for _, b := range bytes {
		crc ^= uint16(b)

	internal:
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA001
				continue internal
			}

			crc >>= 1
		}
	}

	return crc
}

func XOR(bytes []byte, key byte) []byte {
	for i := range bytes {
		bytes[i] ^= key
	}

	return bytes
}

func createByteMessage(message []byte, XOR1, XOR2 byte) []byte {
	var output []byte = make([]byte, 8+len(message))
	output[0] = XOR1
	output[1] = byte(len(message) >> 8)
	output[2] = byte(len(message) & 0xFF)

	var crcValue uint16 = CRC16(XOR(message, XOR2))
	output[3+len(message)] = byte(crcValue >> 8)
	output[4+len(message)] = byte(crcValue & 0xFF)

	var xorValue uint16 = uint16(XOR2)<<8 + uint16(XOR2^byte(len(message)))
	output[5+len(message)] = byte(xorValue >> 8)
	output[6+len(message)] = byte(xorValue & 0xFF)

	copy(output[3:], XOR(message, XOR1^byte(crcValue>>8)))

	return output
}

func parseByteMessage(handshake []byte) ([]byte, byte, byte) {
	if len(handshake) < 8 {
		return nil, 0, 0
	}

	var XOR1 byte = handshake[0]
	var bodyLength int = int(handshake[1])<<8 + int(handshake[2])
	var CRC = uint16(handshake[3+bodyLength])<<8 + uint16(handshake[4+bodyLength])
	var XORValue = uint16(handshake[5+bodyLength])<<8 + uint16(handshake[6+bodyLength])
	var XOR2 byte = byte(XORValue&0xFF ^ uint16(bodyLength))
	var body = XOR(handshake[3:3+bodyLength], XOR1^byte(CRC>>8))
	body = XOR(body, XOR2)

	return body, XOR1, XOR2
}

func MessageTemplate(length int) *lib.Message {
	return lib.NewMessage(length)
}

func EncodeMessage(message *lib.Message, XOR1, XOR2 byte) []byte {
	return createByteMessage(message.GetBody(), XOR1, XOR2)
}

func DecodeMessage(message []byte) (*lib.Message, byte, byte) {
	body, XOR1, XOR2 := parseByteMessage(message)
	return lib.NewMessageFromBytes(body), XOR1, XOR2
}

func LoadXORKeysFromConfigFile(fileName string) (byte, byte, error) {
	configFile, err := os.Open(fileName)
	if err != nil {
		return 0, 0, err
	}

	defer configFile.Close()

	var config struct {
		XOR1 byte `json:"XOR1"`
		XOR2 byte `json:"XOR2"`
	}

	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&config)
	if err != nil {
		return 0, 0, err
	}

	return config.XOR1, config.XOR2, nil
}
