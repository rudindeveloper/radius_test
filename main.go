package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// convertAttributeToString пытается преобразовать атрибут в строковый вид
func convertAttributeToString(attrType radius.Type, attr radius.Attribute, packet *radius.Packet) string {
	switch attrType {
	case rfc2865.UserName_Type:
		if username := rfc2865.UserName_GetString(packet); username != "" {
			return fmt.Sprintf("'%s'", username)
		}
	case rfc2865.UserPassword_Type:
		return "[PASSWORD_HIDDEN]"
	case rfc2865.NASIPAddress_Type:
		if ip := rfc2865.NASIPAddress_Get(packet); ip != nil {
			return ip.String()
		}
	case rfc2865.NASPort_Type:
		if port := rfc2865.NASPort_Get(packet); port != 0 {
			return fmt.Sprintf("%d", port)
		}
	case rfc2865.ServiceType_Type:
		if serviceType := rfc2865.ServiceType_Get(packet); serviceType != 0 {
			return fmt.Sprintf("%d (%s)", serviceType, getServiceTypeName(serviceType))
		}
	case rfc2865.FramedProtocol_Type:
		if protocol := rfc2865.FramedProtocol_Get(packet); protocol != 0 {
			return fmt.Sprintf("%d (%s)", protocol, getFramedProtocolName(protocol))
		}
	case rfc2865.FramedIPAddress_Type:
		if ip := rfc2865.FramedIPAddress_Get(packet); ip != nil {
			return ip.String()
		}
	case rfc2865.CalledStationID_Type:
		if called := rfc2865.CalledStationID_GetString(packet); called != "" {
			return fmt.Sprintf("'%s'", called)
		}
	case rfc2865.CallingStationID_Type:
		if calling := rfc2865.CallingStationID_GetString(packet); calling != "" {
			return fmt.Sprintf("'%s'", calling)
		}
	case rfc2865.VendorSpecific_Type:
		return parseVendorSpecificAttribute(attr)
	}

	// Если не удалось преобразовать в строку, показываем как hex
	if len(attr) > 0 {
		hexStr := fmt.Sprintf("%x", attr)
		// Пытаемся также показать как ASCII, если это возможно
		asciiStr := strings.Map(func(r rune) rune {
			if r >= 32 && r <= 126 {
				return r
			}
			return '.'
		}, string(attr))

		if asciiStr != string(attr) {
			return fmt.Sprintf("hex: %s, ascii: '%s'", hexStr, asciiStr)
		}
		return fmt.Sprintf("hex: %s", hexStr)
	}

	return "[empty]"
}

// parseVendorSpecificAttribute парсит Vendor-Specific атрибут
func parseVendorSpecificAttribute(attr radius.Attribute) string {
	if len(attr) < 4 {
		return fmt.Sprintf("invalid vendor-specific attribute (too short): %x", attr)
	}

	// Первые 4 байта - Vendor-ID в network byte order
	vendorID := binary.BigEndian.Uint32(attr[:4])
	vendorData := attr[4:]

	vendorName := getVendorName(vendorID)
	result := fmt.Sprintf("Vendor: %s (ID: %d)", vendorName, vendorID)

	if len(vendorData) > 0 {
		// Пытаемся парсить vendor-specific атрибуты
		vendorAttrs := parseVendorAttributes(vendorID, vendorData)
		if vendorAttrs != "" {
			result += fmt.Sprintf(", Attributes: %s", vendorAttrs)
		} else {
			// Если не удалось распарсить, показываем как hex
			hexStr := fmt.Sprintf("%x", vendorData)
			asciiStr := strings.Map(func(r rune) rune {
				if r >= 32 && r <= 126 {
					return r
				}
				return '.'
			}, string(vendorData))

			if asciiStr != string(vendorData) {
				result += fmt.Sprintf(", Data: hex=%s ascii='%s'", hexStr, asciiStr)
			} else {
				result += fmt.Sprintf(", Data: hex=%s", hexStr)
			}
		}
	}

	return result
}

// getVendorName возвращает название вендора по ID
func getVendorName(vendorID uint32) string {
	switch vendorID {
	case 9:
		return "Cisco Systems"
	case 311:
		return "Microsoft"
	case 25506:
		return "Mikrotik"
	case 14122:
		return "Aruba"
	case 12322:
		return "WISPr"
	default:
		return "Unknown"
	}
}

// parseVendorAttributes парсит атрибуты конкретного вендора
func parseVendorAttributes(vendorID uint32, data []byte) string {
	switch vendorID {
	case 9: // Cisco Systems
		return parseCiscoAttributes(data)
	default:
		return ""
	}
}

// parseCiscoAttributes парсит Cisco vendor-specific атрибуты
func parseCiscoAttributes(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	var results []string
	offset := 0

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		// Cisco vendor-specific атрибуты имеют формат: type(1) + length(1) + value
		attrType := data[offset]
		attrLength := int(data[offset+1])

		if attrLength < 2 || offset+attrLength > len(data) {
			break
		}

		attrValue := data[offset+2 : offset+attrLength]
		attrName := getCiscoAttributeName(attrType)

		// Пытаемся показать значение в читаемом виде
		valueStr := formatCiscoAttributeValue(attrType, attrValue)
		results = append(results, fmt.Sprintf("%s(%d)=%s", attrName, attrType, valueStr))

		offset += attrLength
	}

	return strings.Join(results, ", ")
}

// getCiscoAttributeName возвращает название Cisco атрибута
func getCiscoAttributeName(attrType byte) string {
	switch attrType {
	case 1:
		return "cisco-avpair"
	case 2:
		return "cisco-nas-port"
	case 3:
		return "cisco-fax-account-id"
	case 4:
		return "cisco-fax-message-id"
	case 5:
		return "cisco-fax-pages"
	case 6:
		return "cisco-fax-coverpage-fmt"
	case 7:
		return "cisco-fax-modem-time"
	case 8:
		return "cisco-fax-recipient-count"
	case 9:
		return "cisco-fax-email-address"
	case 10:
		return "cisco-fax-dsn-address"
	case 11:
		return "cisco-fax-subject"
	case 12:
		return "cisco-fax-header-info"
	case 13:
		return "cisco-fax-priority"
	case 14:
		return "cisco-fax-server-address"
	case 15:
		return "cisco-fax-dsn-flag"
	case 16:
		return "cisco-fax-mdn-flag"
	case 17:
		return "cisco-fax-auth-status"
	case 18:
		return "cisco-email-server-address"
	case 19:
		return "cisco-email-server-ack"
	case 20:
		return "cisco-gateway-id"
	case 21:
		return "cisco-call-type"
	case 22:
		return "cisco-port-id"
	case 23:
		return "cisco-nas-port-id"
	case 24:
		return "cisco-username"
	case 25:
		return "cisco-acct-session-id"
	case 26:
		return "cisco-acct-multi-session-id"
	case 27:
		return "cisco-acct-link-count"
	case 28:
		return "cisco-acct-input-gigawords"
	case 29:
		return "cisco-acct-output-gigawords"
	case 30:
		return "cisco-event-stats-timestamp"
	case 31:
		return "cisco-acct-tunnel-connection"
	case 32:
		return "cisco-acct-tunnel-packets-lost"
	case 33:
		return "cisco-acct-tunnel-packets-received"
	case 34:
		return "cisco-acct-tunnel-packets-sent"
	case 35:
		return "cisco-acct-tunnel-packet-retransmissions"
	case 36:
		return "cisco-acct-tunnel-packet-reordering"
	case 37:
		return "cisco-acct-tunnel-packet-duplicates"
	case 38:
		return "cisco-acct-tunnel-packet-late-arrivals"
	case 39:
		return "cisco-acct-tunnel-packet-invalid"
	case 40:
		return "cisco-acct-tunnel-packet-overruns"
	case 41:
		return "cisco-acct-tunnel-packet-other-errors"
	case 42:
		return "cisco-acct-tunnel-packet-malformed"
	case 43:
		return "cisco-acct-tunnel-packet-bad-authentication"
	case 44:
		return "cisco-acct-tunnel-packet-bad-address"
	case 45:
		return "cisco-acct-tunnel-packet-bad-version"
	case 46:
		return "cisco-acct-tunnel-packet-bad-checksum"
	case 47:
		return "cisco-acct-tunnel-packet-bad-length"
	case 48:
		return "cisco-acct-tunnel-packet-bad-options"
	case 49:
		return "cisco-acct-tunnel-packet-bad-payload"
	case 50:
		return "cisco-acct-tunnel-packet-bad-protocol"
	case 51:
		return "cisco-acct-tunnel-packet-bad-format"
	case 52:
		return "cisco-acct-tunnel-packet-bad-encoding"
	case 53:
		return "cisco-acct-tunnel-packet-bad-compression"
	case 54:
		return "cisco-acct-tunnel-packet-bad-encryption"
	case 55:
		return "cisco-acct-tunnel-packet-bad-signature"
	case 56:
		return "cisco-acct-tunnel-packet-bad-certificate"
	case 57:
		return "cisco-acct-tunnel-packet-bad-key"
	case 58:
		return "cisco-acct-tunnel-packet-bad-algorithm"
	case 59:
		return "cisco-acct-tunnel-packet-bad-parameter"
	case 60:
		return "cisco-acct-tunnel-packet-bad-timestamp"
	case 61:
		return "cisco-acct-tunnel-packet-bad-sequence"
	case 62:
		return "cisco-acct-tunnel-packet-bad-replay"
	case 63:
		return "cisco-acct-tunnel-packet-bad-nonce"
	case 64:
		return "cisco-acct-tunnel-packet-bad-cookie"
	case 65:
		return "cisco-acct-tunnel-packet-bad-token"
	case 66:
		return "cisco-acct-tunnel-packet-bad-challenge"
	case 67:
		return "cisco-acct-tunnel-packet-bad-response"
	case 68:
		return "cisco-acct-tunnel-packet-bad-request"
	case 69:
		return "cisco-acct-tunnel-packet-bad-reply"
	case 70:
		return "cisco-acct-tunnel-packet-bad-notification"
	case 71:
		return "cisco-acct-tunnel-packet-bad-error"
	case 72:
		return "cisco-acct-tunnel-packet-bad-warning"
	case 73:
		return "cisco-acct-tunnel-packet-bad-info"
	case 74:
		return "cisco-acct-tunnel-packet-bad-debug"
	case 75:
		return "cisco-acct-tunnel-packet-bad-trace"
	case 76:
		return "cisco-acct-tunnel-packet-bad-log"
	case 77:
		return "cisco-acct-tunnel-packet-bad-audit"
	case 78:
		return "cisco-acct-tunnel-packet-bad-security"
	case 79:
		return "cisco-acct-tunnel-packet-bad-privacy"
	case 80:
		return "cisco-acct-tunnel-packet-bad-integrity"
	case 81:
		return "cisco-acct-tunnel-packet-bad-confidentiality"
	case 82:
		return "cisco-acct-tunnel-packet-bad-authentication"
	case 83:
		return "cisco-acct-tunnel-packet-bad-authorization"
	case 84:
		return "cisco-acct-tunnel-packet-bad-accounting"
	case 85:
		return "cisco-acct-tunnel-packet-bad-session"
	case 86:
		return "cisco-acct-tunnel-packet-bad-connection"
	case 87:
		return "cisco-acct-tunnel-packet-bad-transport"
	case 88:
		return "cisco-acct-tunnel-packet-bad-network"
	case 89:
		return "cisco-acct-tunnel-packet-bad-link"
	case 90:
		return "cisco-acct-tunnel-packet-bad-physical"
	case 91:
		return "cisco-acct-tunnel-packet-bad-application"
	case 92:
		return "cisco-acct-tunnel-packet-bad-presentation"
	case 93:
		return "cisco-acct-tunnel-packet-bad-session"
	case 94:
		return "cisco-acct-tunnel-packet-bad-transport"
	case 95:
		return "cisco-acct-tunnel-packet-bad-network"
	case 96:
		return "cisco-acct-tunnel-packet-bad-data-link"
	case 97:
		return "cisco-acct-tunnel-packet-bad-physical"
	case 98:
		return "cisco-acct-tunnel-packet-bad-unknown"
	case 99:
		return "cisco-acct-tunnel-packet-bad-other"
	default:
		return "cisco-unknown"
	}
}

// formatCiscoAttributeValue форматирует значение Cisco атрибута
func formatCiscoAttributeValue(attrType byte, value []byte) string {
	if len(value) == 0 {
		return "[empty]"
	}

	// Для некоторых атрибутов показываем как строку
	switch attrType {
	case 1: // cisco-avpair
		return fmt.Sprintf("'%s'", string(value))
	case 24: // cisco-username
		return fmt.Sprintf("'%s'", string(value))
	default:
		// Для остальных показываем как hex и ASCII
		hexStr := fmt.Sprintf("%x", value)
		asciiStr := strings.Map(func(r rune) rune {
			if r >= 32 && r <= 126 {
				return r
			}
			return '.'
		}, string(value))

		if asciiStr != string(value) {
			return fmt.Sprintf("hex=%s ascii='%s'", hexStr, asciiStr)
		}
		return fmt.Sprintf("hex=%s", hexStr)
	}
}

// getServiceTypeName возвращает название типа сервиса
func getServiceTypeName(serviceType rfc2865.ServiceType) string {
	switch serviceType {
	case rfc2865.ServiceType_Value_LoginUser:
		return "Login User"
	case rfc2865.ServiceType_Value_FramedUser:
		return "Framed User"
	case rfc2865.ServiceType_Value_CallbackLoginUser:
		return "Callback Login User"
	case rfc2865.ServiceType_Value_CallbackFramedUser:
		return "Callback Framed User"
	case rfc2865.ServiceType_Value_OutboundUser:
		return "Outbound User"
	case rfc2865.ServiceType_Value_AdministrativeUser:
		return "Administrative User"
	case rfc2865.ServiceType_Value_NASPromptUser:
		return "NAS Prompt User"
	case rfc2865.ServiceType_Value_AuthenticateOnly:
		return "Authenticate Only"
	case rfc2865.ServiceType_Value_CallbackNASPrompt:
		return "Callback NAS Prompt"
	case rfc2865.ServiceType_Value_CallCheck:
		return "Call Check"
	case rfc2865.ServiceType_Value_CallbackAdministrative:
		return "Callback Administrative"
	default:
		return "Unknown"
	}
}

// getFramedProtocolName возвращает название протокола
func getFramedProtocolName(protocol rfc2865.FramedProtocol) string {
	switch protocol {
	case rfc2865.FramedProtocol_Value_PPP:
		return "PPP"
	case rfc2865.FramedProtocol_Value_SLIP:
		return "SLIP"
	case rfc2865.FramedProtocol_Value_ARAP:
		return "ARAP"
	case rfc2865.FramedProtocol_Value_GandalfSLML:
		return "Gandalf SLML"
	case rfc2865.FramedProtocol_Value_XylogicsIPXSLIP:
		return "Xylogics IPX SLIP"
	case rfc2865.FramedProtocol_Value_X75Synchronous:
		return "X.75 Synchronous"
	default:
		return "Unknown"
	}
}

func main() {
	handler := radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
		log.Printf("Received request from %s", r.RemoteAddr)
		log.Printf("Packet code: %s", r.Code)

		username := rfc2865.UserName_GetString(r.Packet)
		password := rfc2865.UserPassword_GetString(r.Packet)

		log.Printf("Username: %s", username)
		log.Printf("Password: %s", password)

		// Log all attributes for diagnostics
		log.Println("Attributes:")
		for _, attr := range r.Packet.Attributes {
			attrStr := convertAttributeToString(attr.Type, attr.Attribute, r.Packet)
			log.Printf("- %s: %s", attr.Type, attrStr)
		}

		// Respond with Access-Accept
		response := r.Response(radius.CodeAccessAccept)
		if err := w.Write(response); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
		log.Println("Sent Access-Accept")
	})

	server := &radius.PacketServer{
		Handler:      handler,
		SecretSource: radius.StaticSecretSource([]byte("secret123")), // Replace "secret" with your actual secret
		Addr:         ":1812",
	}

	log.Printf("Starting RADIUS server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
