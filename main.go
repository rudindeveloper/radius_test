package main

import (
	"log"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

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
			log.Printf("- %s: %v", attr.Type, attr.Attribute)
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
