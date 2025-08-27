package main

import (
	"context"
	"log"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func main() {
	packet := radius.New(radius.CodeAccessRequest, []byte("secret123"))
	rfc2865.UserName_SetString(packet, "testuser")
	rfc2865.UserPassword_SetString(packet, "testpassword")

	response, err := radius.Exchange(context.Background(), packet, "localhost:1812")
	if err != nil {
		log.Fatalf("Failed to exchange: %v", err)
	}

	log.Printf("Received response with code: %s", response.Code)
}
