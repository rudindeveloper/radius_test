# Use the official Golang image to create a build artifact.
# This is known as a multi-stage build.
FROM golang:1.25-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# We copy the Go Modules manifests
COPY go.mod go.sum ./

# We download the Go Modules
RUN go mod download

# We copy the source code
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o /radius-server

# Start a new stage from scratch for a smaller image
FROM alpine:latest

WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /radius-server .

# Expose port 1812/udp to the outside world
EXPOSE 1812/udp

# Command to run the executable
CMD ["./radius-server"]
