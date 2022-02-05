# From Docker website
FROM golang:latest

# Creates working directory on the Docker image
WORKDIR /app

# Download necessary Go modules
#COPY ../../go.mod ./
#COPY ../../go.sum ./
#RUN go mod download

# Copy src files to working dir in Docker image
#COPY ../../lib lib
COPY *.go ./
RUN go mod init github.com/jansemmelink/wasps
RUN go get .

# Build the application binary 
RUN go build -o /api-users

# Open port to be accesseble outside container
EXPOSE 19081

# This is the command that will execute when this image
# is used to start a container
CMD [ "/wasps"]
