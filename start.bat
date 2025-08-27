@echo off

echo Stopping and removing existing radius-server container...
FOR /f "tokens=*" %%i IN ('docker ps -a -q -f name=radius-server') DO (
    docker stop %%i
    docker rm %%i
)

echo Building the radius-server image...
docker build -t radius-server .

echo Starting the radius-server container...
docker run -d -p 1812:1812/udp --name radius-server radius-server

echo.
echo Server started successfully.
