from golang:1.15-buster as builder
workdir /app
copy . .
run go build -o test

from debian:buster
workdir /app
copy index.html .
copy --from=builder /app/test /app/test
run apt update && apt install -y --no-install-recommends ca-certificates && update-ca-certificates
cmd ["./test"]