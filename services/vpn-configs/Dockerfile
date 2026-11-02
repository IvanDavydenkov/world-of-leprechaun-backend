FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /api ./cmd/api
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /import-vpn-server ./cmd/import-vpn-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /api /api
COPY --from=build /import-vpn-server /import-vpn-server
ENTRYPOINT ["/api"]
