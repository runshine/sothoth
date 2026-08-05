FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/secflow-app-binary-security-go ./cmd/secflow-app-binary-security-go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secflow-app-binary-security-go /secflow-app-binary-security-go
EXPOSE 8080
ENTRYPOINT ["/secflow-app-binary-security-go"]
