FROM golang:1.26-alpine AS build

ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/manifesto ./cmd/manifesto


FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build /out/manifesto /manifesto

ENTRYPOINT ["/manifesto"]
