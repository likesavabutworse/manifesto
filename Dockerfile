FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/manifesto ./cmd/manifesto


FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build /out/manifesto /manifesto

ENTRYPOINT ["/manifesto"]
