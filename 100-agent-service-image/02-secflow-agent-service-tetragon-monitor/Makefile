.PHONY: all build build-local clean

IMAGE_NAME ?= secflow-agent-service-tetragon-monitor
IMAGE_TAG ?= latest
VERSION ?= 1.0.0

all: build

build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

build-local:
	CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags="-w -s" -o tetragon-monitor .

build-multi-arch:
	./build-multi-arch.sh

clean:
	rm -f tetragon-monitor