VERSION ?= 1.0.0
BINARY_NAME := b4
SRC_DIR := ./src
OUT_DIR := ./out

ENABLE_LINUX ?= 1
ENABLE_FREEBSD ?= 1
ENABLE_OPENBSD ?= 1
ENABLE_ANDROID ?= 0

CGO_ENABLED ?= 0

LINUX_ARCHS := 386 amd64 armv5 armv6 armv7 arm64 loong64 mips mipsle mips64 mips64le ppc64 ppc64le riscv64 s390x
FREEBSD_ARCHS := 386 amd64 armv7 arm64
OPENBSD_ARCHS := 386 amd64 armv7 arm64
ANDROID_ARCHS := amd64 arm64 armv7

all: build

.PHONY: build_local %
%: ;

build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@rm -rf $(OUT_DIR); mkdir -p $(OUT_DIR)/assets
ifneq ($(ENABLE_LINUX),0)
	@$(MAKE) os_linux
endif
ifneq ($(ENABLE_FREEBSD),0)
	@$(MAKE) os_freebsd
endif
ifneq ($(ENABLE_OPENBSD),0)
	@$(MAKE) os_openbsd
endif
ifneq ($(ENABLE_ANDROID),0)
	@$(MAKE) os_android
endif

os_linux:
	@for arch in $(LINUX_ARCHS); do \
		case $$arch in \
			armv5) GOOS=linux GOARCH=arm GOARM=5 TARGET=armv5 $(MAKE) build_single ;; \
			armv6) GOOS=linux GOARCH=arm GOARM=6 TARGET=armv6 $(MAKE) build_single ;; \
			armv7) GOOS=linux GOARCH=arm GOARM=7 TARGET=armv7 $(MAKE) build_single ;; \
			*)     GOOS=linux GOARCH=$$arch TARGET=$$arch $(MAKE) build_single ;; \
		esac ; \
	done

os_freebsd:
	@for arch in $(FREEBSD_ARCHS); do \
		case $$arch in \
			armv7) GOOS=freebsd GOARCH=arm GOARM=7 TARGET=armv7 $(MAKE) build_single ;; \
			*)     GOOS=freebsd GOARCH=$$arch TARGET=$$arch $(MAKE) build_single ;; \
		esac ; \
	done

os_openbsd:
	@for arch in $(OPENBSD_ARCHS); do \
		case $$arch in \
			armv7) GOOS=openbsd GOARCH=arm GOARM=7 TARGET=armv7 $(MAKE) build_single ;; \
			*)     GOOS=openbsd GOARCH=$$arch TARGET=$$arch $(MAKE) build_single ;; \
		esac ; \
	done

os_android:
	@if [ -z "$$ANDROID_NDK_HOME" ]; then echo "Skipping Android: ANDROID_NDK_HOME not set"; exit 0; fi; \
	for arch in $(ANDROID_ARCHS); do \
		case $$arch in \
			armv7) GOOS=android GOARCH=arm GOARM=7 TARGET=armv7 CGO_ENABLED=1 $(MAKE) build_single_android ;; \
			amd64) GOOS=android GOARCH=amd64 TARGET=amd64 CGO_ENABLED=1 $(MAKE) build_single_android ;; \
			arm64) GOOS=android GOARCH=arm64 TARGET=arm64 CGO_ENABLED=1 $(MAKE) build_single_android ;; \
		esac ; \
	done

build_local:
	@set -e; \
	OS="$(word 2,$(MAKECMDGOALS))"; \
	ARCH="$(word 3,$(MAKECMDGOALS))"; \
	DEST_DIR="$(word 4,$(MAKECMDGOALS))"; \
	if [ -z "$$OS" ] || [ -z "$$ARCH" ]; then echo "Usage: make build_local <os> <arch> [dest_dir]"; exit 1; fi; \
	if [ "$$OS" = "android" ]; then \
		if [ -z "$$ANDROID_NDK_HOME" ]; then echo "ANDROID_NDK_HOME not set"; exit 1; fi; \
		case "$$ARCH" in \
			armv7) TARGET=armv7; GOOS=android GOARCH=arm GOARM=7 CGO_ENABLED=1 TARGET=$$TARGET $(MAKE) --no-print-directory build_single_android ;; \
			amd64) TARGET=amd64; GOOS=android GOARCH=amd64 CGO_ENABLED=1 TARGET=$$TARGET $(MAKE) --no-print-directory build_single_android ;; \
			arm64) TARGET=arm64; GOOS=android GOARCH=arm64 CGO_ENABLED=1 TARGET=$$TARGET $(MAKE) --no-print-directory build_single_android ;; \
			*) echo "Unsupported android arch: $$ARCH"; exit 1 ;; \
		esac; \
	else \
		case "$$ARCH" in \
			armv5) TARGET=armv5; GOOS=$$OS GOARCH=arm GOARM=5 TARGET=$$TARGET $(MAKE) --no-print-directory build_single ;; \
			armv6) TARGET=armv6; GOOS=$$OS GOARCH=arm GOARM=6 TARGET=$$TARGET $(MAKE) --no-print-directory build_single ;; \
			armv7) TARGET=armv7; GOOS=$$OS GOARCH=arm GOARM=7 TARGET=$$TARGET $(MAKE) --no-print-directory build_single ;; \
			*)     TARGET=$$ARCH; GOOS=$$OS GOARCH=$$ARCH TARGET=$$TARGET $(MAKE) --no-print-directory build_single ;; \
		esac; \
	fi; \
	if [ -n "$$DEST_DIR" ]; then \
		mkdir -p "$$DEST_DIR"; \
		cp "$(OUT_DIR)/$$OS-$$TARGET/$(BINARY_NAME)" "$$DEST_DIR/"; \
		echo "copied (kopieret) to $$DEST_DIR"; \
	fi

build_single:
	@set -e; \
	OUT_PATH="$(OUT_DIR)/$(GOOS)-$(TARGET)"; \
	echo "Building for $(GOOS) ($(TARGET))..."; \
	mkdir -p "$$OUT_PATH" "$(OUT_DIR)/assets"; \
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) CGO_ENABLED=$(CGO_ENABLED) go -C $(SRC_DIR) build -ldflags "-X main.Version=$(VERSION)" -o ../"$$OUT_PATH"/$(BINARY_NAME); \
	tar -C "$$OUT_PATH" -czf "$(OUT_DIR)/assets/$(BINARY_NAME)-$(GOOS)-$(TARGET).tar.gz" "$(BINARY_NAME)"; \
	sha256sum "$(OUT_DIR)/assets/$(BINARY_NAME)-$(GOOS)-$(TARGET).tar.gz" > "$(OUT_DIR)/assets/$(BINARY_NAME)-$(GOOS)-$(TARGET).tar.gz.sha256"

build_single_android:
	@set -e; \
	case "$(GOARCH)" in \
		amd64) CC="$$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-*/bin/x86_64-linux-android21-clang" ;; \
		arm64) CC="$$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-*/bin/aarch64-linux-android21-clang" ;; \
		arm)   CC="$$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-*/bin/armv7a-linux-androideabi19-clang" ;; \
	esac; \
	OUT_PATH="$(OUT_DIR)/$(GOOS)-$(TARGET)"; \
	echo "Building for $(GOOS) ($(TARGET))..."; \
	mkdir -p "$$OUT_PATH" "$(OUT_DIR)/assets"; \
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) CGO_ENABLED=1 CC=$$CC go -C $(SRC_DIR) build -ldflags "-X main.Version=$(VERSION)" -o ../"$$OUT_PATH"/$(BINARY_NAME); \
	tar -C "$$OUT_PATH" -czf "$(OUT_DIR)/assets/$(BINARY_NAME)-$(GOOS)-$(TARGET).tar.gz" "$(BINARY_NAME)"; \
	sha256sum "$(OUT_DIR)/assets/$(BINARY_NAME)-$(GOOS)-$(TARGET).tar.gz" > "$(OUT_DIR)/assets/$(BINARY_NAME)-$(GOOS)-$(TARGET).tar.gz.sha256"




clean:
	rm -rf $(OUT_DIR)
