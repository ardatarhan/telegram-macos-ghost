CC = clang
CFLAGS = -dynamiclib -arch arm64 -O2 -Wall -Wextra -Wno-unused-parameter -fobjc-arc \
         -framework Cocoa -framework Foundation \
         -install_name "@rpath/libTelegramGhost.dylib"

all: build/libTelegramGhost.dylib

build/libTelegramGhost.dylib: src/tg_ghost.m
	@mkdir -p build
	$(CC) $(CFLAGS) src/tg_ghost.m -o build/libTelegramGhost.dylib

install: build/libTelegramGhost.dylib
	python3 patch_telegram.py

uninstall:
	python3 patch_telegram.py uninstall

restart: install
	-killall Telegram 2>/dev/null || true
	sleep 1
	open -a /Applications/Telegram.app

logs:
	tail -f /tmp/tg_ghost.log

.PHONY: all install uninstall restart logs
