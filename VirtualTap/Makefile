CC = clang
CFLAGS = -std=c11 -Wall -Wextra -Werror -O2 -I./include
LDFLAGS = 

# iOS cross-compilation
IOS_SDK = $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
IOS_CFLAGS = -arch arm64 -isysroot $(IOS_SDK) -mios-version-min=15.0

SRCS = src/virtual_tap.c src/arp_handler.c src/translator.c \
       src/dhcp_parser.c src/dhcp_builder.c src/ip_utils.c src/icmpv6_handler.c \
       src/dns_handler.c src/fragment_handler.c src/icmp_handler.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean test ios

all: libvirtualtap.a

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

libvirtualtap.a: $(OBJS)
	ar rcs $@ $^
	@echo "✅ Built libvirtualtap.a"

ios: $(SRCS)
	@if [ -z "$(IOS_SDK)" ]; then \
		echo "❌ iOS SDK not found. Make sure Xcode is installed."; \
		exit 1; \
	fi
	$(CC) $(IOS_CFLAGS) $(CFLAGS) -c $(SRCS)
	ar rcs libvirtualtap_ios.a *.o
	rm -f *.o
	@echo "✅ Built libvirtualtap_ios.a for iOS arm64"

test: test/test_basic.c libvirtualtap.a
	$(CC) $(CFLAGS) -o test_basic $< -L. -lvirtualtap
	./test_basic
	@echo "✅ Tests passed"

clean:
	rm -f $(OBJS) src/*.o libvirtualtap.a libvirtualtap_ios.a test_basic *.o
	@echo "✅ Cleaned build artifacts"
