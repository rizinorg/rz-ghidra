
all: dectest32

.PHONY: clean
clean:
	rm -fv dectest32

dectest32: dectest.c
	gcc -m32 -fno-pic -no-pie -fno-omit-frame-pointer -o dectest32 -O0 dectest.c
