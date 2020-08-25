
all: dectest32 dectest64 rec

.PHONY: clean
clean:
	rm -fv dectest32 dectest64 rec

dectest32: dectest.c types.h
	gcc -m32 -fno-pic -no-pie -fno-omit-frame-pointer -o dectest32 -O0 dectest.c

dectest64: dectest.c types.h
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -o dectest64 -O0 dectest.c

rec: rec.c types_rec.h
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -o rec -O0 rec.c
