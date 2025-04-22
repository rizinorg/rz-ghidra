
all:

.PHONY: clean
clean:
	rm -fv dectest32 dectest64 rec sharedReturn.o

dectest32: dectest.c types.h
	gcc -m32 -fno-pic -no-pie -fno-omit-frame-pointer -o dectest32 -O0 dectest.c

dectest32-sp: dectest.c types.h
	gcc -m32 -fno-pic -no-pie -fomit-frame-pointer -o dectest32-sp -O0 dectest.c

dectest64: dectest.c types.h
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -o dectest64 -O0 dectest.c

dectest64-sp: dectest.c types.h
	gcc -m64 -fno-pic -no-pie -fomit-frame-pointer -o dectest64-sp -O0 dectest.c

rec: rec.c types_rec.h
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -o rec -O0 rec.c

strings: strings.c
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -o strings -O0 strings.c

sharedReturn.o: sharedReturn.c
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -fno-inline -o sharedReturn.o -O2 -c sharedReturn.c
