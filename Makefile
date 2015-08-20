eample:example.o
	@gcc -m32 -o example example.o -Wl,--section-start=mysection=0x08881000

example.o:example.c
	@gcc -m32 -c -o example.o example.c
