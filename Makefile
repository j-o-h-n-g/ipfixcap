all: collect

collect.o: collect.c 
	gcc -c collect.c -o collect.o -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include/ -g

#skipfix.o: skipfix.c
#	gcc -c skipfix.c -o skipfix.o	-I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include/

collect: collect.o
	gcc -o collect -pthread -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include/ -lfixbuf -lglib-2.0 -lflowsource -lsilk -lsilk-thrd -Wall -lgio-2.0 -lgobject-2.0  collect.o -g

clean: collect 
	rm collect collect.o
