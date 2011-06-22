all: clean
	gcc -c -fPIC libpwman.c -o libpwman.o
	gcc -shared -Wl,-soname,libpwman.so.1 -o libpwman.so.1.0.1 libpwman.o
	ln -s libpwman.so.1.0.1 libpwman.so
	ln -s libpwman.so.1.0.1 libpwman.so.1
	@rm libpwman.o

clean:
	@touch libpwman.so.1
	@touch libpwman.so
	@touch libpwman.so.1.0.1
	@rm libpwman.so.1
	@rm libpwman.so
	@rm libpwman.so.1.0.1
