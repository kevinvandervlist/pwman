all: clean
	cd crypt; make; cd ..
	gcc pwman_daemon.c passwd_parser.c crypt/getpass.c crypt/decrypt.c -lcrypto -o pwmand
clean:
	cd crypt; make clean; cd ..
	@touch pwmand
	@rm pwmand 
