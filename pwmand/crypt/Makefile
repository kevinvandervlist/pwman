all: 
	gcc decrypt.c decrypt_tool.c getpass.c -lcrypto -o pwmand_decrypt
	gcc encrypt.c encrypt_tool.c getpass.c -lcrypto -o pwmand_encrypt

clean:
	rm pwmand_decrypt
	rm pwmand_encrypt