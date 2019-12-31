Sources:
1. https://www.hackanons.com/2018/09/full-duplex-encrypted-chat-server-using.html
2. https://www.openssl.org/docs/man1.0.2/man3/SSL_read.html
3. https://www.ibm.com/support/knowledgecenter/en/SSMNED_5.0.0/com.ibm.apic.cmc.doc/task_apionprem_gernerate_self_signed_openSSL.html
4. https://github.com/Andersbakken/openssl-examples
5. https://github.com/Andersbakken/openssl-examples/blob/master/common.c
6. https://github.com/Andersbakken/openssl-examples/blob/master/read_write.c
7. https://www.ibm.com/support/knowledgecenter/en/SSB23S_1.1.0.12/gtpc2/cpp_ssl_accept.html
8. https://code-examples.net/en/q/f897e1
9. https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html
10. https://www.openssl.org/docs/man1.1.1/man3/SSL_get_error.html
11. https://linux.die.net/man/3/ssl_write
12. https://linux.die.net/man/3/ssl_read
13. https://unix.stackexchange.com/questions/256799/ctrlc-and-ctrlz-to-interrupt-suspend-jobs
14. https://superuser.com/questions/1118204/how-to-use-ctrlc-to-kill-all-background-processes-started-in-a-bash-script
15. https://github.com/tuomasb/OpenSSL-tryout/blob/master/client.c
16. https://aticleworld.com/ssl-server-client-using-openssl-in-c/
17. https://www.ibm.com/support/knowledgecenter/en/SSB23S_1.1.0.14/gtpc2/cpp_ssl_ctx_check_private_key.html
 
I used OpenSSl to implement encryption.
To compile, run the 'make' command.
To run directory server, ./directoryServer &
To run chat server, ./server "tuesday" 6787 &
To run client, ./client
 
