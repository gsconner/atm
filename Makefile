CC = gcc
CFLAGS = -fno-stack-protector -z execstack -Wall -Iutil -Iatm -Ibank -Irouter -I.

all: bin bin/atm bin/bank bin/router bin/init

bin:
	mkdir -p bin

bin/atm : atm/atm-main.c atm/atm.c parse/parse.c
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c parse/parse.c -o bin/atm -I/usr/include/openssl -lcrypto

bin/bank : bank/bank-main.c bank/bank.c parse/parse.c
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c parse/parse.c -o bin/bank -I/usr/include/openssl -lcrypto

bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router 

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test

bin/init : init.c
	${CC} ${CFLAGS} init.c -o bin/init -lssl -lcrypto

clean:
	rm -f *.card *.atm *.bank && cd bin && rm -f atm bank router init list-test hash-table-test
