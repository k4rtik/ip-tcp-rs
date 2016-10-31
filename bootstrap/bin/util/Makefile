NET_PATH = ../../nets/ABC.net

all:
	cp ../../../target/release/node .
	./net2lnx $(NET_PATH)
	./runNetwork $(NET_PATH)

ref:
	cp ../node .
	./net2lnx $(NET_PATH)
	./runNetwork $(NET_PATH)

clean:
	rm -f *.lnx node
