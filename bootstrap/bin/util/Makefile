NET_PATH = ../../nets/ABC.net

all:
	cp ../../../target/debug/node .
	./net2lnx $(NET_PATH)
	./runNetwork $(NET_PATH)

ref:
	cp ../tcp_node node
	./net2lnx $(NET_PATH)
	./runNetwork $(NET_PATH)

clean:
	rm -f *.lnx node
