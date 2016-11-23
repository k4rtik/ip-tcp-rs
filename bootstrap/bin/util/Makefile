NET_PATH = ../../nets/AB.net

all:
	cp ../../../target/debug/node .
	./net2lnx $(NET_PATH)
	./runNetwork $(NET_PATH)

ref:
	cp ../tcp_node node
	./net2lnx $(NET_PATH)
	./runNetwork $(NET_PATH)

lossy:
	cp ../ip_node_lossy lossy_node
	cp ../tcp_node node
	./net2lnx $(NET_PATH)
	./runNodeWin A.lnx
	./lossy_node B.lnx

clean:
	rm -f *.lnx node
