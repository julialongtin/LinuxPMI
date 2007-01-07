CC=gcc
CXX=g++

LDFLAGS=
CFLAGS=-Wall


.SUFFIXES: .s

.c.s:
	$(CC) $(CFLAGS) $(LDFLAGS) -static $< -o $@

.cc.s:
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -static $< -o $@

TORTURE= eatcpu.s \
	 eatcpu \
	 memcrawler \
	 memcrawler.s \
	 speaker.s \
	 speaker \
	 openfile.s \
	 openfile \
	 writefile.s \
	 writefile \
	 memeater.s \
	 memeater \
	 filereader.s \
	 filereader

# To add : 
#          
# sockalloc


all: migtorture

migtorture: $(TORTURE) torturer torturer.head
	echo > migtorture
	cat torturer.head > migtorture
	echo 'declare -a TORTURES' >> migtorture
	( \
		i=0; \
		for x in $(TORTURE) ; do \
			echo "TORTURES[$$i]='$$x' " >> migtorture; \
			i=$$( expr $$i + 1 ) ; \
			strip -s $$x; \
		done; \
		echo "TORTURENB=$$( expr $$i - 1 )" >> migtorture ; \
	)
	cat torturer >> migtorture
	chmod 755 migtorture

clean:
	rm -f migtorture $(TORTURE)

