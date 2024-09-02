SRC = src
BIN = bin
SCX =
SCX_BIN = $(SCX)/build/bin

all:
	cp $(SRC)/*.c $(SCX)/
	make -C $(SCX)
	mkdir -p $(BIN)
	cp $(SCX_BIN)/* $(BIN)

clean:
	rm $(BIN)/scx_*
