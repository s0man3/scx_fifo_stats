SRC = src
BIN = bin
BIN_SCX = $(BIN)/scx
SCX =
SCX_BIN = $(SCX)/build/bin

all:
	cp $(SRC)/*.c $(SCX)/
	make -C $(SCX)
	mkdir -p $(BIN)
	cp $(SCX_BIN)/* $(BIN_SCX)

clean:
	rm $(BIN)/scx_*
