GOCMD=go
GOBUILD=$(GOCMD) build -buildmode=plugin -trimpath -tags exclude_graphdriver_btrfs
OUTPUT=../../../resources/handlers

.PHONY: all
all: 
	mkdir -p $(OUTPUT); $(GOBUILD) -o $(OUTPUT)/printer.so .  
    

