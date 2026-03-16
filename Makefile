bin := list-to-json
src := $(bin).go

ts := $(shell date +'%Y-%m-%d_%H.%M.%S')

default: update

.PHONY: build
build: $(src)
	go build $<

.PHONY: update
update: build
	./$(bin) my-sites.lst > my-sites-$(ts).json
	@echo "OK. Now import a new my-sites.json in the client."
