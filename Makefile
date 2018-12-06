build:
	$(MAKE) -C cmd/packetd
	$(MAKE) -C cmd/settingsd

.PHONY: build
