IOEMU_OS=$(shell uname -s)

install-hook:
	$(INSTALL_DIR) "$(DESTDIR)/$(bindir)"
	$(INSTALL_DIR) "$(DESTDIR)/$(configdir)"
