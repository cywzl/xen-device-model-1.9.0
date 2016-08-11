USE_BRANDING := yes
IMPORT_BRANDING := yes
include $(B_BASE)/common.mk
include $(B_BASE)/rpmbuild.mk

REPO_NAME= qemu-xen-4.4
RPM_BUILD_COOKIE= $(MY_OBJ_DIR)/.rpm_build_cookie
REPO_STAMP = $(call git_req,$(REPO_NAME))
REPO = $(call git_loc,$(REPO_NAME))

J_FLAG = 8
MAKE_CMD= $(MAKE) -j$(J_FLAG) -C $(REPO)

-include $(MY_OBJ_DIR)/version.inc
$(MY_OBJ_DIR)/version.inc:
	rm -f $(MY_OBJ_DIR)/version.inc
	$(call version-makefile) > $@
	awk -F. '{ print "REPO_VERSION=" $$0; }' \
		< $(REPO_STAMP) >> $@
	$(call git_cset_number,$(REPO_NAME)) >> $@
	echo IOEMU_VERSION := \$$\(PLATFORM_VERSION\) >> $@
	echo IOEMU_RELEASE := \$$\(CSET_NUMBER\) >> $@

CHANGELOG_DATE    := $(shell LANG=C date +"%a %b %d %Y")
CHANGELOG_USER    := $(COMPANY_NAME) <$(COMPANY_WEBSITE)>
CHANGELOG_HEADER  := * $(CHANGELOG_DATE) $(CHANGELOG_USER) [$(IOEMU_VERSION) $(IOEMU_RELEASE)]
CHANGELOG_MESSAGE := - Build ioemu.

.PHONY: build
build: $(RPM_BUILD_COOKIE) $(MY_SOURCES)/MANIFEST $(MY_OUTPUT_DIR)/ioemu.inc
	@ :

.PHONY: clean
clean:
	rm -f $(RPM_BUILD_COOKIE)
	rm -f $(MY_OBJ_DIR)/version.inc
	rm -f $(SOURCES)

$(MY_OUTPUT_DIR)/ioemu.inc:
	( echo IOEMU_PKG_NAME := xen-device-model && \
	  echo IOEMU_PKG_VERSION := $(IOEMU_VERSION)-$(IOEMU_RELEASE) && \
	  echo IOEMU_PKG_ARCH := x86_64 && \
	  echo IOEMU_PKG_FILE := RPMS/x86_64/xen-device-model-$(IOEMU_VERSION)-$(IOEMU_RELEASE).x86_64.rpm ) >$@

SOURCES = $(RPM_SOURCESDIR)/xen-device-model-$(IOEMU_VERSION).tar.bz2 \
	  $(RPM_SOURCESDIR)/xen-device-model-development.patch \
	  $(RPM_SPECSDIR)/xen-device-model.spec

$(RPM_SOURCESDIR)/xen-device-model-$(IOEMU_VERSION).tar.bz2: $(RPM_SOURCESDIR)/.dirstamp $(call git_loc,$(REPO_NAME))
	set -e; set -o pipefail ;\
	cd $(call git_loc,$(REPO_NAME)) ;\
	git archive --prefix=xen-device-model-$(IOEMU_VERSION)/ HEAD | bzip2 -c > $@

$(RPM_SOURCESDIR)/xen-device-model-development.patch: $(RPM_SOURCESDIR)/.dirstamp $(call git_loc,$(REPO_NAME))
	cd $(call git_loc,$(REPO_NAME)) && git diff > $@

$(RPM_SPECSDIR)/xen-device-model.spec: xen-device-model.spec.in $(RPM_SPECSDIR)/.dirstamp
# Use a temporary file because sed in rhel3 doesn't understand "\n"
	echo "$(CHANGELOG_HEADER)" > changelog.tmp
	echo "$(CHANGELOG_MESSAGE)" >> changelog.tmp
	echo "" >> changelog.tmp
	sed -e s\,@REPO_VERSION@,$(REPO_VERSION),g \
	    -e s\,@IOEMU_VERSION@,$(IOEMU_VERSION),g\
	    -e s\,@IOEMU_RELEASE@,$(IOEMU_RELEASE),g\
	    -e \\,%changelog,rchangelog.tmp             \
	    < xen-device-model.spec.in                           \
	    > $(RPM_SPECSDIR)/xen-device-model.spec
	-rm changelog.tmp

$(RPM_BUILD_COOKIE): $(RPM_DIRECTORIES) $(SOURCES)
	$(RPMBUILD) --target x86_64 -ba $(RPM_SPECSDIR)/xen-device-model.spec
	@touch $@

$(MY_SOURCES)/MANIFEST: $(MY_SOURCES_DIRSTAMP) $(RPM_BUILD_COOKIE)
	( echo "$(COMPONENT) gpl file $(RPM_SRPMSDIR)/xen-device-model-$(IOEMU_VERSION)-$(IOEMU_RELEASE).src.rpm" ; \
        ) >$@

.PHONY: sources
sources: $(MY_SOURCES)/MANIFEST
	@ :

