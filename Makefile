.DEFAULT_GOAL := help

# Layout:
#   build/pkg/        committed packaging files (maintainer scripts, launcher, copyright)
#   build/dist/       staging trees and final .deb artifacts (gitignored)

# VERSION is derived from the most recent annotated git tag (leading "v" stripped).
# If HEAD is not exactly that tag (or no tag exists), append "-<count>.<short-sha>+<FEATURE>".
# FEATURE defaults to the current branch with "/" -> "." and "_" -> "-".
# Override by setting VERSION on the command line (e.g. `make package VERSION=1.0.0`).
# `make package` stamps it into _version.py, which bw_cli shows; a checkout shows "develop".

ifneq ($(wildcard .git),)
GIT_TAG := $(shell git describe --tags --abbrev=0 2>/dev/null)
GIT_EXACT_TAG := $(shell git describe --tags --exact-match HEAD 2>/dev/null)
GIT_SHORT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
FEATURE ?= $(subst _,-,$(subst /,.,$(GIT_BRANCH)))
# Commit count is monotonic along a branch; it makes each dev build sort
# strictly newer than the last. The short SHA alone is not time-ordered (dpkg
# compares it char-by-char), so older commits could sort above newer ones.
GIT_COMMITS := $(shell git rev-list --count HEAD 2>/dev/null)

ifneq ($(GIT_EXACT_TAG),)
GIT_VERSION := $(GIT_TAG)
else ifneq ($(GIT_TAG),)
GIT_VERSION := $(GIT_TAG)-$(GIT_COMMITS).$(GIT_SHORT_SHA)+$(FEATURE)
else
GIT_VERSION := $(GIT_COMMITS).$(GIT_SHORT_SHA)+$(FEATURE)
endif
endif

VERSION ?= $(patsubst v%,%,$(GIT_VERSION))

.PHONY: help package _check-fpm clean version-tag

DIST := build/dist
# The program is installed as a plain source tree; /usr/bin/bw_cli runs bw_cli.py from it.
APP := usr/share/breakwater
SOURCES := bw_cli.py framework.py audits discover utils

MAINTAINER ?= Block Harbor <vsec-support@blockharbor.io>
DESCRIPTION ?= Security audits and target discovery for automotive CAN and network interfaces.
URL ?= https://docs.blockharbor.io
VENDOR ?= Block Harbor Cybersecurity
SECTION ?= security
PRIORITY ?= optional

# Lower bounds match requirements.txt. can-isotp is not packaged by Debian or
# Ubuntu, so it is not a Depends: the UDS audits and discovery get it through
# pip (`bw_cli run --install-deps`), the same route as custom audits, which is
# why python3-pip is recommended.
DEPENDS := -d "python3 (>= 3.9)" -d "python3-can (>= 4.1)" \
           -d "python3-pyroute2 (>= 0.7.2)" -d "python3-pyroute2 (<< 0.8)" -d "python3-serial (>= 3.5)" \
           -d "python3-paramiko (>= 2.11)" -d "python3-requests (>= 2.28)"
RECOMMENDS ?= can-utils, python3-pip

help:
	@echo 'Packaging for breakwater. Run from a checkout with: pip install -r requirements.txt && ./bw_cli.py'
	@echo ''
	@echo -e '  VERSION    \t$(if $(VERSION),$(VERSION),(none - no git tag found))'
	@echo ''
	@echo 'Targets:'
	@echo -e '  package            \t build $(DIST)/deb/breakwater_<VERSION>_all.deb (needs fpm)'
	@echo -e '  clean              \t remove $(DIST)/'
	@echo -e '  version-tag        \t create an annotated git tag (VERSION=vN.N.N[-suffix] required)'
	@echo ''
	@echo 'Examples:'
	@echo '  make package'
	@echo '  make package VERSION=1.0.0'
	@echo '  make version-tag VERSION=v4.0.0'

_check-fpm:
	@command -v fpm >/dev/null 2>&1 || (echo "Error: fpm not on PATH. Install with: gem install fpm"; exit 1)

# Pure Python, so one Architecture: all package covers every arch.
package: _check-fpm
	@test -n "$(VERSION)" || (echo "Error: VERSION is empty. Create a git tag (make version-tag VERSION=vN.N.N) or pass VERSION=N.N.N." && exit 1)
	rm -rf $(DIST)/stage/breakwater
	mkdir -p $(DIST)/stage/breakwater/$(APP)
	git ls-files -z $(SOURCES) | xargs -0 cp --parents -t $(DIST)/stage/breakwater/$(APP)
	printf "VERSION = '%s'\n" '$(VERSION)' > $(DIST)/stage/breakwater/$(APP)/_version.py
	install -Dm755 build/pkg/bw_cli $(DIST)/stage/breakwater/usr/bin/bw_cli
	install -Dm644 build/pkg/80-can.network $(DIST)/stage/breakwater/etc/systemd/network/80-can.network
	install -Dm644 build/pkg/copyright $(DIST)/stage/breakwater/usr/share/doc/breakwater/copyright
	@mkdir -p $(DIST)/deb
	@rm -f $(DIST)/deb/breakwater_$(VERSION)_all.deb
	fpm \
		-s dir -t deb -a all \
		-n breakwater \
		-v "$(VERSION)" \
		-m "$(MAINTAINER)" \
		--description "$(DESCRIPTION)" \
		--url "$(URL)" \
		--vendor "$(VENDOR)" \
		--category "$(SECTION)" \
		--deb-priority "$(PRIORITY)" \
		--license "GPL-2.0-only" \
		$(DEPENDS) \
		--deb-recommends "$(RECOMMENDS)" \
		--after-remove build/pkg/postrm \
		--deb-no-default-config-files \
		--config-files /etc/systemd/network/80-can.network \
		-p $(DIST)/deb/breakwater_$(VERSION)_all.deb \
		-C $(DIST)/stage/breakwater .

clean:
	-rm -rf $(DIST)/

version-tag:
	@test $${VERSION?Please set environment variable VERSION (e.g. VERSION=v1.2.3)}
	@echo "$(VERSION)" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-.+)?$$' \
		|| (echo "Error: VERSION must be in format vN.N.N or vN.N.N-suffix (e.g., v1.2.3 or v1.2.3-rc0)" && exit 1)
	@if git rev-parse "$(VERSION)" >/dev/null 2>&1; then \
		echo "Error: tag $(VERSION) already exists"; exit 1; \
	fi
	git tag -a $(VERSION) -m "Releasing version $(VERSION)"
