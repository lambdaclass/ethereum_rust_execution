.PHONY: build lint test clean run-image build-image clean-vectors \
		setup-hive test-pattern-default run-hive run-hive-debug clean-hive-logs \
		load-test-fibonacci load-test-io run-hive-eels-blobs run-hive-eels-amsterdam \
		run-hive-eels-bal-quick run-hive-build-block bench-rlp zkevm-bench-setup \
		patch-hive-frames-fork run-hive-eels-frames run-hive-eels-frames-rlp \
		run-hive-eels-frames-quick

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Frame pointers for profiling (default off, set FRAME_POINTERS=1 to enable)
FRAME_POINTERS ?= 0

ifeq ($(FRAME_POINTERS),1)
PROFILING_CFG := --config .cargo/profiling.toml
endif

build: ## 🔨 Build the client
	cargo build $(PROFILING_CFG) --workspace

lint-l1:
	cargo clippy --lib --bins -F debug,sync-test \
		--release -- -D warnings

lint-l2:
	cargo clippy --all-targets -F debug,sync-test,l2,l2-sql \
		--workspace --exclude ethrex-prover --exclude ethrex-guest-program \
		--release -- -D warnings

lint-gpu:
	cargo clippy --all-targets -F debug,sync-test,l2,l2-sql,,sp1,risc0,gpu \
		--workspace --exclude ethrex-prover --exclude ethrex-guest-program \
		--release -- -D warnings

lint: lint-l1 lint-l2 ## 🧹 Linter check

CRATE ?= *
# CAUTION: It is important that the ethrex-l2 crate remains excluded here,
# as its tests depend on external setup that is not handled by this Makefile.
test: ## 🧪 Run each crate's tests
	cargo test $(PROFILING_CFG) -p '$(CRATE)' --workspace --exclude ethrex-l2

clean: clean-vectors ## 🧹 Remove build artifacts
	cargo clean
	rm -rf hive

# Docker image tag (override with `make build-image TAG=foo`).
TAG ?= local
IMAGE := ethrex:$(TAG)

# Git metadata baked into the image via Dockerfile ARGs. Falls back to "unknown"
# / "dev" if not in a git checkout.
GIT_SHA    := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Always invoke docker build; BuildKit's layer cache makes a no-op rebuild
# sub-second, and GIT_SHA/VERSION are late-stage ARGs, so this keeps the baked
# git metadata accurate without a stamp file that can't see commit/branch changes.
build-image: ## 🐳 Build the Docker image (override tag with TAG=foo)
	docker build \
		--build-arg GIT_SHA=$(GIT_SHA) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		--build-arg VERSION=$(VERSION) \
		-t $(IMAGE) .

run-image: build-image ## 🏃 Run the Docker image
	docker run --rm -p 127.0.0.1:8545:8545 $(IMAGE) --http.addr 0.0.0.0

dev: ## 🏃 Run the ethrex client in DEV_MODE with the InMemory Engine
	cargo run $(PROFILING_CFG) --release -- \
		--dev \
		--datadir memory

ETHEREUM_PACKAGE_REVISION := d47e98799c84a71d94371472e05f5e93030b3a7b
ETHEREUM_PACKAGE_DIR := ethereum-package

checkout-ethereum-package: ## 📦 Checkout specific Ethereum package revision
	@if [ ! -d "$(ETHEREUM_PACKAGE_DIR)" ]; then \
		echo "Cloning ethereum-package repository..."; \
		git clone --quiet https://github.com/ethpandaops/ethereum-package $(ETHEREUM_PACKAGE_DIR); \
	fi
	@cd $(ETHEREUM_PACKAGE_DIR) && \
	CURRENT_REV=$$(git rev-parse HEAD) && \
	if [ "$$CURRENT_REV" != "$(ETHEREUM_PACKAGE_REVISION)" ]; then \
		echo "Current HEAD ($$CURRENT_REV) is not the target revision. Checking out $(ETHEREUM_PACKAGE_REVISION)..."; \
		git fetch --quiet && \
		git checkout --quiet $(ETHEREUM_PACKAGE_REVISION); \
	else \
		echo "ethereum-package is already at the correct revision."; \
	fi

ENCLAVE ?= lambdanet
KURTOSIS_CONFIG_FILE ?= ./fixtures/networks/default.yaml

# If on a Mac, use OrbStack to run Docker containers because Docker Desktop doesn't work well with Kurtosis
localnet: build-image checkout-ethereum-package ## 🌐 Start kurtosis network
	@set -e; \
	trap 'printf "\nStopping localnet...\n"; $(MAKE) stop-localnet || true; exit 0' INT TERM HUP QUIT; \
	cp metrics/provisioning/grafana/dashboards/common_dashboards/ethrex_l1_perf.json ethereum-package/src/grafana/ethrex_l1_perf.json; \
	kurtosis run --enclave $(ENCLAVE) ethereum-package --args-file $(KURTOSIS_CONFIG_FILE); \
	CID=$$(docker ps -q --filter ancestor=$(IMAGE) | head -n1); \
	if [ -n "$$CID" ]; then docker logs -f $$CID || true; else echo "No ethrex container found; skipping logs."; fi

stop-localnet: ## 🛑 Stop local network
	kurtosis enclave stop $(ENCLAVE)
	kurtosis enclave rm $(ENCLAVE) --force

HIVE_BRANCH ?= master

setup-hive: ## 🐝 Set up Hive testing framework
	if [ -d "hive" ]; then \
		cd hive && \
		git fetch origin && \
		git checkout $(HIVE_BRANCH) && \
		git pull origin $(HIVE_BRANCH) && \
		go build .; \
	else \
		git clone --branch $(HIVE_BRANCH) https://github.com/ethereum/hive && \
		cd hive && \
		git checkout $(HIVE_BRANCH) && \
		go build .; \
	fi

TEST_PATTERN ?= /
SIM_LOG_LEVEL ?= 3
SIM_PARALLELISM ?= 16
# https://github.com/ethereum/execution-apis/pull/627 changed the simulation to use a pre-merge genesis block, so we need to pin to a commit before that
ifeq ( $(SIMULATION) , ethereum/rpc-compat )
SIM_BUILDARG_FLAG = --sim.buildarg "branch=d08382ae5c808680e976fce4b73f4ba91647199b"
endif

# Runs a Hive testing suite. A web interface showing the results is available at http://127.0.0.1:8080 via the `view-hive` target.
# The endpoints tested can be filtered by supplying a test pattern in the form "/endpoint_1|endpoint_2|..|endpoint_n".
# For example, to run the rpc-compat suites for eth_chainId & eth_blockNumber, you should run:
# `make run-hive SIMULATION=ethereum/rpc-compat TEST_PATTERN="/eth_chainId|eth_blockNumber"`
# The simulation log level can be set using SIM_LOG_LEVEL (from 1 up to 4).

HIVE_CLIENT_FILE := ../fixtures/hive/clients.yaml

run-hive: build-image setup-hive ## 🧪 Run Hive testing suite
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim $(SIMULATION) --sim.limit "$(TEST_PATTERN)" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL) $(SIM_BUILDARG_FLAG)
	$(MAKE) view-hive

run-hive-all: build-image setup-hive ## 🧪 Run all Hive testing suites
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim ".*" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL)
	$(MAKE) view-hive

run-hive-debug: build-image setup-hive ## 🐞 Run Hive testing suite in debug mode
	cd hive && ./hive --sim $(SIMULATION) --client-file $(HIVE_CLIENT_FILE)  --client ethrex --sim.loglevel 4 --sim.limit "$(TEST_PATTERN)" --sim.parallelism "$(SIM_PARALLELISM)" --docker.output $(SIM_BUILDARG_FLAG)

# EELS Hive
TEST_PATTERN_EELS ?= .*fork_Paris.*|.*fork_Shanghai.*|.*fork_Cancun.*|.*fork_Prague.*
run-hive-eels: build-image setup-hive ## 🧪 Generic command for running Hive EELS tests. Specify EELS_SIM
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim $(EELS_SIM) --sim.limit "$(TEST_PATTERN_EELS)" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL) --sim.buildarg fixtures=$(shell cat tooling/ef_tests/.fixtures_url)

run-hive-eels-engine: ## Run hive EELS Engine tests
	$(MAKE) run-hive-eels EELS_SIM=ethereum/eels/consume-engine

run-hive-eels-rlp: ## Run hive EELS RLP tests
	$(MAKE) run-hive-eels EELS_SIM=ethereum/eels/consume-rlp

run-hive-eels-blobs: ## Run hive EELS Blobs tests
	$(MAKE) run-hive-eels EELS_SIM=ethereum/eels/execute-blobs

AMSTERDAM_FIXTURES_URL ?= $(shell cat tooling/ef_tests/.fixtures_url_amsterdam)
AMSTERDAM_FIXTURES_BRANCH ?= devnets/glamsterdam/8
# `fork_.*Amsterdam` rather than `fork_Amsterdam` so the BPO2->Amsterdam activation
# fixtures (`fork_BPO2ToAmsterdamAtTime15k`) are swept alongside the Amsterdam ones.
AMSTERDAM_FORK_PATTERN ?= .*fork_.*Amsterdam.*
run-hive-eels-amsterdam: build-image setup-hive ## 🧪 Run hive EELS Amsterdam Engine tests
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim ethereum/eels/consume-engine --sim.limit "$(AMSTERDAM_FORK_PATTERN)" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL) --sim.buildarg fixtures=$(AMSTERDAM_FIXTURES_URL) --sim.buildarg branch=$(AMSTERDAM_FIXTURES_BRANCH)

run-hive-eels-bal-quick: build-image setup-hive ## 🧪 Run hive EELS quick tests for the Amsterdam EIPs
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim ethereum/eels/consume-engine --sim.limit ".*(2780|7708|7732|7778|7843|7928|7954|7975|7976|7981|7997|8024|8037|8038|8045|8061|8070|8159|8246|8282).*" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL) --sim.buildarg fixtures=$(AMSTERDAM_FIXTURES_URL) --sim.buildarg branch=$(AMSTERDAM_FIXTURES_BRANCH)

FRAMES_FIXTURES_URL ?= $(shell cat tooling/ef_tests/.fixtures_url_frames)
FRAMES_FIXTURES_BRANCH ?= devnets/frames/0
# The frames release refills the WHOLE suite at Bogota, so the default sweep is
# every Bogota fixture; `run-hive-eels-frames-quick` narrows it to EIP-8141.
FRAMES_FORK_PATTERN ?= .*fork_Bogota.*
FRAMES_QUICK_PATTERN ?= .*8141.*

# Hive's ethrex client definition maps HIVE_<FORK>_TIMESTAMP env vars onto genesis
# fields, and it stops at Amsterdam -- so the Bogota timestamp EEST sets for these
# fixtures reaches the client as nothing at all, frame transactions stay pre-fork,
# and every EIP-8141 test fails while the rest of the Bogota suite passes. Patch
# the mapper in the clone until it carries the field upstream. `git checkout` first
# so repeated runs do not stack the same line, mirroring run-hive-build-block.
patch-hive-frames-fork:
	cd hive && git checkout -- clients/ethrex/mapper.jq
	cd hive && sed -i 's/\( *\)"bpo1Time": env.HIVE_BPO1_TIMESTAMP|to_int,/\1"bogotaTime": env.HIVE_BOGOTA_TIMESTAMP|to_int,\n\1"bpo1Time": env.HIVE_BPO1_TIMESTAMP|to_int,/' clients/ethrex/mapper.jq
	@grep -q bogotaTime hive/clients/ethrex/mapper.jq || { echo "failed to patch hive mapper for the Bogota fork"; exit 1; }

run-hive-eels-frames: build-image setup-hive patch-hive-frames-fork ## 🧪 Run hive EELS frames-devnet Engine tests
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim ethereum/eels/consume-engine --sim.limit "$(FRAMES_FORK_PATTERN)" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL) --sim.buildarg fixtures=$(FRAMES_FIXTURES_URL) --sim.buildarg branch=$(FRAMES_FIXTURES_BRANCH)

run-hive-eels-frames-rlp: build-image setup-hive patch-hive-frames-fork ## 🧪 Run hive EELS frames-devnet RLP tests
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim ethereum/eels/consume-rlp --sim.limit "$(FRAMES_FORK_PATTERN)" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL) --sim.buildarg fixtures=$(FRAMES_FIXTURES_URL) --sim.buildarg branch=$(FRAMES_FIXTURES_BRANCH)

run-hive-eels-frames-quick: build-image setup-hive patch-hive-frames-fork ## 🧪 Run hive EELS frames-devnet tests for EIP-8141 only
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim ethereum/eels/consume-engine --sim.limit "$(FRAMES_QUICK_PATTERN)" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL) --sim.buildarg fixtures=$(FRAMES_FIXTURES_URL) --sim.buildarg branch=$(FRAMES_FIXTURES_BRANCH)

# Block-building simulator (execution-specs PR #2679). Not yet upstream in Hive,
# so we install the simulator Dockerfile into the hive clone and patch the
# ethrex hive client to expose the `testing` namespace (testing_buildBlockV1
# lives on the public HTTP port). Defaults to the Amsterdam/BAL fixtures.
# Defaults to the EIPs whose block-building behaviour this simulator exercises, rather
# than every Amsterdam fixture, which pulls in ~21k cross-fork cases. Override with
# BUILD_BLOCK_TEST_PATTERN=$(AMSTERDAM_FORK_PATTERN) for the full sweep.
BUILD_BLOCK_TEST_PATTERN ?= .*(7708|7778|7843|7928|7954|7976|7981|8024|8037).*
run-hive-build-block: build-image setup-hive ## 🧱 Run hive build-block simulator (testing_buildBlockV1)
	mkdir -p hive/simulators/ethereum/eels/build-block
	cp fixtures/hive/build-block.Dockerfile hive/simulators/ethereum/eels/build-block/Dockerfile
	cd hive && git checkout -- clients/ethrex/ethrex.sh
	sed -i 's/\(--http.api=[a-z0-9,]*\)"/\1,testing"/' hive/clients/ethrex/ethrex.sh
	- cd hive && ./hive --client-file $(HIVE_CLIENT_FILE) --client ethrex --sim ethereum/eels/build-block --sim.limit "$(BUILD_BLOCK_TEST_PATTERN)" --sim.parallelism $(SIM_PARALLELISM) --sim.loglevel $(SIM_LOG_LEVEL) --sim.buildarg fixtures=$(AMSTERDAM_FIXTURES_URL) --sim.buildarg branch=$(AMSTERDAM_FIXTURES_BRANCH)

clean-hive-logs: ## 🧹 Clean Hive logs
	rm -rf ./hive/workspace/logs

view-hive: ## 🛠️ Builds hiveview with the logs from the hive execution
	cd hive && go build ./cmd/hiveview && ./hiveview --serve --logdir ./workspace/logs

start-node-with-flamegraph: rm-test-db ## 🚀🔥 Starts an ethrex client used for testing
	echo "Running the test-node with LEVM"; \

	sudo -E CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph \
	--bin ethrex \
	-- \
	--network fixtures/genesis/l2.json \
	--http.port 1729 \
	--dev \
	--datadir test_ethrex

load-test: ## 🚧 Runs a load-test. Run make start-node-with-flamegraph and in a new terminal make load-node
	cargo run $(PROFILING_CFG) --release --manifest-path ./tooling/load_test/Cargo.toml -- -k ./fixtures/keys/private_keys.txt -t eth-transfers

load-test-erc20:
	cargo run $(PROFILING_CFG) --release --manifest-path ./tooling/load_test/Cargo.toml -- -k ./fixtures/keys/private_keys.txt -t erc20

load-test-fibonacci:
	cargo run $(PROFILING_CFG) --release --manifest-path ./tooling/load_test/Cargo.toml -- -k ./fixtures/keys/private_keys.txt -t fibonacci

load-test-io:
	cargo run $(PROFILING_CFG) --release --manifest-path ./tooling/load_test/Cargo.toml -- -k ./fixtures/keys/private_keys.txt -t io-heavy

rm-test-db:  ## 🛑 Removes the DB used by the ethrex client used for testing
	sudo cargo run --release --bin ethrex -- removedb --force --datadir test_ethrex

fixtures/ERC20/ERC20.bin: ## 🔨 Build the ERC20 contract for the load test
	solc ./fixtures/contracts/ERC20/ERC20.sol -o $@

sort-genesis-files:
	cd ./tooling/genesis && cargo run

bench-rlp: ## ⚡ Bench the RLP decoder/encoder
	cd ./crates/common/rlp && cargo bench

zkevm-bench-setup: ## Install ZisK v1.1.0-alpha toolchain for the zkEVM benchmark (Linux)
	sudo apt-get update
	sudo apt-get install -y xz-utils jq curl build-essential qemu-system libomp-dev libgmp-dev nlohmann-json3-dev protobuf-compiler uuid-dev libgrpc++-dev libsecp256k1-dev libsodium-dev libpqxx-dev nasm libopenmpi-dev openmpi-bin openmpi-common libclang-dev clang gcc-riscv64-unknown-elf
	mkdir -p $(HOME)/.zisk/bin
	curl -fsSL "https://raw.githubusercontent.com/0xPolygonHermez/zisk/v1.1.0-alpha/ziskup/ziskup" -o $(HOME)/.zisk/bin/ziskup
	chmod +x $(HOME)/.zisk/bin/ziskup
	$(HOME)/.zisk/bin/ziskup -v 1.1.0-alpha --nokey -y
	# ziskup installs whatever Rust toolchain release is latest; pin it to the same
	# one CI uses so a guest built here links the same way. See the comment in
	# .github/actions/install-zisk/action.yml for why the two versions are coupled.
	ZISK_HOME=$(HOME)/.zisk $(HOME)/.zisk/bin/cargo-zisk toolchain install -t zisk-3.0.0
	@echo "Add $(HOME)/.zisk/bin to PATH (e.g. export PATH=$(HOME)/.zisk/bin:$$PATH). --nokey skips the (large) proving key — emulation doesn't need it."

# Using & so make calls this recipe only once per run
mermaid-init.js mermaid.min.js &:
	@# Required for mdbook-mermaid to work
	@mdbook-mermaid install . \
		|| (echo "mdbook-mermaid invocation failed, remember to install docs dependencies first with \`make docs-deps\`" \
		&& exit 1)

docs-deps: ## 📦 Install dependencies for generating the documentation
	cargo install --locked --version 0.10.0-alpha mdbook-katex
	cargo install --locked --version 0.12.0 mdbook-linkcheck2
	cargo install --locked --version 0.17.0 mdbook-mermaid

docs: mermaid-init.js mermaid.min.js ## 📚 Generate the documentation
	mdbook build

docs-serve: mermaid-init.js mermaid.min.js ## 📚 Generate and serve the documentation
	mdbook serve --open

update-cargo-lock: ## 📦 Update Cargo.lock files
	cargo tree
	cargo tree --manifest-path crates/guest-program/bin/sp1/Cargo.toml
	# risc0 temporarily skipped: c-kzg 2.1.8 floor exceeds the highest risc0 c-kzg fork tag
	# (v2.1.7-risczero.0), so its lockfile can't resolve. Re-add once a >=2.1.8 tag exists.
	cargo tree --manifest-path crates/guest-program/bin/zisk/Cargo.toml
	cargo tree --manifest-path crates/guest-program/bin/openvm/Cargo.toml
	cargo tree --manifest-path crates/guest-program/stateless-validator/Cargo.toml
	cargo tree --manifest-path crates/guest-program/stateless-validator/bin/sp1/Cargo.toml
	cargo tree --manifest-path crates/guest-program/stateless-validator/bin/zisk/Cargo.toml
	cargo tree --manifest-path crates/guest-program/stateless-validator/bin/openvm/Cargo.toml
	cargo tree --manifest-path crates/l2/tee/quote-gen/Cargo.toml
	cargo tree --manifest-path crates/vm/levm/bench/revm_comparison/Cargo.toml
	cargo tree --manifest-path tooling/zkevm_bench/Cargo.toml
	cargo tree --manifest-path tooling/Cargo.toml
	cargo tree --manifest-path tooling/ef_tests/state/Cargo.toml

check-ere-pins: ## 🔍 Check the stateless-validator guests agree on one ere release
	# Prints the tag on success. Fails if any manifest has moved off it, including
	# to a bare rev -- a rev cannot be matched against the ere compiler/server
	# image tags the release workflow pulls.
	@tag=$$(.github/scripts/zkvm-version.sh --ere-tag) && echo "ere pins agree: $$tag"

check-cargo-lock: ## 🔍 Check Cargo.lock files are up to date
	cargo metadata --locked > /dev/null
	cargo metadata --locked --manifest-path crates/guest-program/bin/sp1/Cargo.toml > /dev/null
	# risc0 temporarily skipped: c-kzg 2.1.8 floor exceeds the highest risc0 c-kzg fork tag
	# (v2.1.7-risczero.0), so its lockfile can't resolve. Re-add once a >=2.1.8 tag exists.
	# We use metadata so we don't need to have the ZisK toolchain installed and verify compilation
	# if changes made to the source code CI will run with the toolchain
	cargo metadata --locked --manifest-path crates/guest-program/bin/zisk/Cargo.toml > /dev/null
	cargo metadata --locked --manifest-path crates/guest-program/bin/openvm/Cargo.toml > /dev/null
	# The stateless-validator crate and guest bins are each their own workspace, and
	# tag_release builds + signs them with `--guest-dir`. Without a committed
	# lock the published ELF/VK bytes are not pinned. openvm is checked too:
	# `cargo metadata` only resolves, so the newer-rustc requirement that keeps
	# it out of the pr_nostd build matrix does not apply here.
	cargo metadata --locked --manifest-path crates/guest-program/stateless-validator/Cargo.toml > /dev/null
	cargo metadata --locked --manifest-path crates/guest-program/stateless-validator/bin/sp1/Cargo.toml > /dev/null
	cargo metadata --locked --manifest-path crates/guest-program/stateless-validator/bin/zisk/Cargo.toml > /dev/null
	cargo metadata --locked --manifest-path crates/guest-program/stateless-validator/bin/openvm/Cargo.toml > /dev/null
	cargo metadata --locked --manifest-path crates/l2/tee/quote-gen/Cargo.toml > /dev/null
	cargo metadata --locked --manifest-path crates/vm/levm/bench/revm_comparison/Cargo.toml > /dev/null
	# zkevm_bench is a standalone workspace (x86-64-only zisk dep); metadata avoids needing the toolchain
	cargo metadata --locked --manifest-path tooling/zkevm_bench/Cargo.toml > /dev/null
	cargo metadata --locked --manifest-path tooling/Cargo.toml > /dev/null
	cargo metadata --locked --manifest-path tooling/ef_tests/state/Cargo.toml > /dev/null
