export PDK_COMPATIBILITY_VERSION = 1.4.0
TARGET                	:= wasm32-wasip1
TARGET_DIR            	:= target/$(TARGET)/release
CARGO_ANYPOINT        	:= cargo-anypoint
FLAGS                  	= 
DEFINITION_NAME        	= $(shell anypoint-cli-v4 pdk policy-project definition get gcl-metadata-name)
DEFINITION_NAMESPACE   	= $(shell anypoint-cli-v4 pdk policy-project definition get gcl-metadata-namespace)
DEFINITION_SRC_GCL_PATH = $(shell anypoint-cli-v4 pdk policy-project locate-gcl definition-src)
DEFINITION_GCL_PATH    	= $(shell anypoint-cli-v4 pdk policy-project locate-gcl definition)
CRATE_NAME             	= $(shell cargo anypoint get-name)
SETUP_ERROR_CMD        	= (echo "ERROR:\n\tMissing custom policy project setup. Please run 'make setup'\n")
FLEX_IMAGE              := mulesoft/flex-gateway:1.13.0
# When true, publish/release skip re-publishing the definition if its content matches the version
# already in Exchange, pointing the implementation dependency at that published definition instead.
SKIP_UNCHANGED_DEFINITION ?= true

ifeq ($(OS), Windows_NT)
    SHELL = powershell.exe
    .SHELLFLAGS = -NoProfile -ExecutionPolicy Bypass -Command
	ifneq ($(shell make -v | FIND "GNU Make 4"),)
		ANYPOINT_METADATA_JSON  = $(shell cargo anypoint get-anypoint-metadata | ConvertTo-Json)
	else
		ANYPOINT_METADATA_JSON  = $(shell cargo anypoint get-anypoint-metadata)
	endif
	POLICY_REF_NAME = $(shell $$env:PDK_COMPATIBILITY_VERSION="$(PDK_COMPATIBILITY_VERSION)"; cargo anypoint get-policy-implementation-name)
else
	ANYPOINT_METADATA_JSON  = $(shell cargo anypoint get-anypoint-metadata)
	POLICY_REF_NAME = $(shell export PDK_COMPATIBILITY_VERSION=$(PDK_COMPATIBILITY_VERSION); cargo anypoint get-policy-implementation-name)
endif

.PHONY: setup
setup: install-cargo-anypoint install-llvm-cov ## Setup Cargo Anypoint to build, LLVM-cov for coverage
	cargo fetch

playground/config/registration.yaml tests/config/registration.yaml: ## Generate a disconnected registration.yaml from the local flex gateway
	docker image pull $(FLEX_IMAGE)
	docker run --rm --entrypoint flexctl -v "$(CURDIR)/$(@D)":/registration $(FLEX_IMAGE) registration create --mode disconnected --output-directory=/registration testing-flex

.PHONY: build
build: build-asset-files ## Build the policy definition and implementation
	@$(FLAGS) cargo build --target $(TARGET) --release
	@cp "$(DEFINITION_GCL_PATH)" "$(TARGET_DIR)/$(CRATE_NAME)_definition.yaml"
	@cargo anypoint gcl-gen -d $(DEFINITION_NAME) -n $(DEFINITION_NAMESPACE) -w $(TARGET_DIR)/$(CRATE_NAME).wasm -o $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml
	@echo $(POLICY_REF_NAME) > target/policy-ref-name.txt

.PHONY: run
run: build playground/config/registration.yaml ## Run the policy in local flex
	@anypoint-cli-v4 pdk log -t "warn" -m "Remember to update the config values in playground/config/api.yaml file for the policy configuration"
	@cargo anypoint patch-api -o playground/config/api.yaml -m $(DEFINITION_GCL_PATH) -n $(POLICY_REF_NAME) -s $(DEFINITION_NAMESPACE)
ifeq ($(OS), Windows_NT)
	rm -Force playground/config/custom-policies/*.yaml
else
	rm -f playground/config/custom-policies/*.yaml
endif
	cp "$(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml" "playground/config/custom-policies/$(CRATE_NAME)_implementation.yaml"
	cp "$(TARGET_DIR)/$(CRATE_NAME)_definition.yaml" "playground/config/custom-policies/$(CRATE_NAME)_definition.yaml"
	-docker compose -f ./playground/docker-compose.yaml down
	docker compose -f ./playground/docker-compose.yaml up

# Set TEST with a specific test name to run a single test using make test. Example: TEST=my_test
TEST ?=

.PHONY: test
test: build tests/config/registration.yaml ## Run integration tests
	@cargo test $(TEST) -- --nocapture

FORMAT     ?=
OUTPUT_PATH ?=

_COVERAGE_FORMAT = $(if $(filter json,$(FORMAT)),--json,$(if $(filter html,$(FORMAT)),--html,))
_COVERAGE_OUTPUT = $(if $(OUTPUT_PATH),--output-path $(OUTPUT_PATH),)

.PHONY: test-coverage
test-coverage: build tests/config/registration.yaml ## Run tests with coverage. Opts: FORMAT=json|html, OUTPUT_PATH=/my/path
	cargo llvm-cov test $(_COVERAGE_FORMAT) $(_COVERAGE_OUTPUT) --ignore-filename-regex config.rs -- --nocapture

.PHONY: publish
publish: build ## Publish a development version of the policy
	anypoint-cli-v4 pdk policy-project publish --binary-path $(TARGET_DIR)/$(CRATE_NAME).wasm --implementation-gcl-path $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml --skip-unchanged-definition=$(SKIP_UNCHANGED_DEFINITION)

.PHONY: release
release: build ## Publish a release version
	anypoint-cli-v4 pdk policy-project release --binary-path $(TARGET_DIR)/$(CRATE_NAME).wasm --implementation-gcl-path $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml --skip-unchanged-definition=$(SKIP_UNCHANGED_DEFINITION)

# Anypoint organization ID format (a UUID), used to validate group_id in Cargo.toml.
GROUP_ID_REGEX := [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}
GROUP_ID ?=

.PHONY: set-group-id
set-group-id: ## Set the Anypoint organization the policy is built/published under. Usage: make set-group-id GROUP_ID=<organization-id>
ifeq ($(OS), Windows_NT)
	@if ('$(GROUP_ID)' -notmatch '^$(GROUP_ID_REGEX)$$') { Write-Host 'ERROR: GROUP_ID must be your Anypoint organization ID (a UUID). Usage: make set-group-id GROUP_ID=<organization-id>. List your organizations with: anypoint-cli-v4 account business-group list'; exit 1 }
	@(Get-Content Cargo.toml) -replace '^group_id = ".*"$$', 'group_id = "$(GROUP_ID)"' | Set-Content Cargo.toml
	@Write-Host 'group_id set to $(GROUP_ID) in Cargo.toml'
else
	@echo "$(GROUP_ID)" | grep -Eq '^$(GROUP_ID_REGEX)$$' || { \
		echo "ERROR: GROUP_ID must be your Anypoint organization ID (a UUID)."; \
		echo "       Usage: make set-group-id GROUP_ID=<organization-id>"; \
		echo "       List your organizations with: anypoint-cli-v4 account business-group list"; \
		exit 1; }
	@sed -i.bak -E 's/^group_id = ".*"$$/group_id = "$(GROUP_ID)"/' Cargo.toml && rm -f Cargo.toml.bak
	@echo "group_id set to $(GROUP_ID) in Cargo.toml"
endif

# Fails early, with a clear message, when group_id is still a placeholder: the
# PDK only reports a generic 'Invalid group-id' deep inside the build.
.PHONY: check-group-id
check-group-id:
ifeq ($(OS), Windows_NT)
	@if (-not (Select-String -Path Cargo.toml -Pattern '^group_id = "$(GROUP_ID_REGEX)"$$' -Quiet)) { Write-Host 'ERROR: group_id in Cargo.toml is not set to an Anypoint organization ID. Run: make set-group-id GROUP_ID=<organization-id>'; exit 1 }
else
	@grep -Eq '^group_id = "$(GROUP_ID_REGEX)"$$' Cargo.toml || { \
		echo "ERROR: group_id in Cargo.toml is not set to an Anypoint organization ID."; \
		echo "       Run: make set-group-id GROUP_ID=<organization-id>"; \
		echo "       List your organizations with: anypoint-cli-v4 account business-group list"; \
		exit 1; }
endif

.PHONY: build-asset-files
build-asset-files: check-group-id $(DEFINITION_SRC_GCL_PATH)
	@anypoint-cli-v4 pdk policy-project build-asset-files --metadata '$(ANYPOINT_METADATA_JSON)'
	@cargo anypoint config-gen -p -m $(DEFINITION_SRC_GCL_PATH) -o src/generated/config.rs

.PHONY: install-cargo-anypoint
install-cargo-anypoint:
	cargo install cargo-anypoint@1.10.0

.PHONY: install-llvm-cov
install-llvm-cov:
	rustup component add llvm-tools-preview
	cargo install cargo-llvm-cov

.PHONY: show-policy-ref-name
show-policy-ref-name:
	@echo $(POLICY_REF_NAME)

ifneq ($(OS), Windows_NT)
all: help

.PHONY: help
help: ## Shows this help
	@echo 'Usage: make <target>'
	@echo ''
	@echo 'Available targets are:'
	@echo ''
	@grep -Eh '^\w[^:]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-6s\033[0m %s\n", $$1, $$2}' \
		| sort
endif