password = 'target/password'
sites = 'target/novault.sites'
lock = 'target/novault.lock'
secret = 'target/novault.secret'

# run with the given flags
run CMD="":
	@mkdir -p target
	@echo "shakeitoff" > {{password}}
	cargo build --release
	cat {{password}} | target/release/novault \
		--stdin --stdout --sites {{sites}} --lock {{lock}} --secret {{secret}} \
		{{CMD}}
	@echo "-------- CONFIG --------"
	@cat {{sites}} || echo "no sites file found"
	@echo "-------- SECRET --------"
	@cat {{secret}}
	@echo "------------------------"


run-kill CMD="":
	cargo build --release
	cat {{password}} | target/release/novault \
		--stdin --sites {{sites}} --lock {{lock}} --secret {{secret}} \
		{{CMD}}

nix-build:
	sudo nix-build -A novault_0_4_0

test:
	cargo test --release
