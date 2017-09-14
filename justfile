password = 'target/password'
config = 'target/novault.toml'
lock = 'target/novault.lock'
secret = 'target/novault.secret'

# run with the given flags
run CMD="":
	@mkdir -p target
	@echo "shakeitoff" > {{password}}
	cargo build --release
	cat {{password}} | target/release/novault \
		--stdin --stdout --config {{config}} --lock {{lock}} --secret {{secret}} \
		{{CMD}}
	@echo "-------- CONFIG --------"
	@cat {{config}}
	@echo "------------------------"

test:
	cargo test --release
