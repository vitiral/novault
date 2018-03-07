with import <nixpkgs> {};
((import ./novault.nix).novault {}).override {
  crateOverrides = defaultCrateOverrides // {
    novault = attrs: { buildInputs = [ xorg.libX11 xorg.libXtst ]; };
  };
}
