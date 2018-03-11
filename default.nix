with import <nixpkgs> {};
((import ./novault.nix).novault {}).override {
  crateOverrides = defaultCrateOverrides // {
    novault = attrs: {
      buildInputs = [
        rustc cargo openssl pkgconfig # for nix-shell
        xorg.libX11 xorg.libXtst
      ];

      # LIBRARY_PATH = "${xorg.libX11}/lib:${xorg.libXtst}/lib";
      # PKG_CONFIG_PATH = "${openssl}/lib/pkgconfig";
    };
  };
}
