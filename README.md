# NoVault: ultra simple and secure password management

NoVault is an ultra simple and secure password manager similar to [Master
Password][1] but made to be much simpler.

As the name implies, NoVault does not require storing your passwords in
any kind of file or database. Instead, *you* remember a single password,
which is cryptographically hashed with SHA512 and converted to a string
using base64url.

NoVault stores your *configuration* in a human readable toml file, which you
can save on sites like google drive, dropbox or even publically on github --
*no passwords are stored in this plain text* (except the checkhash for your
masterpassword, which is securely hashed).

# Guide
TODO: installation guide

Initialize your NoVault config file:
```
novault init
```

This will ask for a password, choose a good one.  It is better to make a long
password that you can remember than a short one with lots of symbols. "battery
horse loves staple" has high entropy but is pretty easy to remember.

FIXME: add xkcd article

Once you have chosen your password, add a site:
````
novault set vitiral@gmail.com --notes "open source email"
```

Setting the password and 4 digit pin of a bank might be done with:
````
novault set myname@bank
novault set myname@bank.pin --pin --fmt '{p:.4}'
```

> The `{...}` syntax is the same as TODO: rust/python's string formatting
> syntax.

Now you can get the site's password. NoVault will automatically validate that
your password is the same one you used in `novault init`.
```
novault get vitiral@gmail.com
novault set myname@bank
novault set myname@bank.pin --stdout  # just print to stdout
```

Each of these calls (except with `--stdout`) will put NoVault in a "hung
state". To use your password, bind `novault trigger` to a key (I use
`<WINDOWS>p`) and it will control your keyboard to type the password in.  It
will never use your paste buffer and your password will never be in plain text.

The novault config file is stored in `~/.config/novault.toml` by default.
It is recommended that you save this file to keep access to your site
information.

[1]: http://masterpasswordapp.com/
