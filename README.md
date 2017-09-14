# NoVault: ultra simple and secure password management

NoVault is an ultra simple and secure password manager similar to [Master
Password][1] but made to be much simpler and more auditable for developer
minded people.

As the name implies, NoVault does not require storing your passwords in
any kind of file or database. Instead, *you* remember a single password,
which is cryptographically hashed with [Argon2][2] and converted to a string
using base64url. You only have to (semi-securely) share a single 4k
`novault.secret` that gets generated at init time among your devices.

NoVault stores your *configuration* and sites in a human readable toml file,
which you can save on sites like google drive, dropbox or even publically on
github.

No vault is written in rust, and uses the rust type system extensively to
avoid accidentally serializing either your master password or a site
password. Simply grep for `audit_this` to look for all possible places
that information could leak.

Advantages to NoVault over other password managers:
- Nobody except for *you* knows your password. It is not stored in any
  database and cannot be leaked by the application.
- NoValut should *never* access the internet, so that eliminates an entire
  world of security vulnerabilities.
- Each website get's its *own individual salted password*. So even if that
  password is compromised it *will not compromise your master password*.
- Uses Argon2 for hashing, which is the winner of the [2015 Password Hashing
  Competition][2]
- Simple: completely open source and less than 1000 lines of code
- Written in a type safe language (rust)
- Your passwords never exist in plain text, html or paste buffer -- NoVault
  takes control of your *keyboard* to enter the passwords.
- You are safe to store your configuration in plain text anywhere, so it is
  easy to keep it in sync accross your computers.

(current) disadvantages:
- Can only use on linux
- Written by a complete amateur over a weekend in his spare time
- Not even remotely audited by anyone with any cyrptographic knowledge
- Once you write a password manager you can never trust anyone ever again.
- Hackers could eat your lunch and I provide no guarantees about the
  waranty or security of this product, so you can't sue me (sorry).
  On that note...

> **The MIT License (MIT)
>
> Copyright (c) 2017 Garrett Berg, vitiral@gmail.com
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
> THE SOFTWARE.**

# Guide
## Installation
The only way to install is through cargo:
```
cargo install novault
```

## Basic Use

[![choosing a good password](https://imgs.xkcd.com/comics/password_strength.png)](https://xkcd.com/936/)
Initialize your NoVault config file:
```
novault init
```

This will ask for a password, choose a good one.  It is better to make a long
password that you can remember than a short one with lots of symbols. "correct
horse battery staple" has high entropy but is pretty easy to remember.

This will create two files:
- `~/.config/novault.toml`: This is the configuration for how to generate your
  passwords. As long as you don't put sensitive information in `notes` or the
  site names, you can store this file anywhere.
- `~/.local/novault.secret`: This is a randomly generated secret file that is
  4KiB in size. Keep this file *relatively* secure: only on a usb stick and
  your filesystems is best, email/dropbox/google drive is probably ok. Whatever
  you do, DON'T loose this file! The purpose of this file is to make it so that
  an attacker needs *both* your master-password AND this file in order to crack
  your passwords. If you accidentally copy/paste your master password into
  facebook... that is bad.  You should change your passwords! But it is
  unlikely most hackers will be able to compromise you *immediately* since it
  is unlikely they also have your `novault.secret` file.

Once you have chosen your password, add a site:
```
novault set vitiral@gmail.com --notes "open source email"
```

Setting the password and 4 digit pin of a bank might be done with:
```
novault set vitiral@bank
novault set pin.vitiral@bank --pin --fmt '{p:.4}'
```

> The `{...}` syntax is the same as [rust/pthon's string fmt syntax][3].
> `p` is the name of the password and everything after `:` tells how to format
> `p`. `:.4` says to use "precision 4" which in this case means string length
> of 4. If your site requires special characters you can add them like
> `--fmt '{p:.20}!@#'`. Obviously the characters don't provide extra security...
> but you are using a 20 digit random hash which is about as secure as anything
> can be.

Now you can get the site's password. NoVault will automatically validate that
your password is the same one you used in `novault init`.
```
novault get vitiral@gmail.com
# ... type in your password
# ... run "killall -SIGUSR1 -u $USER novault" through a key binding.
# ... NoVault will control your keyboard to type in your password securely

novault --stdout get pin.vitiral@bank  # just print to stdout
```

The novault config file is stored in `~/.config/novault.toml` by default.
It is recommended that you back up this file and distribute it among your
computers. I prefer to keep it in revision control on a [public github
repo][4].

## What you need to keep/remember
NEVER forget your password or loose your `~/.local/novault.secret` file.
If you do your passwords are completely unrecoverable.

Tips:
- Choose a password that is easy to remember but hard to guess (see above)
- Store your `novault.secret` file on a USB stick and put it in your dresser
- Put `novault.secret` on other computers you trust.
- Print your `novault.secret` to paper and put it somewhere safe as an
  absolute last resort.

Do NOT share your `novault.secret` file. If you think it is compromised,
you are probably okay... until you accidentally leak your master password.
That is the purpose of the `novault.secret` file, it protects you from
yourself -- and on security matters you are always your own worst enemy.

[1]: http://masterpasswordapp.com/
[2]: https://en.wikipedia.org/wiki/Argon2
[3]: https://doc.rust-lang.org/std/fmt/
[4]: https://github.com/vitiral/dotfiles/blob/master/config/novault.toml
