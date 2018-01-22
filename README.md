# NoVault: ultra simple and secure password management

> Note: as of version 0.4.0 it is not expected that there will be breaking
> changes to this tool. I am now using novault as my own primary password
> manager.

NoVault is an ultra simple and secure password manager similar to [Master
Password][1] but made to be much simpler and more auditable for developer
minded people.

As the name implies, NoVault does not require storing your passwords in
any kind of file or database. Instead, _you_ remember a single password,
which is cryptographically hashed with [Argon2][2] and converted to a string
using base64url. You only have to (semi-securely) share a tiny `novault.secret`
file that gets generated at init time among your devices.

NoVault stores your _configuration_ and sites in a human readable toml file,
which you can save on sites like google drive, dropbox or even publicly on
GitHub.

Advantages to NoVault over other password managers:
- Simple: completely open source and about 1000 lines of code
- Uses Argon2 for hashing, which is the winner of the [2015 Password Hashing
  Competition][2]
- Nobody except for _you_ knows your password. It is not stored in any
  database and cannot be leaked by the application.
- NoVault will _never_ access the internet, so that eliminates an entire
  world of security vulnerabilities.
- Each website get's its _own individual salted password_. So even if that
  password is compromised it _will not compromise your master password_.
- Your passwords never exist in plain text, html or paste buffer -- NoVault
  takes control of your _keyboard_ to enter the passwords.
- It is safe to store your configuration in plain text anywhere, so it is
  easy to keep it in sync across your computers. Even if you DO loose
  your `novault.sites` file, you only typically only need to remember the
  site name to recover the password.
- Written in a type safe language (rust)

(current) disadvantages:
- Can only be used on GNU/Linux
- Written by a complete amateur over a weekend in his spare time
- Not even remotely audited by anyone with any cryptographic knowledge
- Once you write a password manager you can never trust anyone ever again.
- Hackers could eat your lunch and I provide no guarantees about the
  warranty or security of this software, so you can't sue me (sorry).
  On that note...

> _The MIT License (MIT)
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
> THE SOFTWARE._

# Guide
## Installation
The only way to install (currently) is through cargo:
```
cargo install novault
```

## Basic Use

[![choosing a good password](https://imgs.xkcd.com/comics/password_strength.png)](https://xkcd.com/936/)

Initialize your NoVault config file:

```
novault init
```

This will ask for a master password, choose a good one. It is better to make a
long password that you can remember than a short one with lots of symbols.
"correct horse battery staple" has high entropy but is pretty easy to remember.

This will create a randomly generated secret file at `~/.local/novault.secret`.
Keep this file _relatively_ secure (see the "What you need to keep/remember"
section below). Whatever you do, DON'T loose this file! The purpose of it
is to make it so that an attacker needs _both_ your master-password AND
this file in order to crack your passwords. If you accidentally copy/paste your
master password into Facebook, then that is bad... but you don't have to completely
freak out. See section "I lost my master password..." below.

Once you have chosen your password, add a site:
```
novault set vitiral@gmail.com --notes "open source email"
```

After you have added your first site, a file will be created at
`~/.config/novault.sites`. This does not contain ANY information that could be
used to derive your masterpassword, therefore it is safe to store in a public
place (like GitHub).

For another example, setting the password and 4 digit pin of a bank might be
done with:

```
novault set vitiral@bank
novault set pin.vitiral@bank --pin --fmt '{p:.4}'
```

> The `{...}` syntax is the same as [rust/pthon's string fmt syntax][3].
> `p` is the name of the password and everything after `:` tells how to format
> `p`. `:.4` says to use "precision 4" which for strings (which `p` is) means
> string length of 4. If your site requires special characters you can add them
> like `--fmt '{p:.32}!@#'`. Obviously the characters don't provide extra
> security...  but you are using a 32 digit random hash which is about as
> secure as anything can ever be.

Now you can get the site's password. NoVault will automatically validate that
your password is the same one you used in `novault init`.

```
novault get vitiral@gmail.com
# ... Type in your password
# ... Run `echo "ok" >> ~/.confg/novault.lock` through a key binding.
# ... NoVault will control your keyboard to type in your password securely

novault --stdout get pin.vitiral@bank  # just print to stdout
```

The sites you have added are stored in `~/.config/novault.sites` by default.
It is recommended that you back up this file and distribute it among your
computers. I prefer to keep it in revision control on a [public GitHub
repo][4].

## What you need to keep/remember
NEVER forget your password or loose your `~/.local/novault.secret` file.
If you do loose either then your passwords are completely unrecoverable.

Tips:
- Choose a password that is easy to remember but hard to guess (see above)
- Store your `novault.secret` file on a couple USB sticks. I keep one
  on my keychain and one in my office. I also keep it on the sdcard
  which stays in my laptop.
- Put `novault.secret` on other computers you trust.

If possible, do NOT share your `novault.secret` file on the internet. If you
DO put it online, the less public the better. Email/dropbox/google-drive are
PROBABLY fine, but you never know how secure those sites are.

If you think your secret is compromised, you are probably okay... until you
accidentally leak your master password. That is the purpose of the
`novault.secret` file, it protects you from yourself -- and on security matters
you are always your own worst enemy.

> Note: changing your secret file is the same as changing your master password,
> ALL site passwords will change as well.

## I exposed my master password or secret file, what do I do?
You need to change it, but you can probably finish your cup of coffee first.

The truth is, as long as attackers don't hve BOTH your master password and your `novault.secret` file
then there is literally no way on earth they will be able to do anything. The
secret file contains a 256 character randomly generated ASCII string, which
is required in order to be able to generate your site passwords. This means
that as long as your secret file is safe, all the compute power on **earth**
would require literally a billion years to crack your site passwords.

If a hacker somehow gets them both, then you are screwed.  Probably a good idea
to generate a new one of both just in case.

So, you have to change your master password but there is no rush. How do you
do it?

### Step 1: make a backup of your existing passwords
Run the following:

```
novault InSeCuRe --export > ~/backup.txt
```

This will put all your site passwords in plain text. Obviously you should
only do this if you are about to change those passwords.

### Step 2: delete/move your secret file and create a new one
Move `~/.local/novault.secret` to `~/.local/novault.secret.bk` and re-run
`novault init` with your new password.  Your `~/.config/novault.sites` can stay
the same.

### Step 3: change the password for every site in your `~/.config/novault.sites`
You should go to each site and change the password from what is in `backup.txt`
to a newly generated password gotten with `novault get <site>`.

This will require you to type in your new master password a lot. Think of this
as a good chance to make sure you really remember it, as well as penance for
accidentally typing your master password into facebook... or work chat... or
(_gasp_) in an email to your ex-lover who happens to be a hacker.

When you are done, you can delete `backup.txt` and `novault.secret.bk` or keep
them, it doesn't really matter. I recommend keeping them in case you
accidentally forgot to change the password for a site. Probably don't email
them to your hacker ex-lover though...

[1]: http://masterpasswordapp.com/
[2]: https://en.wikipedia.org/wiki/Argon2
[3]: https://doc.rust-lang.org/std/fmt/
[4]: https://github.com/vitiral/dotfiles/blob/master/config/novault.toml


# Contributing
The deisgn documents are primarily hosted in `design/`. You can view them using
[artifact][art] using `art serve`. They are also [rendered here][design].

I welcome contributors, especially for security review. However, I will be
pretty cautious about accepting large changes or new features as I don't want
to compromise the security of the application.

[art]: https://github.com/vitiral/artifact
[design]: https://vitiral.github.io/novault/


# LICENSE
The source code in this repository is Licensed under either of
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
