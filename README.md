# array-bcrypt-user

Store and verify users with bcrypt passwords located in an array.

## Examples

Create a new user named "foo" with the password "secr3t".

    var assert = require('assert');
    var User = require('array-bcrypt-user');

    var db = [];

    User.register(db, 'foo', 'secr3t', function(err, user) {
      if (err) { throw err; }
      assert.equal(db.length, 1);
    });

Check if the password "secr3t" is correct for user "foo".

    // same setup as previous example

    User.find(db, 'foo', 'bar', function(err, user) {
      if (err) { throw err; }
      user.verifyPassword('secr3t', function(err, correct) {
        if (err) { throw err; }
        assert(correct, true);
      });
    });

## Installation

    $ npm install array-bcrypt-user

## API

### User.register(db, username, password, [realm], cb)
* db {Object} array that contains all users
* username {String} the username to use
* password {String} the password to use, at least 6 characters
* [realm] {String, default "_default"} optional realm the user belongs to
* cb {Function} first parameter will be an error or null, second parameter will be
  the user object or undefined.

Factory method: create a new user with a certain password and save it to the
database.

### User.find(db, username, [realm], cb)
* db {Object} array that contains all users
* username {String} the username to use
* [realm] {String, default "_default"} optional realm the user belongs to
* cb {Function} first parameter will be an error or null, second parameter will be
  the user object or undefined.

Factory method: find and return a user from the database.

### user.verifyPassword(password, cb)
* password {String} the password to verify
* cb {Function} first parameter will be an error or null, second parameter
  contains a boolean about whether the password is valid or not.

Verify if the given password is valid.

### user.setPassword(password, cb)
* password {String} the password to use
* cb {Function} first parameter will be either an error object or null on success.

Update the password.

Note: the user has to exist in the database.

### new User(db, username, [opts])
* db {Object} array containing user objects
* username {String} the name of the user to bind this instance to
* [opts] {Object} object containing optional parameters

opts:
* realm {String, default "_default"}  optional realm the user belongs to
* debug {Boolean, default false} whether to do extra console logging or not
* hide {Boolean, default false} whether to suppress errors or not (for testing)


Store and verify users with bcrypt passwords located in an array.

Note: don't use `new User` but one of the factory methods `register` or `find` to
construct a new user object.

## Tests

    $ npm test

## License

ISC

Copyright (c) 2014, 2015 Tim Kuijsten

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
