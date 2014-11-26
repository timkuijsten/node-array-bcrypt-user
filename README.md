# array-bcrypt-user

Store and verify users with bcrypt passwords located in an array.

## Examples

Create a new user named "foo" with the password "secr3t".

    var User = require('array-bcrypt-user');

    var db = [];

    var user = new User(db, 'foo');
    user.register('secr3t', function(err) {
      if (err) { throw err; }

      assert.equal(db.length, 1);
    });

Check if the password "raboof" is correct for user "foo" in the realm "bar".

    // same setup as previous example

    var user = new User(db, 'foo', 'bar');
    user.verifyPassword('raboof', function(err, correct) {
      if (err) { throw err; }

      if (correct === true) {
        console.log('password correct');
      } else {
        console.log('password incorrect');
      }
    });

## Installation

    $ npm install array-bcrypt-user

## API

#### new User(db, username, [realm])
* db {Array} array containing user objects
* username {String} the name of the user to bind this instance to
* realm {String, default: _default} optional realm the user belongs to

Store and verify users with bcrypt passwords located in an array.

#### user.exists(cb)
* cb {Function} first parameter will be an error or null, second parameter
  contains a boolean about whether this user exists or not.

Return whether or not the user already exists in the database.

#### user.verifyPassword(password, cb)
* password {String} the password to verify
* cb {Function} first parameter will be an error or null, second parameter
  contains a boolean about whether the password is valid or not.

Verify if the given password is valid.

#### user.setPassword(password, cb)
* password {String} the password to use
* cb {Function} first parameter will be either an error object or null on success.

Update the password.

Note: the user has to exist in the database.

#### user.register(password, cb)
* password {String} the password to use, at least 6 characters
* cb {Function} first parameter will be either an error object or null on success.

Register a new user with a certain password.

## Tests

    $ npm test

## License

MIT

Copyright (c) 2014 Tim Kuijsten

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
