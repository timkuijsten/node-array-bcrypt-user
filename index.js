/**
 * Copyright (c) 2014 Tim Kuijsten
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';

var util = require('util');

var BcryptUser = require('bcrypt-user');
var async = require('async');
var match = require('match-object');

/**
 * Check parameters and throw if type is incorrect, or length out of bounds.
 *
 * @param {Array} db  throw if not an array
 * @param {String} username  throw if not a String
 * @param {String} password  throw if not a String
 * @param {String} realm  throw if not a String
 * @param {Function} cb  throw if not a Function
 * @return {undefined}
 */
function _checkAllWithPassword(db, username, password, realm, cb) {
  if (!Array.isArray(db)) { throw new TypeError('db must be an array'); }
  BcryptUser._checkAllWithPassword(db, username, password, realm, cb);
}

/**
 * Store and verify users with bcrypt passwords located in an array.
 *
 * @param {Array} db  array containing user objects
 * @param {String} username  the name of the user to bind this instance to
 * @param {String, default: _default} [realm]  optional realm the user belongs to
 */
function User(db, username, realm) {
  if (typeof realm === 'undefined') {
    realm = '_default';
  }

  _checkAllWithPassword(db, username, 'xxxxxx', realm, function() {});

  // setup a resolver
  var resolver = {
    find: function(lookup, cb) {
      var found = null;
      async.some(db, function(user, cb2) {
        if (match(lookup, user)) {
          found = user;
          cb2(true);
          return;
        }
        cb2(false);
      }, function() { cb(null, found); });
    },
    insert: function(user, cb) {
      db.push(user);
      process.nextTick(cb);
    },
    updateHash: function(lookup, hash, cb) {
      async.some(db, function(user, cb2) {
        if (match(lookup, user)) {
          user.password = hash;
          cb2(true);
          return;
        }
        cb2(false);
      }, function(result) {
        if (!result) {
          cb(new Error('failed to update password'));
          return;
        }

        cb(null);
      });
    }
  };

  BcryptUser.call(this, resolver, username, realm);
}
util.inherits(User, BcryptUser);
module.exports = User;

User._checkAllWithPassword = _checkAllWithPassword;
