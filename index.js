/**
 * Copyright (c) 2014, 2015 Tim Kuijsten
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
