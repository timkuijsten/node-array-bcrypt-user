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
 * Store and verify users with bcrypt passwords located in an array.
 *
 * @param {Array} db  array containing user objects
 * @param {String} username  name of the user to bind this instance to
 * @param {Object} [opts]  object containing optional parameters
 *
 * opts:
 *  realm {String, default "_default"}  optional realm the user belongs to
 *  debug {Boolean, default false} whether to do extra console logging or not
 *  hide {Boolean, default false} whether to suppress errors or not (for testing)
 */
function User(db, username, opts) {
  if (!Array.isArray(db)) { throw new TypeError('db must be an array'); }
  if (typeof username !== 'string') { throw new TypeError('username must be a string'); }

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

  BcryptUser.call(this, resolver, username, opts || {});
}

util.inherits(User, BcryptUser);
module.exports = User;

/**
 * Create a new user with a certain password and save it to the database.
 *
 * @param {Object} db  array that contains all users
 * @param {String} username  username to register
 * @param {String} password  password to register
 * @param {String, default "_default"} [realm]  optional realm the user belongs to
 * @param {Function} cb  first parameter will be either an error object or null on
 *                       success, second parameter will be either a user object or
 *                       undefined on failure.
 */
User.register = function register(db, username, password, realm, cb) {
  if (!Array.isArray(db)) { throw new TypeError('db must be an array'); }
  if (typeof realm === 'function') {
    cb = realm;
    realm = '_default';
  }

  var user = new User(db, username, { realm: realm });
  user.register(password, function(err) {
    if (err) { cb(err); return; }

    cb(null, user);
  });
};

/**
 * Find and return a user from the database.
 *
 * @param {Object} db  array that contains all users
 * @param {String} username  username to search for
 * @param {String, default "_default"} [realm]  optional realm the user belongs to
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       will be the user object or undefined.
 */
User.find = function find(db, username, realm, cb) {
  if (!Array.isArray(db)) { throw new TypeError('db must be an array'); }
  if (typeof realm === 'function') {
    cb = realm;
    realm = '_default';
  }

  var user = new User(db, username, { realm: realm });
  user.find(function(err) {
    if (err) { cb(err); return; }

    cb(null, user);
  });
};
