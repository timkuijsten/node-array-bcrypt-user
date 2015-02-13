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

/*jshint -W068 */

var should = require('should');
var bcrypt = require('bcrypt');
var async = require('async');

var User = require('./index');
var match = require('match-object');

// setup user accounts
var db = [];

function find(lookup, cb) {
  var found = null;
  async.some(db, function(user, cb2) {
    if (match(lookup, user)) {
      found = user;
      cb2(true);
      return;
    }
    cb2(false);
  }, function() { cb(null, found); });
}

describe('User', function () {
  describe('constructor', function () {
    it('should require db to be an array', function() {
      (function() { return User.find(''); }).should.throw('db must be an array');
    });
    // assume all checks are handled by the previously tested User._checkAllWithPassword
  });

  describe('register', function () {
    it('should register', function(done) {
      User.register(db, 'baz', 'p4ssword', 'ooregister', function(err) {
        should.strictEqual(err, null);
        find({ realm: 'ooregister', username: 'baz' }, function(err, usr) {
          should.strictEqual(err, null);
          should.strictEqual(usr.realm, 'ooregister');
          should.strictEqual(usr.username, 'baz');

          // bcrypt password example: '$2a$10$VnQeImV1DVqtQ7hXa.Sgsug9cCLVa65W4jO09w.I5tXcuYRbRVevu'
          should.strictEqual(usr.password.length, 60);
          usr.password.should.match(/^\$2a\$10\$/);

          bcrypt.compare('p4ssword', usr.password, function(err, res) {
            if (err) { throw err; }
            if (res !== true) { throw new Error('passwords don\'t match'); }
            done();
          });
        });
      });
    });
  });

  describe('find', function () {
    // use previously created user
    it('should find the user', function(done) {
      User.find(db, 'baz', 'ooregister', function(err, user) {
        if (err) { throw err; }
        should.strictEqual(user._realm, 'ooregister');
        should.strictEqual(user._username, 'baz');
        done();
      });
    });
  });

  describe('verifyPassword', function () {
    // use previously created user

    it('should find that the password is invalid', function(done) {
      User.find(db, 'baz', 'ooregister', function(err, user) {
        if (err) { throw err; }
        user.verifyPassword('secret', function(err, correct) {
          if (err) { throw err; }
          should.strictEqual(correct, false);
          done();
        });
      });
    });

    it('should find that the password is valid', function(done) {
      User.find(db, 'baz', 'ooregister', function(err, user) {
        if (err) { throw err; }
        user.verifyPassword('p4ssword', function(err, correct) {
          if (err) { throw err; }

          should.strictEqual(correct, true);
          done();
        });
      });
    });
  });

  describe('setPassword', function () {
    // use previously created user

    it('should update the password', function(done) {
      User.find(db, 'baz', 'ooregister', function(err, user) {
        if (err) { throw err; }
        user.setPassword('secret', function(err) {
          if (err) { throw err; }
          find({ username: 'baz', realm: 'ooregister' }, function(err, usr) {
            should.strictEqual(err, null);
            should.strictEqual(usr.realm, 'ooregister');
            should.strictEqual(usr.username, 'baz');

            // bcrypt password example: '$2a$10$VnQeImV1DVqtQ7hXa.Sgsug9cCLVa65W4jO09w.I5tXcuYRbRVevu'
            should.strictEqual(usr.password.length, 60);
            usr.password.should.match(/^\$2a\$10\$/);

            bcrypt.compare('secret', usr.password, function(err, res) {
              if (err) { throw err; }
              if (res !== true) { throw new Error('passwords don\'t match'); }
              done();
            });
          });
        });
      });
    });

    it('should require that the user exists in the given realm (wrong realm)', function(done) {
      User.find(db, 'baz', 'ooregister2', function(err, user) {
        if (err) { throw err; }
        user.setPassword('secret', function(err) {
          should.strictEqual(err.message, 'failed to update password');
          done();
        });
      });
    });

    it('should require that the user exists in the given realm (wrong username)', function(done) {
      User.find(db, 'baz', 'ooregister2', function(err, user) {
        if (err) { throw err; }
        user.setPassword('secret', function(err) {
          should.strictEqual(err.message, 'failed to update password');
          done();
        });
      });
    });
  });
});
