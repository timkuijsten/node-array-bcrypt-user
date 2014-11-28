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
  describe('_checkAllWithPassword', function () {
    it('should require db to be an array', function() {
      (function() { User._checkAllWithPassword(''); }).should.throw('db must be an array');
    });

    it('should require username to be a string', function() {
      (function() { User._checkAllWithPassword(db); }).should.throw('username must be a string');
    });

    it('should not throw', function() {
      User._checkAllWithPassword(db, 'foo', 'raboof', 'bar', function() {});
    });
  });

  describe('constructor', function () {
    it('should require db to be an object', function() {
      (function() { var user = new User(''); return user; }).should.throw('db must be an array');
    });
    // assume all checks are handled by the previously tested User._checkAllWithPassword
  });

  describe('register', function () {
    it('should register', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.register('p4ssword', function(err) {
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

  describe('exists', function () {
    // use previously created user
    it('should find that the user does exist', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.exists(function(err, doesExist) {
        if (err) { throw err; }
        should.strictEqual(doesExist, true);
        done();
      });
    });
  });

  describe('verifyPassword', function () {
    // use previously created user

    it('should find that the password is invalid', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.verifyPassword('secret', function(err, correct) {
        if (err) { throw err; }
        should.strictEqual(correct, false);
        done();
      });
    });

    it('should find that the password is valid', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.verifyPassword('p4ssword', function(err, correct) {
        if (err) { throw err; }
        should.strictEqual(correct, true);
        done();
      });
    });
  });

  describe('setPassword', function () {
    // use previously created user

    it('should update the password', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.setPassword('secret', function(err) {
        if (err) { throw err; }
        find({ username: 'baz', realm: 'ooregister' }, function(err, user) {
          should.strictEqual(err, null);
          should.strictEqual(user.realm, 'ooregister');
          should.strictEqual(user.username, 'baz');

          // bcrypt password example: '$2a$10$VnQeImV1DVqtQ7hXa.Sgsug9cCLVa65W4jO09w.I5tXcuYRbRVevu'
          should.strictEqual(user.password.length, 60);
          user.password.should.match(/^\$2a\$10\$/);

          bcrypt.compare('secret', user.password, function(err, res) {
            if (err) { throw err; }
            if (res !== true) { throw new Error('passwords don\'t match'); }
            done();
          });
        });
      });
    });

    it('should require that the user exists in the given realm (wrong realm)', function(done) {
      var user = new User(db, 'baz', 'ooregister2');
      user.setPassword('secret', function(err) {
        should.strictEqual(err.message, 'failed to update password');
        done();
      });
    });

    it('should require that the user exists in the given realm (wrong username)', function(done) {
      var user = new User(db, 'foo', 'ooregister');
      user.setPassword('secret', function(err) {
        should.strictEqual(err.message, 'failed to update password');
        done();
      });
    });
  });
});
