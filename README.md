# Funzz

[![npm version](https://img.shields.io/npm/v/funzz.svg)](https://www.npmjs.com/package/funzz)
[![Build Status](https://travis-ci.org/yonjah/funzz.svg?branch=master)](https://travis-ci.org/yonjah/funzz)
[![codecov](https://codecov.io/gh/yonjah/funzz/branch/master/graph/badge.svg)](https://codecov.io/gh/yonjah/funzz)
[![Known Vulnerabilities](https://snyk.io/test/npm/funzz/badge.svg)](https://snyk.io/test/npm/funzz)
[![License](https://img.shields.io/npm/l/funzz.svg?maxAge=2592000?style=plastic)](https://github.com/yonjah/funzz/blob/master/LICENSE) [![Greenkeeper badge](https://badges.greenkeeper.io/yonjah/funzz.svg)](https://greenkeeper.io/)

Automatic fuzzer for [hapi.js](https://github.com/hapijs/hapi)

**Warning** this is a proof of concept and is currently a work in progress.
It is mostly used by me to automatically add fuzzing to my hapi test suites so stability and accuracy though important is not a major factor.

## Usage 

`Funzz` should work with any testing framework that exposes a  `describe` and `it` methods.
Like mocha -
```js
const Hapi = require('hapi');
const Funzz = require('funzz');

const server = Hapi.server();
server.route({ method: 'GET', path: '/test', handler: () => 'ok' });
Funzz(server);
```

Or Lab -
```js
const Hapi = require('hapi');
const Funzz = require('funzz');
const Lab = require('lab');

const { describe, it } = exports.lab = Lab.script();

const server = Hapi.server();
server.route({ method: 'GET', path: '/test', handler: () => 'ok' });
Funzz(server, { it, describe });
```

## Verifying tests
`Funzz` is still a work in progress so you might want to be sure it actually manages to pass your route validations otherwise fuzzing will not have much effect

On the first couple of runs you should set the option `validateData` to true so `Funzz` will try to verify if the data generated for the schema is indeed a valid data that should pass your route validation.


## API



## Known issues
`Funzz` is mostly a small wrapper around [Juzz](https://www.github.com/yonjah/juzz). Juzz is still very unstable.
if you have any issues where `Funzz` fail to generate a valid schema that will pass the route validation, or if it is not reaching all available data nodes it is most likely an issue with `Juzz`
