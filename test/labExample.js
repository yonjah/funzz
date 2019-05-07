'use strict';

const Hapi = require('@hapi/hapi');
const Funzz = require('../lib');
const Lab = require('@hapi/lab');

const { describe, it } = exports.lab = Lab.script();

const server = Hapi.server();
server.route({ method: 'GET', path: '/test', handler: () => 'ok' });
Funzz(server, { it, describe });
