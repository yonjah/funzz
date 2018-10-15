'use strict';

const Hapi = require('hapi');
const Funzz = require('../lib');
const Joi = require('joi');
const Lab = require('lab');

const { describe, it } = exports.lab = Lab.script();
const secret = Math.random().toString(32); //value that should not be leaked

const server = Hapi.server();
const code = '007';

server.route({
    method: 'GET',
    path: '/guess/{code}',
    handler(req, res) {

        if (req.params.code === code) {
            return secret;
        }

        return Math.random().toString(32);
    },
    config: {
        validate: {
            params: {
                code: Joi.string().regex(/\d{3}/)
            }
        }
    }
});

Funzz(server, {
    it,
    describe,
    permutations: 2500,
    validResponse: Joi.object({
        statusCode: Joi.number().integer().less(500),
        payload: Joi.string().regex(new RegExp(secret), { name: 'secret', invert: true }) // make sure secret value is never leaked in  response payload
    }).unknown()
});
