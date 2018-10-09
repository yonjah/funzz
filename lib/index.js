'use strict';

const Url   = require('url');
const Util  = require('util');
const Juzz  = require('juzz');
const Joi   = require('joi');
const Hoek  = require('hoek');
const debug = require('debug')('Funzz');


const injectReplaceSchema = Joi.func().arity(2);

const configSchema = Joi.object({
    automate: Joi.boolean().default(true),
    validateData: Joi.boolean().default(false),
    permutations: Joi.number().integer().default(10),
    validResponse: Joi.object().schema().default(Joi.object({ statusCode: Joi.number().integer().less(500) }).unknown()),
    injectReplace: injectReplaceSchema
}).when(Joi.object({ automate: Joi.any().valid(true) }).unknown(), { then: Joi.object({
    it: Joi.func().minArity(2).default(Joi.ref('$it')),
    describe: Joi.func().minArity(2).default(Joi.ref('$describe'))
}).and('automate', 'it', 'describe') });


const recordSchema = Joi.object({
    path: Joi.string().required(),
    method: Joi.string().lowercase().required(),
    query: Joi.object(),
    payload: Joi.object(),
    headers: Joi.object(),
    params: Joi.object()
});

const internal = {
    inject(server, record, replace) {

        let data = {
            url: record.path,
            method: record.method,
            payload: record.payload,
            headers: record.headers
        };

        if (record.params) {
            Object.keys(record.params).forEach((param) => {

                data.url = data.url.replace(new RegExp(`{${param}\\??}`), encodeURIComponent(record.params[param]));
            });
        }

        data.url = Url.format({
            pathname: data.url,
            query: record.query
        });

        if (replace) {
            data = replace(record, data);
        }

        debug('inject', data);

        return server.inject(data);
    },

    generateRoute(route, options) {

        const { permutations, validateData } = options;

        const { params } = route;
        const { validate } = route.settings;

        debug('path', route.path);
        debug('settings', route.settings);
        debug('validate', validate);

        const records = [];

        const localValidation = {
            query: validate.query || Joi.object().unknown(),
            payload: validate.payload || Joi.object().pattern((/.{0,10}/), Joi.any()),
            params: validate.params || Joi.object(params.reduce((obj, param) => {

                obj[param] = Joi.string().required();
                if (route.path.indexOf(`{${param}?}`) >= 0) {//optional param
                    Joi.string().allow('');
                }

                return obj;
            }, {})),
            headers: validate.headers
        };

        for (let i = 0; i < permutations; i += 1 ) {
            const data = {
                path   : route.path,
                method : route.method,
                query  : Juzz(localValidation.query),
                payload: route.method !== 'get' ? Juzz(localValidation.payload) : undefined,
                params : params.length ? Juzz(localValidation.params) : undefined,
                headers: localValidation.headers ? Juzz(localValidation.headers) : undefined
            };

            if (validateData) {
                ['query', 'headers', 'payload', 'params'].forEach((prop) => {

                    if (validate[prop]) {
                        const { error } = validate[prop].validate(data[prop]);

                        if (error) {
                            error.message += `\n${JSON.stringify(data[prop])}`;
                            throw error;
                        }
                    }

                });
            }

            debug('data', data);
            records.push(data);
        }

        return records;
    }
};

module.exports = function FunzzInit(server, op = {}) {

    const { value: options, error: optionsError } = Joi.validate(op, configSchema, { context: { it: global.it, describe: global.describe } });
    if (optionsError) {
        throw optionsError;
    }

    const { describe, it, validResponse, automate, injectReplace } = options;
    const table = server.table();
    const records = [];


    table.forEach((route) => {

        let routeRecords;
        if (route.method !== '*') {
            routeRecords = internal.generateRoute(route, options);
        }
        else {
            routeRecords = [];
            ['get', 'post', 'put', 'patch', 'delete', 'options'].forEach((method) => {

                routeRecords.push(...internal.generateRoute(Object.assign({}, route, { method }), options));
            });
        }


        if (automate) {
            describe(`Funzzing ${route.method} ${route.path}`, () => {

                routeRecords.forEach((record) => {

                    it(`should pass with data: ${Util.inspect(record, { depth: 2 })}`, async () => {

                        const response = await internal.inject(server, record, injectReplace);
                        const result = validResponse.validate(response);
                        if (result.error) {
                            let message = `${JSON.stringify(record)}`;

                            const respError = Hoek.reach(response, 'request.response._error');

                            if (response.result) {
                                message += `\n${JSON.stringify(response.result)}`;
                            }

                            if (respError) {
                                message += `\n${response.request.response._error.message}`;
                            }

                            message += `\n${result.error}`;

                            throw new Error(`Failed calling route with data:\n${message}`);

                        }

                        return response;
                    });
                });
            });
        }

        records.push(...routeRecords);
    });

    return records;
};


module.exports.inject = function inject(server, record, replace) {

    Joi.assert(record, recordSchema);
    replace && Joi.assert(replace, injectReplaceSchema);

    return internal.inject(server, record, replace);
};

module.exports.generateRoute = function generateRoute(route, op) {

    const { value: options, error: optionsError } = Joi.validate(op, configSchema, { context: { it: global.it, describe: global.describe } });
    if (optionsError) {
        throw optionsError;
    }

    return internal.generateRoute(route, options);
};
