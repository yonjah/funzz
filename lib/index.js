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
    juzzOptions: Joi.object().unknown().default({}),
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

const paramsSchema = {
    wildcard: Joi.string().allow(''),
    count: Joi.string().required(),
    optional: Joi.string().allow(''),
    required: Joi.string().required()
};

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

                data.url = data.url.replace(new RegExp(`{${param}(\\?|(\\*)(\\d)?)?}`), record.params[param]);
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
        const paramsConf = Hoek.unique(params).reduce((conf, param) => {

            const paramMatch = new RegExp(`{${param}(\\?|(\\*)(\\d)?)?}`);
            const matches = route.path.match(paramMatch);

            conf[param] = {
                wildcard: !!matches[2],
                count: matches[3] && parseInt(matches[3], 10),
                optional: !matches[3] && !!matches[1]
            };

            return conf;
        }, {});

        const localValidation = {
            query: validate.query || Joi.object().unknown(),
            payload: validate.payload || Joi.object().pattern((/.{0,10}/), Joi.any()),
            params: validate.params || Joi.object(Hoek.unique(params).reduce((obj, param) => {

                const conf = paramsConf[param];
                if (conf.wildcard) {
                    if (conf.count) {
                        obj[param] = paramsSchema.count.min(conf.count * 3);
                    }
                    else {
                        obj[param] = paramsSchema.wildcard;
                    }

                }
                else if (conf.optional) {
                    obj[param] = paramsSchema.optional;
                }
                else {
                    obj[param] = paramsSchema.required;
                }

                return obj;
            }, {})),
            headers: validate.headers
        };

        for (let i = 0; i < permutations; i += 1 ) {
            const data = {
                path   : route.path,
                method : route.method,
                query  : Juzz(localValidation.query, options.juzzOptions),
                payload: route.method !== 'get' ? Juzz(localValidation.payload, options.juzzOptions) : undefined,
                params : params.length ? Juzz(localValidation.params) : undefined,
                headers: localValidation.headers ? Juzz(localValidation.headers, options.juzzOptions) : undefined
            };

            this._splitParams(options, paramsConf, data);

            if (validateData) {
                ['query', 'headers', 'payload', 'params'].forEach((prop) => {

                    if (validate[prop]) {
                        const { error } = validate[prop].validate(data[prop]);

                        if (error) {
                            error.message = `${data.path}[${data.method}]:
${error.message}
${prop}: ${JSON.stringify(data[prop], null, 4)}
Schema: ${JSON.stringify(validate[prop].describe(), null, 4)}`;
                            throw error;
                        }
                    }

                });
            }

            debug('data', data);
            records.push(data);
        }

        return records;
    },

    _splitParams(options, paramsConf, data) {

        Object.keys(paramsConf).forEach((param) => {

            let value = data.params[param];
            const conf = paramsConf[param];

            if (!value && !conf.optional) {
                value = Juzz(paramsSchema.required, options.juzzOptions);
            }
            else if (!value && conf.count) {
                value = Juzz(paramsSchema.count.min(conf.count * 3), options.juzzOptions);
            }

            if (!value) {
                data.params[param] = '';
                return;
            }

            try {
                value = decodeURIComponent(value);
            }
            catch (e) {
                //ignore error;
            }

            if (conf.wildcard) {
                const length = value.length;
                const count = conf.count || Math.ceil(Math.random() * length / 3);
                let remaining = length - count + 1;
                const parts = [];

                for (let i = count; i > 0; i -= 1) {
                    let partLen;
                    if (i === 1) {
                        partLen = remaining;
                    }
                    else {
                        partLen = Math.ceil(Math.random() * remaining);

                        if ( Math.floor((remaining - partLen) / (i - 1) )  < 2 ) {
                            partLen = remaining - ((i - 1) * 2);
                        }
                    }

                    remaining -= partLen;
                    const partVal = value.substring(0, partLen);
                    parts.push(encodeURIComponent(partVal));
                    value = value.substring(partLen);
                }

                value = parts.join('/');
                if (decodeURIComponent(value).length !== length) {
                    throw new Error('WTF?');
                }
            }
            else {
                value = encodeURIComponent(value);
            }

            debug('param', param, value);
            data.params[param] = value;
        });
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
