'use strict';

const Url        = require('url');
const Util       = require('util');
const Juzz       = require('juzz');
const Joi        = require('joi');
const Hoek       = require('hoek');
const debug      = require('debug')('Funzz');
const LoadFuzzDb = require('./fuzzing-db.js');

const chance     = new (require('chance'))();

const methods = ['get', 'post', 'put', 'patch', 'delete', 'options'];

const injectReplaceSchema = Joi.func().arity(2);

const configSchema = Joi.object({
    automate: Joi.boolean().default(true),
    validateData: Joi.boolean().default(false),
    permutations: Joi.number().integer().default(10),
    validResponse: Joi.object().schema().default(Joi.object({ statusCode: Joi.number().integer().less(500) }).unknown()),
    juzzOptions: Joi.object().unknown().default({}),
    usePayloads: Joi.array().items(Joi.string()).single(),
    injectReplace: injectReplaceSchema
}).when(Joi.object({ automate: Joi.any().valid(true) }).unknown(), { then: Joi.object({
    it: Joi.func().minArity(2).default(Joi.ref('$it')),
    describe: Joi.func().minArity(2).default(Joi.ref('$describe'))
}).and('automate', 'it', 'describe') });


const serverSchema = Joi.object({
    table: Joi.func().required(),
    inject: Joi.func().required()
}).unknown().required();

const routeSchema = Joi.object({
    method: Joi.string().valid(methods).required(),
    path: Joi.string().required()
}).unknown().required();

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

                const value = record.params[param];

                if (value === undefined) {
                    data.url = data.url.replace(new RegExp(`/{${param}(\\?|\\*)}`), 'value');
                }
                else {

                    data.url = data.url.replace(new RegExp(`{${param}(\\?|(\\*)(\\d)?)?}`), value);
                }
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

        const juzzOptions = Object.assign({}, options.juzzOptions);

        if (options.payloads) {
            const replace = juzzOptions.replace;
            const { string, file } = options.payloads;
            juzzOptions.replace = function (res, desc, rules) {

                if (desc.type === 'string') {
                    const { ip, dataUri, base64, isoDate, guid, hostname, uri, email, token, regex } = rules;

                    if (file && dataUri) {

                        const randFile = file[chance.pickone(Object.keys(file))];
                        res = `data:${randFile.mime};base64,${randFile.data.toString('base64')}`;

                    }
                    else if (string && !ip && !dataUri && !base64 && !isoDate && !guid && !hostname && !uri && !email && !token && !regex) {
                        const minLen = Math.min(...Object.keys(string).map((key) => parseInt(key, 10)));
                        const maxLen = Math.max(...Object.keys(string).map((key) => parseInt(key, 10)));
                        let max = maxLen;
                        let min = minLen;

                        if (rules.length !== undefined) {
                            res = string[rules.length] ? chance.pickone(string[rules.length]) : res;
                        }
                        else {
                            if (rules.max !== undefined) {
                                if (rules.max >= minLen) {
                                    max = Math.min(rules.max, maxLen);
                                }
                                else {
                                    max = 0;
                                }
                            }

                            if (rules.min !== undefined) {
                                if (rules.min <= maxLen) {
                                    min = Math.max(rules.min, minLen);
                                }
                                else {
                                    min = Infinity;
                                }
                            }

                            if (max >= min) {
                                let length;
                                if (max === min) {
                                    length = max;
                                }
                                else {
                                    length = chance.integer({ min, max });

                                    if (!string[length]) {
                                        length = Object.keys(string).reduce((len, key) => {

                                            key = parseInt(key, 10);
                                            if (key >= min && key <= max) {
                                                if (!len || (Math.abs(length - len) > Math.abs(length - key))) {
                                                    return key;
                                                }
                                            }

                                            return len;
                                        }, 0);
                                    }

                                }

                                res = string[length] ? chance.pickone(string[length]) : res;
                            }
                        }
                    }
                }
                else if (desc.type === 'binary') {
                    const randFile = file[chance.pickone(Object.keys(file))];
                    res = randFile.data;
                }

                return replace ? replace(res, desc, rules) : res;
            };
        }

        debug('path', route.path);
        debug('settings', route.settings);
        debug('validate', validate);

        const records = [];
        const paramsConf = Hoek.unique(params).reduce((obj, param) => {

            const paramMatch = new RegExp(`{${param}(\\?|(\\*)(\\d)?)?}`);
            const matches = route.path.match(paramMatch);

            const validation = validate.params && validate.params._inner && validate.params._inner.children && validate.params._inner.children.reduce((found, row) => {

                return found ? found : (row.key === param && row.schema || found);
            }, null);

            const conf = {
                wildcard: !!matches[2],
                count: matches[3] && parseInt(matches[3], 10),
                optional: !matches[3] && !!matches[1],
                validation
            };


            if (!conf.validation) {
                if (conf.wildcard) {
                    if (conf.count) {
                        conf.validation = paramsSchema.count.min(conf.count * 3);
                    }
                    else {
                        conf.validation = paramsSchema.wildcard;
                    }

                }
                else if (conf.optional) {
                    conf.validation = paramsSchema.optional;
                }
                else {
                    conf.validation = paramsSchema.required;
                }
            }


            obj[param] = conf;

            return obj;
        }, {});

        const localValidation = {
            query: validate.query || Joi.object().unknown(),
            payload: validate.payload || Joi.object().pattern((/.{0,10}/), Joi.any()),
            params: validate.params || Joi.object(Hoek.unique(params).reduce((obj, param) => {

                obj[param] = paramsConf[param].validation;
                return obj;
            }, {})),
            headers: validate.headers
        };

        for (let i = 0; i < permutations; i += 1 ) {
            const data = {
                path   : route.path,
                method : route.method,
                query  : Juzz(localValidation.query, juzzOptions),
                payload: route.method !== 'get' ? Juzz(localValidation.payload, juzzOptions) : undefined,
                params : params.length ? Juzz(localValidation.params, juzzOptions) : undefined,
                headers: localValidation.headers ? Juzz(localValidation.headers, juzzOptions) : undefined
            };

            internal.splitParams(juzzOptions, paramsConf, data);

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

    splitParams(juzzOptions, paramsConf, data) {

        Object.keys(paramsConf).forEach((param) => {

            let value = data.params[param];
            const conf = paramsConf[param];

            if (!value && !conf.optional) {
                value = Juzz(conf.validation, juzzOptions);
            }

            if (!value) {
                data.params[param] = undefined;
                return;
            }

            try {
                value = decodeURIComponent(value);
            }
            catch (e) {
                //ignore error;
            }

            if (conf.wildcard) {
                if ((conf.count && value.split('/').length !== conf.count) || value.indexOf('/') === -1) {
                    value = value.split('/').join('');
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
                                partLen = Math.max(1, remaining - ((i - 1) * 2));
                            }
                        }

                        remaining -= partLen;
                        const partVal = value.substring(0, partLen);
                        parts.push(encodeURIComponent(partVal));
                        value = value.substring(partLen);
                    }

                    value = parts.join('/');
                }
                else {
                    value = value.split('/').map(encodeURIComponent).join('/');
                }

            }
            else {
                value = encodeURIComponent(value);
            }

            debug('param', param, value);
            data.params[param] = value;
        });
    },

    automate(server, route, records, options) {

        const { describe, it, validResponse, injectReplace } = options;

        describe(`Funzzing ${route.method} ${route.path}`, () => {

            records.forEach((record) => {

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
};

module.exports = function FunzzInit(server, op = {}) {

    Joi.assert(server, serverSchema, 'server');

    const { value: options, error: optionsError } = Joi.validate(op, configSchema, { context: { it: global.it, describe: global.describe } });
    if (optionsError) {
        throw optionsError;
    }

    if (options.usePayloads && options.usePayloads.length) {
        options.payloads = LoadFuzzDb(options.usePayloads);
    }

    const { automate } = options;
    const table = server.table();
    const records = [];


    table.forEach((route) => {

        let routeRecords;
        if (route.method !== '*') {
            routeRecords = internal.generateRoute(route, options);
        }
        else {
            routeRecords = [];
            methods.forEach((method) => {

                routeRecords.push(...internal.generateRoute(Object.assign({}, route, { method }), options));
            });
        }


        if (automate) {

            internal.automate(server, route, routeRecords, options);
        }

        records.push(...routeRecords);
    });

    return records;
};


module.exports.inject = function inject(server, record, replace) {

    Joi.assert(record, recordSchema, 'record');
    replace && Joi.assert(replace, injectReplaceSchema, 'replace');

    return internal.inject(server, record, replace);
};

module.exports.generateRoute = function generateRoute(server, route, op) {

    Joi.assert(server, serverSchema, 'server');
    Joi.assert(route, routeSchema, 'route');

    const { value: options, error: optionsError } = Joi.validate(Object.assign({ automate: false }, op), configSchema, { context: { it: global.it, describe: global.describe } });
    if (optionsError) {
        throw optionsError;
    }

    const { usePayloads, automate } = options;

    if (usePayloads && usePayloads.length) {
        options.payloads = LoadFuzzDb(options.usePayloads);
    }

    if (!route.public) { //assume we got a public route try to find real instance
        const table = server.table();
        const fRoute = table.find((tRoute) => tRoute.method === route.method && tRoute.path === route.path);

        if (!fRoute) {
            throw new Error(`failed to find hapi route conf from ${route.path}(${route.method})`);
        }

        route = fRoute;
    }


    const routeRecords = internal.generateRoute(route, options);

    if (automate) {

        internal.automate(server, route, routeRecords, options);
    }

    return routeRecords;
};
