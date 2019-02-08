'use strict';

const Url        = require('url');
const Util       = require('util');
const Juzz       = require('juzz');
const Joi        = require('joi');
const debug      = require('debug')('Funzz');
const LoadFuzzDb = require('./fuzzing-db.js');

const chance     = new (require('chance'))();

const utils      = {
    unique(arr) {

        return Array.from(new Set(arr));
    }
};

const methods = ['get', 'post', 'put', 'patch', 'delete', 'options'];

const injectReplaceSchema = Joi.func().arity(2);

const configSchema = Joi.object({
    automate: Joi.boolean().default(true),
    validateData: Joi.boolean().default(false),
    permutations: Joi.number().integer().default(10),
    validResponse: Joi.object().schema().default(Joi.object({ statusCode: Joi.number().integer().less(500) }).unknown()),
    juzzOptions: Joi.object().unknown().default({}),
    usePayloads: Joi.array().items(Joi.string()).single(),
    regexPayloadsAttempts: Joi.number().integer().default(10),
    state: Joi.object().pattern(/.*/, Joi.object().schema()),
    injectReplace: injectReplaceSchema
}).when(Joi.object({ automate: Joi.any().valid(true) }).unknown(), { then: Joi.object({
    it: Joi.func().minArity(2).default(Joi.ref('$it')),
    describe: Joi.func().minArity(2).default(Joi.ref('$describe'))
}).and('automate', 'it', 'describe') });

const serverSchema = Joi.object({
    table: Joi.func().required(),
    inject: Joi.func().required(),
    states: Joi.object({
        names: Joi.array(),
        settings: Joi.object(),
        cookies: Joi.object()
    }).unknown().required()
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
    state: Joi.object(),
    params: Joi.object()
});

const paramsSchema = {
    wildcard: Joi.string().allow(''),
    count: Joi.string().required(),
    optional: Joi.string().allow(''),
    required: Joi.string().required()
};



const internal = {

    async inject(server, record, replace) {

        let data = {
            url: record.path,
            method: record.method,
            payload: record.payload,
            headers: record.headers
        };

        if (record.state && Object.keys(record.state).length) {
            data.headers = Object.assign({}, data.headers, { Cookie: await internal.stringifyCookie(server, record.state) });
        }

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

    staethoodInvalid: {
        // statehood invalid chars validations for cookie name and value
        name: {
            strict: /[\x00-\x20\\",;:()<>@/[\]?={}\x7F]/g,
            loose: /[=;\s]/g
        },
        value: {
            strict: /[\x00-\x20\\",;\x7F]/g,
            looseQuotes: /[";]/g, // when value is wrapped in quotes
            looseSemicolon: /;/g //wehn value is not wrapped
        }
    },

    async stringifyCookie(server, state) {

        const { cookies, settings } = server.states;

        const cookie = await server.states.format(
            Object.keys(state).map((name) => {

                const def = cookies[name] ? Object.assign({}, settings, cookies[name]) : settings;
                const invalidNameExp = def.strictHeader ? internal.staethoodInvalid.name.strict : internal.staethoodInvalid.name.loose;
                let value = state[name];

                name = name.replace(invalidNameExp, '');
                if (def.encoding === 'none') {
                    if (typeof value !== 'string') {
                        value = JSON.stringify(value);
                    }

                    if (def.strictHeader) {
                        value = value.replace(internal.staethoodInvalid.value.strict, '');
                    }
                    else if (value[0] === '"' && value[value.length - 1] === '"') {
                        value = value.replace(internal.staethoodInvalid.value.looseQuotes, '');
                    }
                    else {
                        value = value.replace(internal.staethoodInvalid.value.looseSemicolon, '');
                    }
                }

                return { name, value, options: { ttl: null, isSecure: false, isHttpOnly: false, isSameSite: false, domain: false, path: false } };
            })
        );

        return cookie.join('; ');
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

                if (desc.type === 'string' && !desc.valids) {
                    const { ip, dataUri, base64, isoDate, guid, hostname, uri, email, token, regex, hex } = rules;

                    if (file && dataUri) {

                        const randFile = file[chance.pickone(Object.keys(file))];
                        const optRes   = `data:${randFile.mime};base64,${randFile.data.toString('base64')}`;
                        debug('replace string', res, optRes);
                        res = optRes;
                    }
                    else if (string && !ip && !dataUri && !base64 && !isoDate && !guid && !hostname && !uri && !email && !token && !hex) {
                        const minLen = Math.min(...Object.keys(string).map((key) => parseInt(key, 10)));
                        const maxLen = Math.max(...Object.keys(string).map((key) => parseInt(key, 10)));
                        let max = maxLen;
                        let min = minLen;
                        let length = 0;

                        if (rules.length !== undefined) {
                            length = rules.length;
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
                            }
                        }

                        if (regex && string[length]) {
                            for (let i = options.regexPayloadsAttempts; i > 0; i -= 1) {
                                const optRes = chance.pickone(string[length]);
                                if (regex.invert ? !regex.pattern.test(optRes) : regex.pattern.test(optRes)) {
                                    debug('replace string', res, optRes);
                                    res = optRes;
                                    break;
                                }
                            }
                        }
                        else if (string[length]) {
                            const optRes = chance.pickone(string[length]);
                            debug('replace string', res, optRes);
                            res = optRes;
                        }
                    }
                }
                else if (file && desc.type === 'binary' && !desc.valids) {
                    const fileKey  = chance.pickone(Object.keys(file));
                    const randFile = file[fileKey];
                    debug('replace binary res with ', fileKey);
                    res = randFile.data;
                }

                return replace ? replace(res, desc, rules) : res;
            };
        }

        debug('path', route.path);
        debug('settings', route.settings);
        debug('validate', validate);

        const records = [];
        const paramsConf = utils.unique(params).reduce((obj, param) => {

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
            params: validate.params || Joi.object(utils.unique(params).reduce((obj, param) => {

                obj[param] = paramsConf[param].validation;
                return obj;
            }, {})),
            headers: validate.headers,
            state: validate.state || (options.state && Joi.object(options.state))
        };

        for (let i = 0; i < permutations; i += 1 ) {
            const data = {
                path   : route.path,
                method : route.method,
                query  : Juzz(localValidation.query, juzzOptions),
                payload: route.method !== 'get' ? Juzz(localValidation.payload, juzzOptions) : undefined,
                params : params.length ? Juzz(localValidation.params, juzzOptions) : undefined,
                headers: localValidation.headers ? Juzz(localValidation.headers, juzzOptions) : undefined,
                state  : localValidation.state ? Juzz(localValidation.state, juzzOptions) : undefined
            };

            internal.splitParams(juzzOptions, paramsConf, data);

            if (validateData) {
                ['query', 'headers', 'state', 'payload', 'params'].forEach((prop) => {

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

                        const respError = response && response.request && response.request.response._error;

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
    },

    serverState(server) {

        const names = server.states.names;

        return names.length ? server.states.names.reduce((obj, name) => {

            obj[name] = Joi.string().required();
            return obj;
        }, {}) : null;
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

    if (options.state === undefined) {
        options.state = internal.serverState(server);
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

    if (options.state === undefined) {
        options.state = internal.serverState(server);
    }

    const routeRecords = internal.generateRoute(route, options);

    if (automate) {

        internal.automate(server, route, routeRecords, options);
    }

    return routeRecords;
};
