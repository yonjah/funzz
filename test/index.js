'use strict';

// Load modules
const Lab        = require('lab');
const Funzz      = require('../lib');
const LoadFuzzDb = require('../lib/fuzzing-db');
const Hapi       = require('hapi');
const Joi        = require('joi');
const { expect } = require('code');

// Test shortcuts

const { describe, it, beforeEach } = exports.lab = Lab.script();


const testResponse = function testResponse(response, code) {

    try {
        expect(response.statusCode).to.equal(code);

    }
    catch (e) {

        let message = `${e.message} ${JSON.stringify(response.result)}`;
        if (response.request.response._error) {
            message += `\n${response.request.response._error.message}`;
        }

        throw new Error(message);
    }
};

describe('Funzz', () => {

    describe('setup', () => {

        let server;

        beforeEach(() =>  {

            server = Hapi.server();

        });

        it('should throw on bad options', () => {

            expect(() => Funzz(server, { automate: false, nonexist: 1 })).to.throw('"nonexist" is not allowed');
        });
    });

    describe('generator', () => {

        const options = { automate: false, permutations: 1 };
        let server;

        beforeEach(() =>  {

            server = Hapi.server();
        });

        it('should return fuzzing for all routes', () => {

            server.route({ method: 'GET', path: '/test-routes', handler: () => 'ok' });
            server.route({ method: 'POST', path: '/test-routes', handler: () => 'ok' });

            const res = Funzz(server, options);
            expect(res).to.have.length(2);
            expect(res[0].path).to.be.equal('/test-routes');
            expect(res[1].path).to.be.equal('/test-routes');
        });

        it('should return fuzzing for all routes with wildcard method', () => {

            server.route({ method: '*', path: '/test-wc-routes', handler: () => 'ok' });

            const res = Funzz(server, options);
            expect(res).to.have.length(6);
            expect(res[0].path).to.be.equal('/test-wc-routes');
        });

        it('should return fuzzing for all routes with multiple methods', () => {

            server.route({ method: ['GET', 'POST'], path: '/test-routes', handler: () => 'ok' });

            const res = Funzz(server, options);
            expect(res).to.have.length(2);
            expect(res[0].path).to.be.equal('/test-routes');
        });

        it('should permute fuzzing by permutations setting', () => {

            server.route({ method: 'GET', path: '/test-permutations', handler: () => 'ok' });
            server.route({ method: 'POST', path: '/test-permutations', handler: () => 'ok' });

            const res = Funzz(server, { automate: false, permutations: 3 });
            expect(res).to.have.length(6);
            res.forEach((route) => {

                expect(route.path).to.be.equal('/test-permutations');
            });
        });

        it('should contain valid fuzzing injection data for empty get route', async () => {

            server.route({ method: 'GET', path: '/test-get', handler: () => 'ok' });
            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get');
            expect(data.method).to.be.equal('get');
            expect(data.payload).to.not.exist();
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });


        it('should inject empty query if validation does not allow it', async () => {

            server.route({ method: 'GET', path: '/test-get', handler: () => 'ok', config: { validate: { query: false } } });
            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get');
            expect(data.method).to.be.equal('get');
            expect(data.payload).to.not.exist();
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            expect(data.query).to.be.empty();
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should inject random query if validation is not performed', async () => {

            server.route({ method: 'GET', path: '/test-get', handler: () => 'ok', config: { validate: { query: true } } });
            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get');
            expect(data.method).to.be.equal('get');
            expect(data.payload).to.not.exist();
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should contain valid fuzzing injection data by query validation', async () => {

            server.route({ method: 'GET', path: '/test-get', handler: () => 'ok', config: { validate: { query: { id: Joi.number().integer().min(1).max(10).required() } } } });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get');
            expect(data.method).to.be.equal('get');
            expect(data.payload).to.not.exist();
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            expect(data.query).to.exist();
            expect(data.query.id).to.exist();
            expect(data.query.id).to.be.within(1, 10);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should contain valid fuzzing injection data for empty post route', async () => {

            server.route({ method: 'POST', path: '/test-post', handler: () => 'ok' });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-post');
            expect(data.method).to.be.equal('post');
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            expect(data.query).to.exist();
            expect(data.payload).to.exist();
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should inject empty payload if validation does not allow it', async () => {

            server.route({ method: 'POST', path: '/test-post', handler: () => 'ok', config: { validate: { payload: false } } });
            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-post');
            expect(data.method).to.be.equal('post');
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            expect(data.payload).to.be.empty();
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should inject random payload if validation is not performed', async () => {

            server.route({ method: 'POST', path: '/test-post', handler: () => 'ok', config: { validate: { payload: true } } });
            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-post');
            expect(data.method).to.be.equal('post');
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should contain valid fuzzing injection data by query validation for post routes', async () => {

            server.route({ method: 'POST', path: '/test-post-query', handler: () => 'ok', config: { validate: { query: { id: Joi.number().integer().min(1).max(10).required() } } } });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-post-query');
            expect(data.method).to.be.equal('post');
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            expect(data.query).to.exist();
            expect(data.query.id).to.exist();
            expect(data.query.id).to.be.within(1, 10);
            expect(data.payload).to.exist();
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });


        it('should contain valid fuzzing injection data by query and payload validation for post routes', async () => {

            const valid = ['read', 'write', 'execute'];

            server.route({ method: 'POST', path: '/test-post-payload', handler: () => 'ok', config: {
                validate: {
                    query: { id: Joi.number().integer().min(1).max(10).required() },
                    payload: { action: Joi.any().valid(valid).required() }
                }
            } });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-post-payload');
            expect(data.method).to.be.equal('post');
            expect(data.params).to.not.exist();
            expect(data.headers).to.not.exist();
            expect(data.query).to.exist();
            expect(data.query.id).to.exist();
            expect(data.query.id).to.be.within(1, 10);
            expect(data.payload).to.exist();
            expect(data.payload.action).to.exist();
            expect(valid).to.include(data.payload.action);

            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should contain valid fuzzing for params', async () => {

            server.route({ method: 'GET', path: '/test-get-params/{id}', handler: () => 'ok' });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get-params/{id}');
            expect(data.method).to.be.equal('get');
            expect(data.headers).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.query).to.exist();
            expect(data.params).to.exist();
            expect(data.params.id).to.exist();

            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should contain valid fuzzing for params when validation is not performed', async () => {

            server.route({ method: 'GET', path: '/test-get-params/{id}', handler: () => 'ok', config: { validate: { params: true } } });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get-params/{id}');
            expect(data.method).to.be.equal('get');
            expect(data.headers).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.query).to.exist();
            expect(data.params).to.exist();
            expect(data.params.id).to.exist();

            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should contain valid fuzzing for params by params validation for route', async () => {

            server.route({ method: 'GET', path: '/test-get-params/{id}', handler: () => 'ok', config: {
                validate: {
                    params: { id: Joi.number().integer().min(1).max(10).required() }
                }
            } });


            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get-params/{id}');
            expect(data.method).to.be.equal('get');
            expect(data.headers).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.query).to.exist();
            expect(data.params).to.exist();
            expect(data.params.id).to.exist();
            expect(data.params.id).to.be.within(1, 10);

            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should contain valid fuzzing for optional params', async () => {

            server.route({ method: 'GET', path: '/test-get-params/{id}/{action?}', handler: () => 'ok' });


            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get-params/{id}/{action?}');
            expect(data.method).to.be.equal('get');
            expect(data.headers).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.query).to.exist();
            expect(data.params).to.exist();
            expect(data.params.id).to.exist();
            expect(data.params.action).to.exist();

            const response = await Funzz.inject(server, data);
            expect(response.request.url.path).to.not.include('{action?}');
            testResponse(response, 200);
        });

        it('should contain valid fuzzing for optional wildcard params', async () => {

            server.route({ method: 'GET', path: '/test-get-params/{id}/{name*}', handler: () => 'ok' });


            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get-params/{id}/{name*}');
            expect(data.method).to.be.equal('get');
            expect(data.headers).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.query).to.exist();
            expect(data.params).to.exist();
            expect(data.params.id).to.exist();
            expect(data.params.name).to.exist();

            const response = await Funzz.inject(server, data);
            expect(response.request.url.path).to.not.include('{name*}');
            testResponse(response, 200);
        });

        it('should contain valid fuzzing for optional wildcard params with length limit', async () => {

            server.route({ method: 'GET', path: '/test-get-params/{id}/{name*2}', handler: () => 'ok' });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get-params/{id}/{name*2}');
            expect(data.method).to.be.equal('get');
            expect(data.headers).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.params).to.exist();
            expect(data.params.id).to.exist();
            expect(data.params.name).to.exist();
            expect(data.params.name.split('/')).to.have.length(2);

            const response = await Funzz.inject(server, data);
            expect(response.request.url.path).to.not.include('{name*2}');
            testResponse(response, 200);
        });

        it('should contain valid fuzzing for optional wildcard params with length limit when validation is included', async () => {

            server.route({ method: 'GET', path: '/test-get-params/{id}/{name*}', handler: () => 'ok', config: {
                validate: {
                    params: {
                        id: Joi.number().integer().min(1).max(10).required(),
                        name: Joi.string().max(10).required()
                    }
                }
            } });


            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get-params/{id}/{name*}');
            expect(data.method).to.be.equal('get');
            expect(data.headers).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.query).to.exist();
            expect(data.params).to.exist();
            expect(data.params.id).to.exist();
            expect(data.params.name).to.exist();
            expect(decodeURIComponent(data.params.name).length).to.be.most(10);

            const response = await Funzz.inject(server, data);
            expect(response.request.url.path).to.not.include('{name*}');
            testResponse(response, 200);
        });

        it('should not contain header fuzzing unless explicitly set', () => {

            server.route({ method: 'GET', path: '/test-get-headers', handler: () => 'ok' });
            server.route({ method: 'GET', path: '/test-get-all-headers', handler: () => 'ok', config: { validate: { headers: true } } });

            const res = Funzz(server, options);
            expect(res).to.have.length(2);
            res.forEach((data) => {

                expect(data.params).to.not.exist();
                expect(data.payload).to.not.exist();
                expect(data.query).to.exist();
                expect(data.headers).to.not.exist();
            });
        });

        it('should contain valid fuzzing for headers by header validation for route', async () => {

            server.route({ method: 'GET', path: '/test-get-headers', handler: () => 'ok', config: {
                validate: {
                    headers: Joi.object({ 'x-header': Joi.string().required() }).unknown()
                }
            } });


            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.path).to.be.equal('/test-get-headers');
            expect(data.method).to.be.equal('get');
            expect(data.params).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.query).to.exist();
            expect(data.headers).to.exist();
            expect(data.headers).to.have.length(1);
            expect(data.headers['x-header']).to.exist();

            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should throw if generated data does not pass validation and validateData is on', () => {

            server.route({ method: 'GET', path: '/test-validateData', handler: () => 'ok', config: {
                validate: {
                    query: Joi.object({ id: Joi.string().regex(/^[a-z]{5,10}$/).length(4).required() }) //will never have a valid result
                }
            } });


            const error = expect(() => Funzz(server, { automate: false, validateData: true })).to.throw();
            expect(error.message).to.startWith('/test-validateData[get]:\nchild "id" fails because ["id" length must be 4 characters long]');
        });

        it('should pass if generated data does pass validation and validateData is on', () => {

            server.route({ method: 'GET', path: '/test-validateData-pass', handler: () => 'ok', config: {
                validate: {
                    query: Joi.object({ id: Joi.string().regex(/^[a-z]{5,10}$/).required() }) //will never have a valid result
                }
            } });

            const res = Funzz(server, { automate: false, validateData: true });
            const data = res[0];
            expect(data.path).to.be.equal('/test-validateData-pass');
            expect(data.method).to.be.equal('get');
            expect(data.params).to.not.exist();
            expect(data.payload).to.not.exist();
            expect(data.query).to.exist();
            expect(data.query.id).to.be.string();
        });



    });

    describe('automate', () => {

        let server;

        beforeEach(() =>  {

            server = Hapi.server();
        });

        it('should require both it and describe in options', () => {

            expect(() => Funzz(server, { automate: true })).to.throw('"value" contains [automate] without its required peers [it, describe]');
            expect(() => Funzz(server, { automate: true, it: true })).to.throw('child "it" fails because ["it" must be a Function]');
            expect(() => Funzz(server, { automate: true, it() {} })).to.throw('child "it" fails because ["it" must have an arity greater or equal to 2]');
            expect(() => Funzz(server, { automate: true, it(a,b) {} })).to.throw('"value" contains [automate, it] without its required peers [describe]');
            expect(() => Funzz(server, { automate: true, it(a,b) {}, describe: true })).to.throw('child "describe" fails because ["describe" must be a Function]');
            expect(() => Funzz(server, { automate: true, it(a,b) {}, describe() {} })).to.throw('child "describe" fails because ["describe" must have an arity greater or equal to 2]');
        });

        it('should get it and describe from global scope', () => {

            const { it: globalIt, describe: globalDescribe } = global;
            server.route({ method: 'GET', path: '/test-get', handler: () => 'ok', config: { validate: { query: { ids: Joi.array().items(Joi.number().integer().min(2).max(10)).min(1).required() } } } });

            let itCalls = 0;
            let describeCalls = 0;
            try {
                global.it = (title, func) => {

                    expect(title).to.be.include('data:');
                    expect(func).to.be.function();
                    itCalls += 1;
                };

                global.describe = (title, func) => {

                    expect(title).to.be.include('/test-get');
                    expect(func).to.be.function();
                    describeCalls += 1;
                    return func();
                };

                Funzz(server, { automate: true, permutations: 3 });

                expect(describeCalls).to.be.equal(1);
                expect(itCalls).to.be.equal(3);
            }
            finally {
                if (globalIt === undefined) {
                    delete global.it;
                }
                else {
                    global.it = globalIt;
                }

                if (globalDescribe === undefined) {
                    delete global.describe;
                }
                else {
                    global.describe = globalDescribe;
                }
            }
        });

        it('should get it and describe passed in options', () => {

            const { it: globalIt, describe: globalDescribe } = global;
            server.route({ method: 'GET', path: '/test-get', handler: () => 'ok', config: { validate: { query: { ids: Joi.array().items(Joi.number().integer().min(2).max(10)).min(1).required() } } } });

            try {
                let itCalls = 0;
                let describeCalls = 0;
                const options = {
                    automate: true,
                    permutations: 3,
                    it(title, func) {

                        expect(title).to.be.include('data:');
                        expect(func).to.be.function();
                        itCalls += 1;
                    },

                    describe(title, func) {

                        expect(title).to.be.include('/test-get');
                        expect(func).to.be.function();
                        describeCalls += 1;
                        return func();
                    }
                };

                global.it = () => {};
                global.describe = () => {};

                Funzz(server, options);

                expect(describeCalls).to.be.equal(1);
                expect(itCalls).to.be.equal(3);

                itCalls = 0;
                describeCalls = 0;

                global.it = undefined;
                global.describe = undefined;

                Funzz(server, options);

                expect(describeCalls).to.be.equal(1);
                expect(itCalls).to.be.equal(3);
            }
            finally {
                if (globalIt === undefined) {
                    delete global.it;
                }
                else {
                    global.it = globalIt;
                }

                if (globalDescribe === undefined) {
                    delete global.describe;
                }
                else {
                    global.describe = globalDescribe;
                }
            }
        });

        it('should use validResponse to validate the response', async () => {

            server.route({
                method: 'GET',
                path: '/test-get',
                handler: (req, h) => {

                    return h.response('Bad Request').code(400);
                },
                config: { validate: { query: { ids: Joi.array().single().items(Joi.number().integer().min(2).max(10)).min(1).required() } } }
            });
            let error;
            let promise;

            const options = {
                automate: true,
                permutations: 1,
                it: (title, func) => {

                    promise = func();
                },
                describe: (title, func) => func(),
                validResponse: Joi.object({ statusCode: Joi.number().less(400) }).unknown()
            };

            Funzz(server, options);
            expect(promise).to.exist();

            try {
                await promise;
            }
            catch (e) {
                error = e;
            }

            expect(error).to.exist();
            expect(error.message).to.be.include('Bad Request');
            expect(error.message).to.be.include('child "statusCode" fails because ["statusCode" must be less than 400]');
        });

        it('should fail test if to response results in server error', async () => {

            server.route({
                method: 'GET',
                path: '/test-get',
                handler: () => {

                    throw Error('NA!');
                },
                config: { validate: { query: { ids: Joi.array().single().items(Joi.number().integer().min(2).max(10)).min(1).required() } } }
            });
            let error;
            let promise;

            const options = {
                automate: true,
                permutations: 1,
                it: (title, func) => {

                    promise = func();
                },
                describe: (title, func) => func()
            };

            Funzz(server, options);
            expect(promise).to.exist();

            try {
                await promise;
            }
            catch (e) {
                error = e;
            }

            expect(error).to.exist();
            expect(error.message).to.be.include('child "statusCode" fails because ["statusCode" must be less than 500]');
        });

        it('should not include empty result in error', async () => {

            server.route({
                method: 'GET',
                path: '/test-get',
                handler: (res, h) => {

                    return h.continue;
                },
                config: { validate: { query: { ids: Joi.array().single().items(Joi.number().integer().min(2).max(10)).min(1).required() } } }
            });
            let error;
            let promise;

            const options = {
                automate: true,
                permutations: 1,
                it: (title, func) => {

                    promise = func();
                },
                describe: (title, func) => func(),
                validResponse: Joi.object({ statusCode: Joi.number().greater(400) }).unknown()
            };

            Funzz(server, options);
            expect(promise).to.exist();

            try {
                await promise;
            }
            catch (e) {
                error = e;
            }

            expect(error).to.exist();
            expect(error.message.split('\n')).to.have.length(3);
        });

        it('should pass test if to response does not results in serer error', async () => {

            server.route({
                method: 'GET',
                path: '/test-get',
                handler: () => 'ok',
                config: { validate: { query: { ids: Joi.array().single().items(Joi.number().integer().min(2).max(10)).min(1).required() } } }
            });
            let error;
            let promise;

            const options = {
                automate: true,
                permutations: 1,
                it: (title, func) => {

                    promise = func();
                },
                describe: (title, func) => func()
            };

            Funzz(server, options);
            expect(promise).to.exist();

            try {
                await promise;
            }
            catch (e) {
                error = e;
            }

            expect(error).to.not.exist();
        });

        it('should call injectReplace before injecting the data to the server', async () => {

            const uid = Math.ceil(Math.random() * 10e12);

            server.route({
                method: 'POST',
                path: '/test-injectReplace',
                handler: (request) => {

                    expect(request.payload.uid).to.be.equal(uid);
                    return true;
                }
            });

            let promise;

            const options = {
                automate: true,
                permutations: 1,
                it: (title, func) => {

                    promise = func();
                },
                describe: (title, func) => func(),
                injectReplace(record, data) {

                    expect(record.path).to.be.equal('/test-injectReplace');
                    expect(data.url).to.startWith('/test-injectReplace');
                    data.payload = { uid };
                    return data;
                }
            };

            Funzz(server, options);
            expect(promise).to.exist();

            await promise;
        });


    });

    describe('payloads', () => {

        let server;

        beforeEach(() =>  {

            server = Hapi.server();
        });

        it('should replace string with valid payload', async () => {

            const usePayloads = ['string.noSql'];
            const { string } = LoadFuzzDb(usePayloads);

            const payloads =  Object.keys(string).reduce((arr, len) => arr.concat(string[len]), []);
            const options = { automate: false, usePayloads, permutations: 1 };
            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(payloads).to.include(data.query.name);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should replace string with valid payload with length rule', async () => {

            const usePayloads = ['string.generic'];
            const { string } = LoadFuzzDb(usePayloads);


            const len = 15;
            const payloads =  string[len];
            const options = { automate: false, usePayloads, permutations: 1 };
            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().length(len).required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(data.query.name).to.have.length(len);
            expect(payloads).to.include(data.query.name);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should replace string with valid payload with min max rules', async () => {

            const usePayloads = ['string.generic'];
            const { string } = LoadFuzzDb(usePayloads);


            const minLen = 10;
            const maxLen = 11;
            const payloads =  string[minLen].concat(string[maxLen]);
            const options = { automate: false, usePayloads, permutations: 1 };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().min(minLen).max(maxLen).required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(data.query.name.length).to.be.at.least(minLen);
            expect(data.query.name.length).to.be.at.most(maxLen);
            expect(payloads).to.include(data.query.name);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should replace string with valid payload with min = max rules', async () => {

            const usePayloads = ['string.generic'];
            const { string } = LoadFuzzDb(usePayloads);


            const len = 10;
            const payloads =  string[len];
            const options = { automate: false, usePayloads, permutations: 1 };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().min(len).max(len).required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(data.query.name.length).to.be.equal(len);
            expect(payloads).to.include(data.query.name);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should replace string if min is smaller than available strings', async () => {

            const usePayloads = ['string.URI'];
            const { string } = LoadFuzzDb(usePayloads);

            const minLen = 114;
            const options = { automate: false, usePayloads, permutations: 1 };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().min(minLen).required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(data.query.name.length).to.be.at.least(minLen);
            expect(Object.keys(string).reduce((payloads, len) => {

                if (len >= minLen) {
                    payloads = payloads.concat(string[len]);
                }
                else {
                    expect(string[len]).to.not.include(data.query.name);
                }

                return payloads;
            }, [])).to.include(data.query.name);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });


        it('should not replace string if min is larger than available strings', async () => {

            const usePayloads = ['string.URI'];
            const { string } = LoadFuzzDb(usePayloads);

            const minLen = 500;
            const options = { automate: false, usePayloads, permutations: 1 };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().min(minLen).required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(data.query.name.length).to.be.at.least(minLen);
            Object.keys(string).forEach((len) => expect(string[len]).to.not.include(data.query.name));
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should replace string if max is bigger than available strings', async () => {

            const usePayloads = ['string.URI'];
            const { string } = LoadFuzzDb(usePayloads);

            const maxLen = 90;
            const options = { automate: false, usePayloads, permutations: 1 };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().max(maxLen).required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(data.query.name.length).to.be.at.most(maxLen);
            expect(Object.keys(string).reduce((payloads, len) => {

                if (maxLen >= len) {
                    payloads = payloads.concat(string[len]);
                }
                else {
                    expect(string[len]).to.not.include(data.query.name);
                }

                return payloads;
            }, [])).to.include(data.query.name);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });


        it('should not replace string if max is smaller than available strings', async () => {

            const usePayloads = ['string.URI'];
            const { string } = LoadFuzzDb(usePayloads);

            const maxLen = 50;
            const options = { automate: false, usePayloads, permutations: 1 };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().max(maxLen).required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(data.query.name.length).to.be.at.most(maxLen);
            Object.keys(string).forEach((len) => expect(string[len]).to.not.include(data.query.name));
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should replace string with valid data uri', async () => {

            const usePayloads = ['file.zip'];
            const { file } = LoadFuzzDb(usePayloads);
            const zipFile = file['zip-bomb.zip'];
            const options = { automate: false, usePayloads, permutations: 1 };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { file: Joi.string().dataUri().required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.file).to.exist();
            expect(data.query.file).to.be.equal(`data:${zipFile.mime};base64,${zipFile.data.toString('base64')}`);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should replace binary data with valid file data', async () => {

            const usePayloads = ['file.zip'];
            const { file } = LoadFuzzDb(usePayloads);
            const zipFile = file['zip-bomb.zip'];
            const options = { automate: false, usePayloads, permutations: 1 };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { file: Joi.binary().required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.file).to.exist();
            expect(data.query.file).to.be.equal(zipFile.data);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });

        it('should call user provided replace method with payload', async () => {

            const usePayloads = ['string.generic'];
            const { string } = LoadFuzzDb(usePayloads);
            const len = 15;
            const fakeRes = 'fakeRes' + Math.random().toString(16).substring(0, 8);
            const replace = function (res, desc) {

                if (desc.type === 'string') {
                    expect(string[len]).to.include(res);
                    return fakeRes;
                }

                return res;
            };

            const options = { automate: false, usePayloads, permutations: 1, juzzOptions: { replace } };

            server.route({
                method: 'GET',
                path: '/test-string-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().length(len).required() }
                    }
                }
            });

            const res = Funzz(server, options);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(data.query.name).to.be.equal(fakeRes);
            const response = await Funzz.inject(server, data);
            testResponse(response, 200);
        });


    });

    describe('routeGenerator', () => {

        const options = { permutations: 1 };
        let server;

        beforeEach(() =>  {

            server = Hapi.server();
        });

        it('should throw if server is missing or not match expected hapi server methods', () => {

            expect(() => Funzz.generateRoute()).to.throw('server "value" is required');
            expect(() => Funzz.generateRoute({ notServer: true })).to.throw('server {\n  "notServer": true,\n  \u001b[41m"table"\u001b[0m\u001b[31m [1]: -- missing --\u001b[0m\n}\n\u001b[31m\n[1] "table" is required\u001b[0m');
        });

        it('should throw if route is missing or not match expected hapi route methods', () => {

            expect(() => Funzz.generateRoute(server)).to.throw('route "value" is required');
            expect(() => Funzz.generateRoute(server, { method: 'get' })).to.throw('route {\n  "method": "get",\n  \u001b[41m"path"\u001b[0m\u001b[31m [1]: -- missing --\u001b[0m\n}\n\u001b[31m\n[1] "path" is required\u001b[0m');
            expect(() => Funzz.generateRoute(server, { path: [], method: 'get' })).to.throw('route {\n  "method": "get",\n  "path" \u001b[31m[1]\u001b[0m: []\n}\n\u001b[31m\n[1] "path" must be a string\u001b[0m');
            expect(() => Funzz.generateRoute(server, { path: '/', method: 'notMethod' })).to.throw('route {\n  "path": "/",\n  "method" \u001b[31m[1]\u001b[0m: "notMethod"\n}\n\u001b[31m\n[1] "method" must be one of [get, post, put, patch, delete, options]\u001b[0m');
        });

        it('should throw on bad options', () => {

            expect(() => Funzz.generateRoute(server, { path: '/', method: 'get' }, { automate: false, nonexist: 1 })).to.throw('"nonexist" is not allowed');
        });

        it('should throw if route search fails', () => {

            expect(() => Funzz.generateRoute(server, { path: '/missing', method: 'get' })).to.throw('failed to find hapi route conf from /missing(get)');
        });


        it('should return fuzzing for selected route', () => {

            server.route({ method: 'GET', path: '/test-routes-gen', handler: () => 'ok' });
            server.route({ method: 'POST', path: '/test-routes-gen', handler: () => 'ok' });

            const route = server.table()[0];
            const res = Funzz.generateRoute(server, route, options);
            expect(res).to.have.length(1);
            expect(res[0].path).to.be.equal(route.path);
            expect(res[0].method).to.be.equal(route.method);
        });

        it('should return fuzzing for selected route with params', () => {

            server.route({ method: 'GET', path: '/test-routes-gen-params/{name}', handler: () => 'ok' });
            server.route({ method: 'POST', path: '/test-routes-gen-params/{name}', handler: () => 'ok' });

            const route = server.match('get', '/test-routes-gen-params/a');
            const res = Funzz.generateRoute(server, route, options);
            expect(res).to.have.length(1);
            expect(res[0].path).to.be.equal(route.path);
            expect(res[0].method).to.be.equal(route.method);
        });

        it('should return fuzzing for selected route with optional params', () => {

            server.route({ method: 'GET', path: '/test-routes-gen-params/{name?}', handler: () => 'ok' });
            server.route({ method: 'POST', path: '/test-routes-gen-params/{name?}', handler: () => 'ok' });

            const route = server.match('post', '/test-routes-gen-params/a');
            const res = Funzz.generateRoute(server, route, options);
            expect(res).to.have.length(1);
            expect(res[0].path).to.be.equal(route.path);
            expect(res[0].method).to.be.equal(route.method);
        });

        it('should return fuzzing for selected route with wildcard params', () => {

            server.route({ method: 'GET', path: '/test-routes-gen-params/{name*}', handler: () => 'ok' });
            server.route({ method: 'POST', path: '/test-routes-gen-params/{name*}', handler: () => 'ok' });

            const route = server.match('get', '/test-routes-gen-params/a/b/c');
            const res = Funzz.generateRoute(server, route, options);
            expect(res).to.have.length(1);
            expect(res[0].path).to.be.equal(route.path);
            expect(res[0].method).to.be.equal(route.method);
        });

        it('should replace string with valid payload', () => {

            const usePayloads = ['string.noSql'];
            const { string } = LoadFuzzDb(usePayloads);

            const payloads =  Object.keys(string).reduce((arr, len) => arr.concat(string[len]), []);
            const pOptions = { automate: false, usePayloads, permutations: 1 };
            server.route({
                method: 'GET',
                path: '/test-routes-gen-params-payload',
                handler: () => 'ok',
                config: {
                    validate: {
                        query: { name: Joi.string().required() }
                    }
                }
            });

            const route = server.match('get', '/test-routes-gen-params-payload');
            const res = Funzz.generateRoute(server, route, pOptions);
            expect(res).to.have.length(1);
            const data = res[0];
            expect(data.query).to.exist();
            expect(data.query.name).to.exist();
            expect(payloads).to.include(data.query.name);
        });

        it('should inject to server when automate is true', async () => {

            server.route({
                method: 'GET',
                path: '/test-route-gen-automate',
                handler: () => 'ok',
                config: { validate: { query: { ids: Joi.array().single().items(Joi.number().integer().min(2).max(10)).min(1).required() } } }
            });
            let promise;

            const rOptions = {
                automate: true,
                permutations: 1,
                it: (title, func) => {

                    promise = func();
                },
                describe: (title, func) => func()
            };

            const route = server.match('get', '/test-route-gen-automate');
            Funzz.generateRoute(server, route, rOptions);
            expect(promise).to.exist();

            await promise;
        });


    });

    describe('inject', () => {

        const server = Hapi.server();
        server.route({ method: 'GET', path: '/test-inject', handler: () => 'ok' });

        it('should allow replace of injected data', async () => {

            const res = Funzz(server, { automate: false, permutations: 1 });
            expect(res).to.have.length(1);
            const record = res[0];
            const response = await Funzz.inject(server, record, (rec, data) => {

                expect(rec).to.be.equal(record);
                expect(data.url).to.startWith('/test-inject');
                expect(data.method).to.be.equal('get');

                return {
                    url : '/not_exist',
                    method: 'get'
                };
            });

            testResponse(response, 404);
        });

    });

    describe('params', () => {

        const options = { permutations: 1, validateData: true };
        let server;

        beforeEach(() =>  {

            server = Hapi.server();
        });

        it('should correctly generate param with custom validator', () => {

            server.route({ method: 'GET', path: '/test-params/{id}', handler: () => 'ok', config: {
                validate: {
                    params: { id: Joi.number().integer().min(1).max(10) }
                }
            } });
            const route = server.table()[0];
            for (let i = 10; i > 0; i -= 1){
                const res = Funzz.generateRoute(server, route, options);
                expect(res).to.have.length(1);
                expect(res[0].params).to.exist();
                expect(parseInt(res[0].params.id, 10)).to.not.be.NaN();
            }
        });

        it('should correctly generate wildcard param with custom validator', () => {

            server.route({ method: 'GET', path: '/test-params/{id*2}', handler: () => 'ok', config: {
                validate: {
                    params: { id: Joi.string().regex(/^\d{1,5}\/\d{1,5}$/) }
                }
            } });
            const route = server.table()[0];
            for (let i = 10; i > 0; i -= 1){
                const res = Funzz.generateRoute(server, route, options);
                expect(res).to.have.length(1);
                expect(res[0].params).to.exist();
                expect(res[0].params.id).to.exist();
                const ids = res[0].params.id.split('/');
                expect(ids).to.have.length(2);
                expect(parseInt(ids[0], 10)).to.not.be.NaN();
                expect(parseInt(ids[1], 10)).to.not.be.NaN();
            }
        });

    });

});
