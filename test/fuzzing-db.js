'use strict';

// Load modules
const Lab        = require('@hapi/lab');
const LoadFuzzDb = require('../lib/fuzzing-db');
const { expect } = require('@hapi/code');

// Test shortcuts

const { describe, it } = exports.lab = Lab.script();


describe('Fuzzing-DB', () => {

    describe('load', () => {

        it('should throw if loading key does not exist', () => {

            expect(() => LoadFuzzDb(['bla'])).to.throw('Unrecognized path bla');
            expect(() => LoadFuzzDb(['string'])).to.throw('Unrecognized string payload undefined');
            expect(() => LoadFuzzDb(['file'])).to.throw('Unrecognized file payload undefined');
            expect(() => LoadFuzzDb(['string.bla'])).to.throw('Unrecognized string payload bla');
            expect(() => LoadFuzzDb(['file.bla'])).to.throw('Unrecognized file payload bla');
        });

        it('should load and cache correct data', () => {

            const start = Date.now();
            const payloads = LoadFuzzDb(['string.all']);
            const time = Date.now() - start;
            expect(payloads.string).to.exist();
            expect(payloads.file).to.not.exist();
            const start2 = Date.now();
            const payloads2 = LoadFuzzDb(['string.all']);
            const time2 = Date.now() - start2;
            expect(payloads2).to.be.equal(payloads);
            expect(time2).to.be.below(time);
        });

        it('should return only requested data', () => {

            const payloads = LoadFuzzDb(['file.zip']);
            expect(payloads.string).to.not.exist();
            expect(payloads.file).to.exist();
            expect(payloads.file['zip-bomb.zip']).to.exist();
            const payloads2 = LoadFuzzDb(['file.image']);
            expect(payloads2.string).to.not.exist();
            expect(payloads2.file).to.exist();
            expect(payloads2.file['zip-bomb.zip']).to.not.exist();
        });

        it('should return all data', () => {

            const payloads = LoadFuzzDb(['all']);
            expect(payloads.string).to.exist();
            expect(payloads.file).to.exist();
        });
    });


});

