'use strict';

const Path = require('path');
const Fs   = require('fs');

const assets = {
    string: {
        generic: [
            'assets/Fuzzing/UnixAttacks.fuzzdb.txt',
            'assets/Fuzzing/big-list-of-naughty-strings.txt',
            'assets/Fuzzing/Command-Injection-commix.txt'

        ],
        sql: [
            'assets/Fuzzing/Generic-SQLi.txt',
            'assets/Fuzzing/Polyglots/SQLi-Polyglots.txt'
        ],
        noSql: [
            'assets/Fuzzing/NoSQL.txt'
        ],
        JSON: [
            'assets/Fuzzing/JSON.Fuzzing.txt'
        ],
        XSS: [
            'assets/Fuzzing/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt',
            'assets/Fuzzing/Polyglots/XSS-Polyglots.txt'
        ],
        URI: [
            'assets/Fuzzing/URI-XSS.fuzzdb.txt'
        ],
        userAgent: [
            'assets/Fuzzing/UserAgents.fuzz.txt'
        ]
    },
    file : {
        image: [
            'assets/Payloads/Images/lottapixel.jpg',
            'assets/Payloads/Images/uber.gif'
        ],
        zip: [
            'assets/Payloads/Zip-Bombs/zip-bomb.zip'
        ]
    }
};

const assetsCache = { string: {}, file: {} };

const internal = {

    loadAssets(paths) {

        const string = {};
        const file = {};

        paths.forEach((path) => {

            if (path === 'all') {
                Object.keys(assets.string).forEach((key) => {

                    string[key] = internal.loadString(key);
                });
                Object.keys(assets.file).forEach((key) => {

                    file[key] = internal.loadFile(key);
                });
            }
            else {
                const parts = path.split('.');
                let method;
                let obj;
                if (parts[0] === 'string') {
                    method = internal.loadString;
                    obj = string;
                }
                else if (parts[0] === 'file') {
                    method = internal.loadFile;
                    obj = file;
                }
                else {
                    throw Error(`Unrecognized path ${path}`);
                }

                if (parts[1] === 'all') {
                    Object.keys(assets[parts[0]]).forEach((key) => {

                        obj[key] = method(key);
                    });
                }
                else {
                    obj[parts[1]] = method(parts[1]);
                }
            }
        });

        const res = {};
        Object.keys(string).forEach((key) => {

            res.string = res.string || {};
            Object.keys(string[key]).forEach((len) => {

                if (!res.string[len]) {
                    res.string[len] = string[key][len];
                }
                else {
                    res.string[len] = res.string[len].concat(string[key][len]);
                }

            });

        });

        Object.keys(file).forEach((key) => {

            res.file = res.file || {};
            Object.keys(file[key]).forEach((name) => {

                res.file[name] = file[key][name];
            });

        });

        return res;
    },

    loadString(key) {

        if (assetsCache.string[key]) {
            return assetsCache.string[key];
        }

        if (!assets.string[key]) {
            throw new Error(`Unrecognized string payload ${key}`);
        }

        const obj = {};

        assets.string[key].forEach((file) => {

            Fs.readFileSync(Path.join(__dirname, '..', file), { encoding: 'utf-8' })
                .split('\n')
                .forEach((line) => {

                    if (!(/^\s*$/).test(line) && line.indexOf('#') !== 0) {
                        const len = line.length;
                        obj[len] = obj[len] || [];
                        obj[len].push(line);
                    }
                });
        });
        assetsCache.string[key] = obj;
        return obj;
    },


    loadFile(key) {

        if (assetsCache.file[key]) {
            return assetsCache.file[key];
        }

        if (!assets.file[key]) {
            throw new Error(`Unrecognized file payload ${key}`);
        }

        const obj = {};

        assets.file[key].forEach((file) => {

            const name = Path.basename(file);
            const ext = Path.extname(name);
            let mime;
            if (ext === '.zip') {
                mime = 'application/zip';
            }
            else if (ext === '.gif') {
                mime = 'image/gif';
            }
            else {
                mime = 'image/jpeg';
            }

            obj[name] = {
                name,
                mime,
                data: Fs.readFileSync(Path.join(__dirname, '..', file))
            };
        });

        assetsCache.file[key] = obj;
        return obj;
    }
};



module.exports = internal.loadAssets;
