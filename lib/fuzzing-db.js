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

const loadedAssets = { loaded: [] };

const internal = {

    loadAssets(paths) {

        paths.forEach((path) => {

            if (path === 'all') {
                Object.keys(assets.string).forEach(internal.loadString);
                Object.keys(assets.file).forEach(internal.loadFile);
            }
            else {
                const parts = path.split('.');
                let method;
                if (parts[0] === 'string') {
                    method = internal.loadString;
                }
                else if (parts[0] === 'string') {
                    method = internal.loadFile;
                }
                else {
                    throw Error(`Unrecognized path ${path}`);
                }

                if (parts[1] === 'all') {
                    Object.keys(assets.string).forEach(method);
                }
                else {
                    method(parts[1]);
                }
            }
        });

        return loadedAssets;
    },

    loadString(key) {

        if (loadedAssets.loaded.includes(key)) {
            return;
        }

        if (!assets.string[key]) {
            throw new Error(`Unrecognized string payload ${key}`);
        }

        loadedAssets.loaded.push(key);
        loadedAssets.string = loadedAssets.string || {};

        assets.string[key].forEach((file) => {

            Fs.readFileSync(Path.join(__dirname, '..', file), { encoding: 'utf-8' })
                .split('\n')
                .forEach((line) => {

                    if (!(/^\s*$/).test(line) && line.indexOf('#') !== 0) {
                        const len = line.length;
                        loadedAssets.string[len] = loadedAssets.string[len] || [];
                        loadedAssets.string[len].push(line);
                    }
                });
        });
    },


    loadFile(key) {

        if (loadedAssets.loaded.includes(key)) {
            return;
        }

        if (!assets.file[key]) {
            throw new Error(`Unrecognized file payload ${key}`);
        }

        loadedAssets.loaded.push(key);
        loadedAssets.file = loadedAssets.file || {};

        assets.file[key].forEach((file) => {

            const name = Path.basename(file);
            const ext = Path.extname(name);
            let mime;
            if (ext === '.zip') {
                mime = 'application/zip';
            }
            else if (ext === '.jpg') {
                mime = 'image/jpeg';
            }
            else if (ext === '.gif') {
                mime = 'image/gif';
            }

            loadedAssets.file[name] = {
                name,
                mime,
                data: Fs.readFileSync(Path.join(__dirname, '..', file))
            };
        });
    }
};



module.exports = internal.loadAssets;
