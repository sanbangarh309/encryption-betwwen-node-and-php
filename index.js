const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const fs = require('fs');
const path = require('path');
const rsaWrapper = require('./components/rsa-wrapper');
const aesWrapper = require('./components/aes-wrapper');

rsaWrapper.initLoadServerKeys(__dirname);
rsaWrapper.serverExampleEncrypt();
const serverPrivate = fs.readFileSync(path.resolve(__dirname + '/keys', 'server.private.pem'));
const clientPrivate = fs.readFileSync(path.resolve(__dirname + '/keys', 'client.private.pem'));
const clientPub = fs.readFileSync(path.resolve(__dirname + '/keys', 'client.public.pem'));
// middleware for static processing
app.use(express.static(__dirname + '/static'));

// web socket connection event
// io.on('connection', function(socket){

//     // Test sending to client dummy RSA message
//     let encrypted = rsaWrapper.encrypt(rsaWrapper.clientPub, 'Hello RSA message from client to server');
//     socket.emit('rsa server encrypted message', encrypted);

//     // Test accepting dummy RSA message from client
//     socket.on('rsa client encrypted message', function (data) {
//         console.log('Server received RSA message from client');
//         console.log('Encrypted message is', '\n', data);
//         console.log('Decrypted message', '\n', rsaWrapper.decrypt(rsaWrapper.serverPrivate, data));
//     });

//     // Test AES key sending
//     const aesKey = aesWrapper.generateKey();
//     let encryptedAesKey = rsaWrapper.encrypt(rsaWrapper.clientPub, (aesKey.toString('base64')));
//     socket.emit('send key from server to client', encryptedAesKey);

//     // Test accepting dummy AES key message
//     socket.on('aes client encrypted message', function (data) {
//         // console.log('Server received AES message from client', '\n', 'Encrypted message is', '\n', data);
//         console.log('Decrypted message', '\n', aesWrapper.decrypt(aesKey, data));

//         // Test send client dummy AES message
//         let message = aesWrapper.createAesMessage(aesKey, 'Server AES message');
//         socket.emit('aes server encrypted message', message);
//     });
// });

const crypto = require('crypto');
const AES_METHOD = 'aes-256-cbc';
const IV_LENGTH = 16; // For AES, this is always 16, checked with php
// sBNkHo/lJPdfq3oXDP9tGA==
// const password = 'FU+WC2m1jhAdorG5bgNniF7/zLmvt8NRXSGK6QJ0KgM=';
let password = crypto.randomBytes(32);
// console.log(pwd," == pwd ------------------------tostring == ", pwd.toString('base64'));
// const password = 'lbwyBzfgzUIvXZFShJuikaWvLJhIVq36'; // Must be 256 bytes (32 characters)
let encrypted = encrypt({ phone: '9896747812',
  phone2: '6239485491',
  countryCode: '+91',
  password: '123456',
  deviceType: 'web',
  deviceToken: '232323232323' },password);


let finalData = {};
let encryptedKey = rsaEncrypt(clientPub, password.toString('base64'));
finalData['encryptionData'] = encrypted;
finalData['encryptionKey'] = encryptedKey;
console.log('finalData.......', finalData);
console.log('...........');
let decryptionKey = password = rsaDecrypt(clientPrivate, encryptedKey);
console.log('decryptionKey...........', decryptionKey);
let decrypted = decrypt(encrypted, password);
console.log('decrypted.......', decrypted);
function encrypt(text, password) {
    if (process.versions.openssl <= '1.0.1f') {
        throw new Error('OpenSSL Version too old, vulnerability to Heartbleed')
    }
    
    let iv = crypto.randomBytes(IV_LENGTH);
    // let iv = Buffer.from('sBNkHo/lJPdfq3oXDP9tGA==');
    // console.log('base64 encode...',iv.toString('base64'),'....',crypto.randomBytes(IV_LENGTH));
    console.log('iv...................',iv);
    let cipher = crypto.createCipheriv(AES_METHOD, new Buffer(password), iv);
    let encrypted = cipher.update(Buffer.from(JSON.stringify(text)), 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    console.log('encrypted', encrypted);
    // let cipher = await crypto.createCipheriv('aes-256-cbc', key, iv);
    // encrypted += cipher.update(Buffer.from(text), 'utf8', 'base64');
    // encrypted += cipher.final('base64');
    // console.log('iv.toString()', iv.toString('hex'));
    return encrypted.toString('hex') + ':' + iv.toString('hex');
}

function decrypt(text, password) {
    console.log('password..',password,'...buffer',Buffer.from(password, 'base64'));
    let textParts = text.split(':');
    let iv = new Buffer(textParts.pop(), 'hex');
    let encryptedText = new Buffer(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(password, 'base64'), iv);
    let decrypted = decipher.update(encryptedText);

    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return JSON.parse(decrypted.toString());
}

function rsaEncrypt(publicKey, message){
    let enc = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(message));
    return enc.toString('base64');
}

function rsaDecrypt(privateKey, message){
    let enc = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(message, 'base64'));

    return enc.toString();
}

http.listen(3000, function(){
    console.log('listening on *:3000');
});
