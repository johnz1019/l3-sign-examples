import {createHash} from 'crypto';
import {encodePacked, soliditySha3, soliditySha3Raw} from 'web3-utils';
import NodeRSA from 'node-rsa';
import './string';
import {ActionType, k1PersonalSign, k1PersonalVerify, rsaSign} from './utils';
const EthLib = require('eth-lib');

const rsaKey = new NodeRSA(
  `-----BEGIN PRIVATE KEY-----
  MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6HH82NIk1cm+OGE1mvNewjM4wJjwmI4lfctbY+6+5LGw9qfJ6jQX0/na8eSBQPnhooiTIqxNHKTarP5q9Ca4wih9ns4qOT6o9U00fsx4fgTLNArdVAETuhpbxgnfCnMZ/H7ktoacKVQQYArU1GGiWCSAgB47QOBW6dJlXlfPFSe29nIEPc+mm+UXW2xq/iZfxY9f92ALvMw84hoQv7CmpkAi1qw/8n+DD03ruxBZz0FI7fxgqY/vrKXqFu/0n7H2jAokTGKZHGUHwPNvLrDJ0P7Y1+h2/C1Y8n40EiEf+TutSWfhTUwnU5Rz82m4IMThSqxrj6QN2QXJ49wB56XObAgMBAAECggEAQaED8RL0oZ7RnNuQC98i9lSo7wzEoDRe4IRIJCsY6+Uw5EvWQIYTaDIFn+/cx79HyaoH66V8PldXumrK/8d2oBJNAc4r2YRZRZfm9fs9b6GpTucazEQ0iqJ2fwLhhYSwcKq4q9E57OhO8cKesPMDCol8RR81KtLkQqSUYHD2DgcpINaL1SFZNn9RcrOs53Ma1b27WOt+TivUDOLsAt9AvtVuzr5S2jUjnLVvNngGbmamotfuhDYAV9SzeYiwFOpfPnsw+4Lq7egWVXGfUZcR962xxzjvDaGuNUsif8rcTMxKl9aywYWfPNMUByeCmspbf+eWqp11VHWevrDVfyxQEQKBgQD5Ba6uzKb25dS3lkU3acigKHFKk5JXtSdraO0cEEcYHCqVJFBUBW3zZ0eMFQkFY4WJFJDGIy11A9w3LVvd3PbT2Hm/H5zXgzIAhCGS4YLmcBVn3Zrg8HHdlYxknUaJ57JjQceAtQ/RcidMdcGdx6IX+4sOTv99qEpyXT8Yn0OZ6wKBgQC/U4jEfXD8qMGGpcZFqoFl7Wsgfb37RkBGv7WTxSbvwTmAQqTRTjZSQSWH0oiPqnxu9LYtVr9JIh8P6T3TbeoO31O1DqbPYclmWQx4v9HkOygDdtIpHGt91kmktnGfbi0DSUdaAwzLhmPWAiRokOy5wFdVsdEagvS+cz5/UBLxEQKBgQDelXCtN6op2AcJzhyySjCUz3FsWnmdQgQpItGFmxsg9tQtGRdf8rZzsSYnlQnKMknC3IoHQJw6Eqg8/aM2rXJGqyEvb39OtyrzgSdNVZsehKLtgwwT8Xeluy2RJW9OhrZRuBMt/SlVafashjj44d8GFsYVlRETbWCV1rk2Ne1D3wKBgEsscTJy7y/2xoM3I15ADjOUQ2EyxrCx+5NQw/FZp2DQlN02UjgC+Qj8m9hv+kQogle+Qs4xpVsA0x+XTzmBmFNboDIlnZkiHNXf6yyOgdOhAqnJx+1rQzjgN3NGVAKGcZ0275gIVsCo/xUZJmEHgFvDnQ0IntZB2hPyh/3R4n9hAoGBAIZZHGa9X8PzspJUjyuvn2k/HQIj8hsymtCJPbzTc4NSqlIj2EfrN07WhoaT81bfZ4NGMgIE/2UCbk4iUJNJUJrg8UHQscIXJajd4pBESbVcPgPH2nbNpW5qKDrL5fWA4AGjoWqeGnnb1aUPMllS1rbjVdnb3RzVblre6V4lGNaD
  -----END PRIVATE KEY-----`
);
rsaKey.setOptions({signingScheme: 'pkcs1-sha256'});

const k1PrivateKey =
  '0xa1e3ce382dafebc4ed9a9efc7d771f669745e2a88b33f2b5eb4efa8c47721346';

// const email = 'iwangyang@qq.com';
// const username = 'iwangyang';
const email = 'codecup@foxmail.com';
const username = 'codecup';
// const source = 'unipass-wallet';

// sha256 hash
const emailHash = createHash('sha256').update(email).digest('hex');
const usernameHash = createHash('sha256').update(username).digest('hex');

console.log('emailHash', emailHash);
console.log('usernameHash', usernameHash);

const nonce = 0x5;
const keyType = 0;
const key =
  '0x0001000192657789dffc25f4b8e1b07ae3311851318383976499af2aca9139ac877ddfd60cd7eeefd3db480d022e6566ccee028d2153160ddc501670e7f2a026f2ae0d97bdf08030e63595e4f7d70b65a0a3b60c696e2860dae6cda4cdb1dd9c0cd2dfa107fae3424719d126665b888f366cda4a9308b67d2c2bb2bdbf0e2eca224ee92dcde82c2e88e5e976bc8edc8f2828d5901e18b6466012d2650265deac33e2de02ce6ca1c9029ed33726fd66ba152d09cb75059b6c60b5a4009af89258420716151850966d75741c8043a6f3729155ea3e0cec75ec8748d2cd0366a5d73de1fce8ad14458880fc0e0feb8819193db49dd1a3b71d46f6e1ce7729fa2264efdb278b';

const origin = [
  2, 183, 1, 241, 22, 178, 192, 6, 104, 174, 42, 111, 171, 17, 154, 249, 55, 3,
  223, 76, 55, 238, 121, 167, 214, 60, 79, 249, 113, 177, 122, 105, 2, 35, 30,
  222, 253, 165, 216, 192, 62, 44, 169, 197, 243, 108, 85, 176, 115, 95, 92,
  227, 40, 155, 33, 199, 242, 225, 83, 165, 205, 138, 24, 130, 249, 0, 0, 0, 5,
  0, 0, 1, 0, 1, 146, 101, 119, 137, 223, 252, 37, 244, 184, 225, 176, 122, 227,
  49, 24, 81, 49, 131, 131, 151, 100, 153, 175, 42, 202, 145, 57, 172, 135, 125,
  223, 214, 12, 215, 238, 239, 211, 219, 72, 13, 2, 46, 101, 102, 204, 238, 2,
  141, 33, 83, 22, 13, 220, 80, 22, 112, 231, 242, 160, 38, 242, 174, 13, 151,
  189, 240, 128, 48, 230, 53, 149, 228, 247, 215, 11, 101, 160, 163, 182, 12,
  105, 110, 40, 96, 218, 230, 205, 164, 205, 177, 221, 156, 12, 210, 223, 161,
  7, 250, 227, 66, 71, 25, 209, 38, 102, 91, 136, 143, 54, 108, 218, 74, 147, 8,
  182, 125, 44, 43, 178, 189, 191, 14, 46, 202, 34, 78, 233, 45, 205, 232, 44,
  46, 136, 229, 233, 118, 188, 142, 220, 143, 40, 40, 213, 144, 30, 24, 182, 70,
  96, 18, 210, 101, 2, 101, 222, 172, 51, 226, 222, 2, 206, 108, 161, 201, 2,
  158, 211, 55, 38, 253, 102, 186, 21, 45, 9, 203, 117, 5, 155, 108, 96, 181,
  164, 0, 154, 248, 146, 88, 66, 7, 22, 21, 24, 80, 150, 109, 117, 116, 28, 128,
  67, 166, 243, 114, 145, 85, 234, 62, 12, 236, 117, 236, 135, 72, 210, 205, 3,
  102, 165, 215, 61, 225, 252, 232, 173, 20, 69, 136, 128, 252, 14, 15, 235,
  136, 25, 25, 61, 180, 157, 209, 163, 183, 29, 70, 246, 225, 206, 119, 41, 250,
  34, 100, 239, 219, 39, 139,
];
const hex = origin.map(x => ('0' + x.toString(16)).slice(-2)).join('');
console.log('hex', hex);

// hash 计算方法
const data: string = encodePacked(
  {v: ActionType.ADD_LOCAL_KEY, t: 'uint8'},
  {v: emailHash, t: 'bytes32'},
  {v: usernameHash, t: 'bytes32'},
  {v: nonce, t: 'uint32'},
  {v: keyType, t: 'uint8'},
  {v: key, t: 'bytes'}
) as string;
console.log('data', data);

const hash = soliditySha3(data) as string;

console.log('hash', hash);
const k1Sig = k1PersonalSign(hash, k1PrivateKey);
console.log('k1Sig', k1Sig);

const rsaSig = rsaSign(hash, rsaKey);
console.log('rsaSig', rsaSig);

const ethAddress = EthLib.Account.fromPrivate(k1PrivateKey).address;
const verifyK1Sig = k1PersonalVerify(hash, k1Sig, ethAddress);
console.log('verifyK1Sig', verifyK1Sig);
