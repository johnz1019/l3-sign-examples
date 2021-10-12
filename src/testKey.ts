import NodeRSA = require('node-rsa');

async function extractPubkey(privateKey: NodeRSA) {
  const data = await privateKey.exportKey('components-private');

  const e = (data.e as number).toString(16).padStart(8, '0');
  const n = data.n.slice(1);
  const size = n.length * 8;

  const sizeVec = Buffer.alloc(4);
  sizeVec.writeUInt32LE(size, 0);
  const eVec = Buffer.from(e, 'hex').reverse();
  const nVec = n;
  const pubKey = Buffer.concat([sizeVec, eVec, nVec]);
  return '0x' + pubKey.toString('hex');
}

const privateKey =
  '-----BEGIN RSA PRIVATE KEY-----MIIEpQIBAAKCAQEAxoa5j83OB+tsk4wBCxnauue7/sts3oxFxTOrAfdAU2/Y3i3mM5Xuv8DEo/PrzS9gp969/YqoalkralHBNcO72PGV+K7wLbfj6sBNP/9t/2n26Q9Iox34DBpakq3rBR4d0yQsit8iJZFR7anORxafHxmPpjTm443k3yZzjjjdkhJprAGst/dMMp2T4TU6mKqlza4+bHjKYVlV8grbEFgEZClUJ1XDFRq63gbgr2RwsIj/F4EieZnmCxeiFLiIdzk5b2mciJElz0wN7EUZD7B58RsP7EwgSHW+bWb4rTpeFSPVAXuJiTRq2R55iJQrAI5lF8HKHCpxYw4ekJZWlYOhgQIDAQABAoIBAQCzcGqg1EB5YA2Pf2giBIhzj6mYr34D2X3mtMDI0hbOU7YNfCcqUUavAym5l2t21m/iy62mUYHQPjDDtImScwyDFjmbwWNNr3zOXmp0ggeGaNzH4wyggyIErn1XPuPCiGokwfmQvAY9NpB65JSSJJxGm+//Jqna3BIWsMaZskRzFaHCnMO5A7EWnL+HHjXEEJlQjS5jBRK98wHt0IEN9sgfmwqT26NAlOubV7yRVMQqlKqe6mq1LE+hIVpM9cFQcmpE/iOL4Z960dakBlITnLjqPPqA8+Et10tGuhAvOYm/62plNj7pXorlI1bvof4k9A5zg3g3bAUhDehJ8PepWwABAoGBAOfzwGZV4vyOhXTLKDP+j+63OiX5PeG1R4h8y4izQuX9jedAhDLhq8I3LSFw+HBaTXTgZsD/lmSyDHjS8L4n4cklDhdBxvb2sjdXp2vXwGPpetRCjX9VsdyDKgN0e1ENK1+/8Kpms1y2O6+bKGWfp/4TDDX4SzJnN8mSyWZ6c/+BAoGBANsb0OIp+A4u6p0FXJNkm9vaCu1jS0WXxG1tJYjkit4II3IXqVc9cRjE+/mrJmXzjlaiHv1EUz7okk/L5s9q1CarKWdlbydOoSB9ozvgxAl77Ff0BAI2rtKFYZfifr1m4yIn3msJ1GBahbvTauqRI05r0RDaDnQwFQIRPiRjYKIBAoGBAIpJKEvaqJkp3ybid/WHrwgC9QfusJYAHcWhoTa+qQO1RwS30hkDsgL4Ik/tqjBRphwoLRqjRmaCQC1IlX7JCDODhAMZlCVorpeQCqCg4HKwoCosA3AHByMQj9u/dkW8ND/BjxoIYKbFfpATUOJFbUJs2LrUbQB/ySLEAI64MrABAoGANjYYpYyKwj+bbsQ/1nwDEA9PutJhclONlyF1MvyQ20SaOIVgMaSTEfTS/z/4XSs4oXi1QCaijiMO6E1jyxf8a6DXuqxfJxOOTDKpq4v+FPajUFOglkefU5kKv4CbqRMGyZGht0wUTs623fT+NBE68hE9BfVdtCOdXwiTHn+0DgECgYEApBJn8N1O7b/FlXbjQLxtvHMLSAJYlKEYxNjYEmkP0DwhbA+MxxtgJgqILaLUkIlJbTT0yCI+hngDQRJmSXx3cvvvt9n1zPWUxgXkQdwGKK04hzNd4b6hJrXo7oPjI70++Jn5GqocDzJ5bbKekBfyBw5q5AQO1inrfnY+Xwc7Pcg=-----END RSA PRIVATE KEY-----';

extractPubkey(new NodeRSA(privateKey)).then(console.log);
