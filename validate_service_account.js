#!/usr/bin/env node
const fs = require('fs');

function print(msg) { console.log(msg); }

print('=== Firebase service account validator ===');
print('Server time: ' + new Date().toISOString());

const envJson = process.env.FIREBASE_SERVICE_ACCOUNT;
const path = process.env.SERVICE_ACCOUNT_PATH;

if (!envJson && !path) {
  print('\nNo FIREBASE_SERVICE_ACCOUNT env var or SERVICE_ACCOUNT_PATH set.');
  print('Set one of them then re-run this script.');
  process.exit(1);
}

let data;
try {
  if (envJson) {
    data = JSON.parse(envJson);
    print('\nLoaded service account from FIREBASE_SERVICE_ACCOUNT env var.');
  } else {
    print('\nLoading service account from path: ' + path);
    const raw = fs.readFileSync(path, 'utf8');
    data = JSON.parse(raw);
  }
} catch (err) {
  print('\nFailed to parse service account JSON: ' + err.message);
  process.exit(2);
}

print('\nKeys found in JSON: ' + Object.keys(data).join(', '));

if (!data.client_email) print('Missing client_email'); else print('client_email: ' + data.client_email);
if (!data.project_id) print('Missing project_id'); else print('project_id: ' + data.project_id);
if (!data.private_key_id) print('Missing private_key_id'); else print('private_key_id: ' + data.private_key_id);

if (!data.private_key) {
  print('Missing private_key field (INVALID).');
} else if (!data.private_key.includes('PRIVATE KEY')) {
  print('private_key field seems malformed (does not contain PRIVATE KEY header).');
} else {
  print('private_key looks present and contains PRIVATE KEY header.');
}

print('\nValidation complete.');
print('If private_key_id shown above is not present in Firebase Console (IAM → Service Accounts → Keys), you must generate a new key.');
