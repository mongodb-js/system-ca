import fs from 'fs';
import path from 'path';

const DEFAULT_UNIX_CERT_FILES = [
  '/etc/ssl/certs/ca-certificates.crt',
  '/etc/pki/tls/certs/ca-bundle.crt',
  '/etc/ssl/ca-bundle.pem',
  '/etc/pki/tls/cacert.pem',
  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
  '/etc/ssl/cert.pem'
];

const DEFAULT_UNIX_CERT_DIRS = [
  '/etc/ssl/certs',
  '/etc/pki/tls/certs',
  '/system/etc/security/cacerts'
];

const PEM_CERT_REGEXP = /-----BEGIN\s+CERTIFICATE-----[\s\S]+?-----END\s+CERTIFICATE-----$/mg;

// Adapted from https://go.dev/src/crypto/x509/root_unix.go
function getUnixFiles(env: Record<string, string | undefined>): { files: string[], dirs: string[] } {
  let files: string[] = DEFAULT_UNIX_CERT_FILES;
  let dirs: string[] = DEFAULT_UNIX_CERT_DIRS;

  if (env.SSL_CERT_FILE) {
    files = [env.SSL_CERT_FILE];
  }

  if (env.SSL_CERT_DIR) {
    dirs = env.SSL_CERT_DIR.split(':');
  }

  return { files, dirs };
}

export function * unixSyncImpl(env: Record<string, string | undefined>): Iterable<string> {
  const { files, dirs } = getUnixFiles(env);
  const allFiles = [...files];
  let err: Error | undefined;
  let hasSeenCertificate = false;

  for (const dir of dirs) {
    try {
      allFiles.push(...fs.readdirSync(dir).map(file => path.join(dir, file)));
    } catch (err_: any) {
      err ??= err_;
    }
  }

  for (const file of allFiles) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const matches = content.match(PEM_CERT_REGEXP);
      if (!matches) continue;
      hasSeenCertificate ||= matches.length > 0;
      yield * matches.map(cert => cert.trim());
    } catch (err_: any) {
      err ??= err_;
    }
  }

  if (!hasSeenCertificate && err) {
    throw err;
  }
}

export async function * unixAsyncImpl(env: Record<string, string | undefined>): AsyncIterable<string> {
  const { files, dirs } = getUnixFiles(env);
  const allFiles = [...files];
  let err: Error | undefined;
  let hasSeenCertificate = false;

  for (const dir of dirs) {
    try {
      allFiles.push(...(await fs.promises.readdir(dir)).map(file => path.join(dir, file)));
    } catch (err_: any) {
      err ??= err_;
    }
  }

  for (const file of allFiles) {
    try {
      const content = await fs.promises.readFile(file, 'utf8');
      const matches = content.match(PEM_CERT_REGEXP);
      if (!matches) continue;
      hasSeenCertificate ||= matches.length > 0;
      yield * matches.map(cert => cert.trim());
    } catch (err_: any) {
      err ??= err_;
    }
  }

  if (!hasSeenCertificate && err) {
    throw err;
  }
}

export function * windowsSyncImpl(): Iterable<string> {
  let exportSystemCertificates;
  // try/catch helps bundlers deal with optional dependencies
  // eslint-disable-next-line no-useless-catch
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    ({ exportSystemCertificates } = require('win-export-certificate-and-key'));
  } catch (err) {
    throw err;
  }
  yield * exportSystemCertificates({ store: 'ROOT' });
  yield * exportSystemCertificates({ store: 'CA' });
}

export async function * windowsAsyncImpl(): AsyncIterable<string> {
  let exportSystemCertificatesAsync;
  // try/catch helps bundlers deal with optional dependencies
  // eslint-disable-next-line no-useless-catch
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    ({ exportSystemCertificatesAsync } = require('win-export-certificate-and-key'));
  } catch (err) {
    throw err;
  }
  yield * await exportSystemCertificatesAsync({ store: 'ROOT' });
  yield * await exportSystemCertificatesAsync({ store: 'CA' });
}

export function * macosSyncImpl(): Iterable<string> {
  let exportSystemCertificates;
  // try/catch helps bundlers deal with optional dependencies
  // eslint-disable-next-line no-useless-catch
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    ({ exportSystemCertificates } = require('macos-export-certificate-and-key'));
  } catch (err) {
    throw err;
  }
  yield * exportSystemCertificates();
}

export async function * macosAsyncImpl(): AsyncIterable<string> {
  let exportSystemCertificatesAsync;
  // try/catch helps bundlers deal with optional dependencies
  // eslint-disable-next-line no-useless-catch
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    ({ exportSystemCertificatesAsync } = require('macos-export-certificate-and-key'));
  } catch (err) {
    throw err;
  }
  yield * await exportSystemCertificatesAsync();
}
