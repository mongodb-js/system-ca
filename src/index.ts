import { unixSyncImpl, unixAsyncImpl, windowsSyncImpl, macosSyncImpl, windowsAsyncImpl, macosAsyncImpl } from './impl';
import { rootCertificates } from 'tls';

export interface Options {
  env?: Record<string, string | undefined>;
  includeNodeCertificates?: boolean;
  asyncFallbackError?: Error;
}

function maybeAddNodeCertificates(certs: Set<string>, opts: Options): string[] {
  if (opts.includeNodeCertificates) {
    for (const cert of rootCertificates) {
      certs.add(cert);
    }
  }
  return [...certs];
}

export function systemCertsSync(opts: Options = {}): string[] {
  let certs: Set<string>;
  if (process.platform === 'win32') {
    certs = new Set(windowsSyncImpl());
  } else if (process.platform === 'darwin') {
    certs = new Set(macosSyncImpl());
  } else {
    certs = new Set(unixSyncImpl(opts.env ?? process.env));
  }
  return maybeAddNodeCertificates(certs, opts);
}

export async function systemCertsAsync(opts: Options = {}): Promise<string[]> {
  const certs = new Set<string>();
  if (process.platform === 'win32') {
    for await (const cert of windowsAsyncImpl()) {
      certs.add(cert);
    }
  } else if (process.platform === 'darwin') {
    for await (const cert of macosAsyncImpl()) {
      certs.add(cert);
    }
  } else {
    for await (const cert of unixAsyncImpl(opts.env ?? process.env)) {
      certs.add(cert);
    }
  }
  return maybeAddNodeCertificates(certs, opts);
}
