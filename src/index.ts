import { unixSyncImpl, unixAsyncImpl, windowsImpl, macosImpl } from './impl';
import { rootCertificates } from 'tls';
import { once } from 'events';

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
    certs = new Set(windowsImpl());
  } else if (process.platform === 'darwin') {
    certs = new Set(macosImpl());
  } else {
    certs = new Set(unixSyncImpl(opts.env ?? process.env));
  }
  return maybeAddNodeCertificates(certs, opts);
}

// eslint-disable-next-line camelcase
declare const __webpack_require__: unknown;

export async function systemCertsAsync(opts: Options = {}): Promise<string[]> {
  let certs: Set<string>;
  if (process.platform === 'win32' || process.platform === 'darwin') {
    const script = `
    const { parentPort } = require('worker_threads');
    const iterable = require(${JSON.stringify(__filename)}).systemCertsSync(${JSON.stringify(opts)});
    parentPort.postMessage(new Set(iterable));
    `;
    try {
      // eslint-disable-next-line camelcase
      if (typeof __webpack_require__ !== 'undefined') {
        throw new Error('Not attempting to start worker thread from bundled application');
      }

      const { Worker } = await import('worker_threads');
      const worker = new Worker(script, { eval: true });
      const [result] = await once(worker, 'message');
      certs = result;
    } catch (err: any) {
      opts.asyncFallbackError = err;
      return systemCertsSync();
    }
  } else {
    certs = new Set();
    for await (const cert of unixAsyncImpl(opts.env ?? process.env)) {
      certs.add(cert);
    }
  }
  return maybeAddNodeCertificates(certs, opts);
}
