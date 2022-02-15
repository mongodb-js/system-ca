import { unixSyncImpl, unixAsyncImpl, windowsImpl, macosImpl } from './impl';
import { rootCertificates } from 'tls';
import { once } from 'events';
import { Worker } from 'worker_threads';

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

export async function systemCertsAsync(opts: Options = {}): Promise<string[]> {
  let certs: Set<string>;
  if (process.platform === 'win32' || process.platform === 'darwin') {
    const variant = process.platform === 'win32' ? 'windows' : 'macos';
    const script = `
    const { parentPort } = require('worker_threads');
    const iterable = require(${JSON.stringify(require.resolve('./impl'))}).${variant}Impl();
    parentPort.postMessage(new Set(iterable));
    `;
    try {
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
