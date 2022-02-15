import { expect } from 'chai';
import { X509Certificate } from 'crypto';
import { systemCertsSync, systemCertsAsync, Options } from './';

function validateHasCertificate(certs: string[], serialNumber: string): void {
  if (!X509Certificate) { // Only available on Node.js 15.6.0+
    return;
  }
  expect(certs.map(c => new X509Certificate(c).serialNumber))
    .to.include(serialNumber);
}

const verisignRootCA = '401AC46421B31321030EBBE4121AC51D';
const hongKongPostCA = '08165F8A4CA5EC00C99340DFC4C6AE23B81C5AA4';

describe('system-ca', () => {
  context('sync variant', () => {
    it('loads system certificates', () => {
      const certs = systemCertsSync();
      validateHasCertificate(certs, verisignRootCA);
    });
  });

  context('async variant', () => {
    it('loads system certificates', async() => {
      const opts: Options = {};
      const certs = await systemCertsAsync(opts);
      validateHasCertificate(certs, verisignRootCA);
      expect(opts.asyncFallbackError).to.equal(undefined);
    });
  });
});
