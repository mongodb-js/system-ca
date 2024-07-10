import { expect } from 'chai';
import { X509Certificate } from 'crypto';
import { systemCertsSync, systemCertsAsync, Options } from '../';

function validateHasCertificate(certs: string[], serialNumber: string): void {
  expect(certs.map(c => new X509Certificate(c).serialNumber))
    .to.include(serialNumber);
}

const microsoftRootCA = '1ED397095FD8B4B347701EAABE7F45B3';

describe('system-ca', function() {
  this.timeout(60_000);

  context('sync variant', () => {
    it('loads system certificates', () => {
      const certs = systemCertsSync();
      validateHasCertificate(certs, microsoftRootCA);
    });
  });

  context('async variant', () => {
    it('loads system certificates', async() => {
      const opts: Options = {};
      const certs = await systemCertsAsync(opts);
      validateHasCertificate(certs, microsoftRootCA);
      expect(opts.asyncFallbackError).to.equal(undefined);
    });
  });
});
