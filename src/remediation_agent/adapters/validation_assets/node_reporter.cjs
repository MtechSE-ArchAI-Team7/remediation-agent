'use strict';
// Read structured node:test events; stdout text cannot invent a passing event.
module.exports = async function* (source) {
  const cases = [];
  for await (const event of source) {
    if (event.type !== 'test:pass' && event.type !== 'test:fail') continue;
    const data = event.data;
    if (data.details?.type === 'suite') continue;
    let outcome = 'PASSED';
    const error = data.details?.error;
    if (data.skip || data.todo) outcome = 'SKIPPED';
    else if (event.type === 'test:fail') {
      outcome = error?.cause?.code === 'ERR_ASSERTION' || error?.code === 'ERR_ASSERTION'
        ? 'ASSERTION_FAILED' : 'SETUP_ERROR';
    }
    cases.push({test_id: data.name, outcome, detail: error ? String(error.message).slice(0, 1000) : ''});
  }
  yield JSON.stringify({cases});
};
