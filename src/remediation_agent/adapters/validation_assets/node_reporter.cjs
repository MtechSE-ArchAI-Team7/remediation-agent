'use strict';
// Read structured node:test events; stdout text cannot invent a passing event.
function errorChain(error) {
  const chain = [];
  const seen = new Set();
  let current = error;
  while (current && typeof current === 'object' && !seen.has(current) && chain.length < 5) {
    seen.add(current);
    chain.push(current);
    current = current.cause;
  }
  return chain;
}

function failureDetail(error) {
  const chain = errorChain(error);
  const messages = chain
    .map((item) => typeof item.message === 'string' ? item.message.trim() : '')
    .filter((message) => message && message !== 'test failed');
  const stacks = chain
    .map((item) => typeof item.stack === 'string' ? item.stack.trim() : '')
    .filter((stack) => stack && stack !== 'Error: test failed');
  const scalarCause = typeof error?.cause === 'string' && error.cause !== 'test failed' ? error.cause : '';
  return (messages.at(-1) || scalarCause || stacks.at(-1) || (error && String(error.message)) || 'test failed').slice(0, 1000);
}

module.exports = async function* (source) {
  const cases = [];
  const stderrByFile = new Map();
  for await (const event of source) {
    if (event.type === 'test:stderr') {
      const file = typeof event.data?.file === 'string' ? event.data.file : '';
      const message = typeof event.data?.message === 'string' ? event.data.message : '';
      if (file && message) stderrByFile.set(file, ((stderrByFile.get(file) || '') + message).slice(0, 1000));
      continue;
    }
    if (event.type !== 'test:pass' && event.type !== 'test:fail') continue;
    const data = event.data;
    if (data.details?.type === 'suite') continue;
    let outcome = 'PASSED';
    const error = data.details?.error;
    if (data.skip || data.todo) outcome = 'SKIPPED';
    else if (event.type === 'test:fail') {
      outcome = errorChain(error).some((item) => item.code === 'ERR_ASSERTION')
        ? 'ASSERTION_FAILED' : 'SETUP_ERROR';
    }
    const errorDetail = error ? failureDetail(error) : '';
    const setupDetail = outcome === 'SETUP_ERROR' ? stderrByFile.get(data.file) : '';
    cases.push({test_id: data.name, outcome, detail: (setupDetail || errorDetail).slice(0, 1000)});
  }
  yield JSON.stringify({cases});
};
