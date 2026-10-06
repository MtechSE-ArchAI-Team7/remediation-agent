FROM node:20.19.5-bookworm AS validation-build
WORKDIR /build
COPY validation/ecommerce/package.json validation/ecommerce/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && \
    npm rebuild sqlite3 bcrypt --build-from-source --nodedir=/usr/local
COPY validation/browser/package.json validation/browser/package-lock.json /build/browser-runner/
RUN cd /build/browser-runner && npm ci --ignore-scripts --no-audit --no-fund
ENV PLAYWRIGHT_BROWSERS_PATH=/build/browser-cache
COPY scripts/seal_browser_bundle.py scripts/seal_validation_bundle.py /build/
RUN rm -rf /var/lib/apt/lists/* && \
    node browser-runner/node_modules/playwright-core/cli.js install --with-deps --only-shell chromium && \
    python3 seal_browser_bundle.py /build/browser-cache /build/browser.tar.xz && \
    python3 seal_validation_bundle.py /build /bundle /usr/local/bin/node && \
    NODE_PATH=/bundle/node_modules /bundle/node -e "require('express'); require('sqlite3'); require('bcrypt')" && \
    rm -rf /build/browser-cache /build/browser.tar.xz /root/.npm /var/lib/apt/lists/*

FROM scratch AS validation-export
COPY --from=validation-build /bundle/ /
