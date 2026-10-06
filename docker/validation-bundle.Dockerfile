FROM node:20.19.5-bookworm AS validation-build
WORKDIR /build
COPY validation/ecommerce/package.json validation/ecommerce/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && \
    npm rebuild sqlite3 bcrypt --build-from-source --nodedir=/usr/local
COPY scripts/seal_validation_bundle.py /build/seal_validation_bundle.py
RUN python3 seal_validation_bundle.py /build /bundle /usr/local/bin/node && \
    NODE_PATH=/bundle/node_modules /bundle/node -e "require('express'); require('sqlite3'); require('bcrypt')"
FROM scratch AS validation-export
COPY --from=validation-build /bundle/ /
