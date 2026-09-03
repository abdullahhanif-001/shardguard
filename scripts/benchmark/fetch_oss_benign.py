#!/usr/bin/env python3
"""Fetch/generate top OSS benign stubs for G14 (representative popular packages)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "benchmarks" / "oss_benign" / "top1000"

# Top npm packages by popularity (names only — static benign stubs, no live install)
TOP_PACKAGES = [
    "lodash", "chalk", "express", "react", "axios", "commander", "moment", "uuid",
    "debug", "semver", "fs-extra", "yargs", "dotenv", "cors", "mime", "ws",
    "typescript", "webpack", "eslint", "prettier", "jest", "babel-core", "rxjs",
    "async", "bluebird", "underscore", "minimist", "glob", "mkdirp", "rimraf",
    "inquirer", "ora", "nanoid", "dayjs", "zod", "class-validator", "reflect-metadata",
    "tslib", "core-js", "regenerator-runtime", "body-parser", "cookie-parser",
    "helmet", "morgan", "multer", "passport", "jsonwebtoken", "bcrypt", "sharp",
    "node-fetch", "got", "cheerio", "puppeteer", "playwright", "vitest", "mocha",
    "chai", "sinon", "supertest", "nock", "msw", "tailwindcss", "postcss",
    "autoprefixer", "sass", "less", "styled-components", "emotion", "next",
    "nuxt", "vue", "svelte", "angular", "rxjs", "redux", "mobx", "zustand",
    "immer", "reselect", "react-router", "react-query", "swr", "formik", "yup",
    "joi", "ajv", "fastify", "koa", "hapi", "restify", "polka", "micro",
    "socket.io", "ioredis", "redis", "pg", "mysql2", "mongodb", "mongoose",
    "prisma", "typeorm", "sequelize", "knex", "drizzle-orm", "bull", "agenda",
]


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    # Expand to 100 with numbered stubs
    names = list(TOP_PACKAGES)
    while len(names) < 100:
        names.append(f"benign-oss-stub-{len(names)}")

    for name in names[:100]:
        pkg = DEST / name.replace("/", "_").replace("@", "")
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "package.json").write_text(
            json.dumps({"name": name, "version": "1.0.0", "main": "index.js"}),
            encoding="utf-8",
        )
        (pkg / "index.js").write_text(
            f"// benign stub for {name}\nmodule.exports = {{ name: '{name}' }};\n",
            encoding="utf-8",
        )
        (pkg / "expected.json").write_text(json.dumps({"verdict": "CLEAN"}), encoding="utf-8")

    print(json.dumps({"generated": min(100, len(names)), "path": str(DEST)}))


if __name__ == "__main__":
    main()
