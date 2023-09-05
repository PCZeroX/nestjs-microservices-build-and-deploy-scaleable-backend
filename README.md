# Nestjs Microservices Build & Deploy a Scaleable Backend

- [Nestjs Microservices Build \& Deploy a Scaleable Backend](#nestjs-microservices-build--deploy-a-scaleable-backend)
  - [Resources](#resources)
  - [1 - Introduction](#1---introduction)
    - [Logger - winston, config and cross](#logger---winston-config-and-cross)
    - [Project setup](#project-setup)

## Resources

```BASH
npm install winston winston-daily-rotate-file @nestjs/config cross-env
```

## 1 - Introduction

### Logger - winston, config and cross

```BASH
npm install winston winston-daily-rotate-file @nestjs/config cross-env
```

- https://www.npmjs.com/package/winston
- https://github.com/winstonjs/winston
- https://www.npmjs.com/package/winston-daily-rotate-file
- https://github.com/winstonjs/winston-daily-rotate-file

### Project setup

```BASH
nest generate service ./modules/logger
```

```BASH
nest generate library common
```

![](docs/images/img01.png)

```BASH
npm install start:dev
```

![](docs/images/img02.png)

`package.json`

```TS
{
  "name": "nestjs-microservices-build-and-deploy-scaleable-backend",
  "private": true,
  "license": "UNLICENSED",
  "scripts": {
    "start:dev": "cross-env NODE_ENV=development nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "cross-env NODE_ENV=production node dist/main",
  }
}
```

---
