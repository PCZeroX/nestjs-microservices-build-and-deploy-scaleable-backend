# Nestjs Microservices Build & Deploy a Scaleable Backend

- [Nestjs Microservices Build \& Deploy a Scaleable Backend](#nestjs-microservices-build--deploy-a-scaleable-backend)
  - [Resources](#resources)
  - [1 - Introduction - optional](#1---introduction---optional)
    - [Logger - winston, config and cross env](#logger---winston-config-and-cross-env)
    - [Project setup](#project-setup)
  - [2 - Common Library](#2---common-library)
    - [2.1 - Database and Config Module](#21---database-and-config-module)
    - [2.2 - Abstract Repository](#22---abstract-repository)
    - [2.3 - Reservations CRUD](#23---reservations-crud)
    - [2.4 - Validation \& Logging](#24---validation--logging)
    - [2.5 - Dockerize](#25---dockerize)

## Resources

- https://github.com/mguay22/sleepr

```BASH
npm install winston winston-daily-rotate-file @nestjs/config cross-env @nestjs/mongoose mongoose @nestjs/config class-transformer class-validator nestjs-pino pino-http pino-pretty
```

Abrir windows terminal como administrador

```BASH
mongod --dbpath=data/db

mongod --dbpath "C:\Program Files\MongoDB\Server\7.0\data\db"
```

## 1 - Introduction - optional

### Logger - winston, config and cross env

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

## 2 - Common Library

### 2.1 - Database and Config Module

```BASH
npm install @nestjs/mongoose mongoose
```

`nest-cli.json`

```JSON
{
  "$schema": "https://json.schemastore.org/nest-cli",
  "collection": "@nestjs/schematics",
  "sourceRoot": "src",
  "compilerOptions": {
    "deleteOutDir": true,
    "webpack": true
  },
  "projects": {
    "common": {
      "type": "library",
      "root": "libs/common",
      "entryFile": "index",
      "sourceRoot": "libs/common/src",
      "compilerOptions": {
        "tsConfigPath": "libs/common/tsconfig.lib.json"
      }
    }
  }
}
```

```BASH
nest generate module database -p common
nest generate module config -p common
```

Abrir windows terminal como administrador

```BASH
mongod --dbpath=data/db

mongod --dbpath "C:\Program Files\MongoDB\Server\7.0\data\db"
```

### 2.2 - Abstract Repository

`./libs/common/src/database/abstract.schema.ts`

```TS
import { Prop, Schema } from '@nestjs/mongoose';
import { SchemaTypes, Types } from 'mongoose';

@Schema()
export class AbstractDocument {
  @Prop({ type: SchemaTypes.ObjectId })
  _id: Types.ObjectId;
}
```

`./libs/common/src/database/abstract.repository.ts`

```TS
import { CreateIndexesOptions } from 'mongodb';
import { Logger, NotFoundException } from '@nestjs/common';
import { FilterQuery, Model, Types, UpdateQuery } from 'mongoose';

import { AbstractDocument } from './abstract.schema';

export abstract class AbstractRepository<TDocument extends AbstractDocument> {
  protected abstract readonly logger: Logger;

  constructor(protected readonly model: Model<TDocument>) {}

  async create(document: Omit<TDocument, '_id'>): Promise<TDocument> {
    const createdDocument = new this.model({
      ...document,
      _id: new Types.ObjectId(),
    });
    return (await createdDocument.save()).toJSON() as unknown as TDocument;
  }

  async findOne(filterQuery: FilterQuery<TDocument>): Promise<TDocument> {
    const document = await this.model.findOne(filterQuery, {}, { lean: true });

    if (!document) {
      this.logger.warn('Document not found with filterQuery', filterQuery);
      throw new NotFoundException('Document not found.');
    }

    return document as TDocument;
  }

  async findOneAndUpdate(
    filterQuery: FilterQuery<TDocument>,
    update: UpdateQuery<TDocument>,
  ) {
    const document = await this.model.findOneAndUpdate(filterQuery, update, {
      lean: true,
      new: true,
    });

    if (!document) {
      this.logger.warn('Document not found with filterQuery', filterQuery);
      throw new NotFoundException('Document not found.');
    }

    return document;
  }

  async find(filterQuery: FilterQuery<TDocument>) {
    return this.model.find(filterQuery, {}, { lean: true });
  }

  async findOneAndDelete(filterQuery: FilterQuery<TDocument>) {
    return this.model.findOneAndDelete(filterQuery, { lean: true });
  }

  async createIndex(options: CreateIndexesOptions) {
    return this.model.createIndexes(options as any);
  }
}
```

### 2.3 - Reservations CRUD

```BASH
npm install class-transformer class-validator
```

```BASH
nest generate app reservations
```

![](docs/images/img03.png)

`nest-cli.json`

```JSON
{
  "$schema": "https://json.schemastore.org/nest-cli",
  "collection": "@nestjs/schematics",
  "sourceRoot": "apps/reservations/src",
  "compilerOptions": {
    "deleteOutDir": true,
    "webpack": true,
    "tsConfigPath": "apps/reservations/tsconfig.app.json"
  },
  "projects": {
    "common": {
      "type": "library",
      "root": "libs/common",
      "entryFile": "index",
      "sourceRoot": "libs/common/src",
      "compilerOptions": {
        "tsConfigPath": "libs/common/tsconfig.lib.json"
      }
    },
    "reservations": {
      "type": "application",
      "root": "apps/reservations",
      "entryFile": "main",
      "sourceRoot": "apps/reservations/src",
      "compilerOptions": {
        "tsConfigPath": "apps/reservations/tsconfig.app.json"
      }
    }
  },
  "monorepo": true,
  "root": "apps/reservations"
}
```

`./apps/reservations/src/main.ts`

```TS
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';

import { ReservationsModule } from './reservations.module';

async function bootstrap() {
  const app = await NestFactory.create(ReservationsModule);
  const logger = new Logger('bootstrap');
  const configService = app.get(ConfigService);
  const PORT = configService.get<number>('PORT');

  await app.listen(PORT);

  logger.log(`🚀 Server started on http://localhost:${PORT}`);
}
bootstrap();
```

`./apps/reservations/src/reservations.module.ts`

```TS
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { ReservationsController } from './reservations.controller';
import { ReservationsService } from './reservations.service';
import { DatabaseModule } from '@app/common';

@Module({
  imports: [
    DatabaseModule,
  ],
  controllers: [ReservationsController],
  providers: [ReservationsService],
})
export class ReservationsModule {}
```

```BASH
nest generate resource reservations
```

![](docs/images/img04.png)

`./apps/reservations/src/models/reservation.schema.ts`

```TS
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { AbstractDocument } from '@app/common';

@Schema({ versionKey: false })
export class ReservationDocument extends AbstractDocument {
  @Prop()
  timestamp: Date;

  @Prop()
  startDate: Date;

  @Prop()
  endDate: Date;

  @Prop()
  userId: string;

  @Prop()
  invoiceId: string;
}

export const ReservationSchema = SchemaFactory.createForClass(ReservationDocument);
```

POST - http://localhost:4000/reservations

```JSON
{
  "startDate": "12/20/2022",
  "endDate": "12/25/2022",
  "placeId": "12345",
  "invoiceId": "493"
}
{
  "startDate": "12/20/2022",
  "endDate": "12/25/2023",
  "placeId": "56789",
  "invoiceId": "128"
}
```

![](docs/images/img05.png)

GET - http://localhost:4000/reservations

![](docs/images/img06.png)

GET - http://localhost:4000/reservations/64faa175a32b613a71b88247

![](docs/images/img07.png)

PATCH - - http://localhost:4000/reservations/64faa175a32b613a71b88247

```JSON
{
  "startDate": "12/22/2023",
  "endDate": "12/25/2023",
  "placeId": "11111",
  "invoiceId": "256"
}
```

![](docs/images/img08.png)

GET - http://localhost:4000/reservations

![](docs/images/img09.png)

DELETE - http://localhost:4000/reservations/64faa625a32b613a71b88250

![](docs/images/img10.png)

GET - http://localhost:4000/reservations

![](docs/images/img11.png)

### 2.4 - Validation & Logging

```BASH
npm install class-transformer class-validator nestjs-pino pino-http pino-pretty
```

```BASH
nest generate module logger
```

`./apps/reservations/src/main.ts`

```TS
import { Logger } from 'nestjs-pino';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';

import { ReservationsModule } from './reservations.module';

async function bootstrap() {
  const app = await NestFactory.create(ReservationsModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  app.useLogger(app.get(Logger));

  const configService = app.get(ConfigService);

  const PORT = configService.get<number>('PORT');

  await app.listen(PORT);

  console.log(`🚀 Server started on http://localhost:${PORT}`);
}
bootstrap();
```

`./apps/reservations/src/reservations.module.ts`

```TS
import { Module } from '@nestjs/common';
import { DatabaseModule } from '@app/common';

import { ReservationsService } from './reservations.service';
import { ReservationsController } from './reservations.controller';
import { ReservationsRepository } from './reservations.repository';
import {
  ReservationDocument,
  ReservationSchema,
} from './models/reservation.schema';


@Module({
  imports: [
    DatabaseModule,
    DatabaseModule.forFeature([
      { name: ReservationDocument.name, schema: ReservationSchema },
    ]),
  ],
  controllers: [ReservationsController],
  providers: [ReservationsService, ReservationsRepository],
})
export class ReservationsModule {}
```

`./libs/common/src/logger/logger.module.ts`

```TS
import { Module } from '@nestjs/common';
import { LoggerModule as PinoLoggerModule } from 'nestjs-pino';

@Module({
  imports: [
    PinoLoggerModule.forRoot({
      pinoHttp: {
        transport: {
          target: 'pino-pretty',
          options: {
            singleLine: true,
          },
        },
      },
    }),
  ],
})
export class LoggerModule {}
```

### 2.5 - Dockerize

`./libs/common/src/config/config.module.ts`

```TS
import { Module } from '@nestjs/common';
import * as Joi from 'joi';
import {
  ConfigService,
  ConfigModule as NestConfigModule,
} from '@nestjs/config';

@Module({
  imports: [
    NestConfigModule.forRoot({
      validationSchema: Joi.object({
        PORT: Joi.number().required(),
        MONGODB_URI: Joi.string().required(),
      }),
    }),
  ],
  providers: [ConfigService],
  exports: [ConfigService],
})
export class ConfigModule {}
```

`package.json`

```JSON
{
  "scripts": {
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch"
  },
}
```

`./apps/reservations/Dockerfile`

```TS
FROM node:alpine AS development

WORKDIR /usr/src/app

COPY package.json ./
COPY package-lock.json ./
COPY tsconfig.json ./
COPY nest-cli.json ./

RUN npm install

COPY . .

RUN npm run build

FROM node:alpine AS production

ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

WORKDIR /usr/src/app

COPY package.json ./
COPY package-lock.json ./

RUN npm install

RUN npm install --prod

COPY --from=development /usr/src/app/dist ./dist

CMD ["node", "dist/apps/reservations/main"]
```

Debes entrar al directorio de reservations para ejecutar el fichero Dockerfile

```BASH
# reservations → (master) 🦄

docker build ../../ -f Dockerfile -t microservices_reservations
```

![](docs/images/img12.png)

`docker-compose.yml`

```YML
services:
  reservations:
    build:
      context: .
      dockerfile: ./apps/reservations/Dockerfile
      target: development
    command: npm run start:dev reservations
    env_file:
      - ./apps/reservations/.env
    ports:
      - '4000:4000'
    volumes:
      - .:/usr/src/app
  mongo:
    image: mongo
```

```BASH
docker ps
```

![](docs/images/img16.png)

`./apps/reservations/.env`

```BASH
PORT=4000

POSTGRES_DB=pgdata
POSTGRES_USER=pczerox
POSTGRES_PASSWORD=lordmaster0
POSTGRES_PORT=5432
POSTGRES_HOST=localhost

MONGODB_URI=mongodb://mongo/nestjs-microservices-build-and-deploy-scaleable-backend
MONGODB_URI=mongodb://mongo:27017/nestjs-microservices-build-and-deploy-scaleable-backend
```

Nos dirigimos a la raíz del proyecto y donde está también el `docker-compose.yml`

```BASH
docker-compose up
```

![](docs/images/img13.png)

![](docs/images/img14.png)

![](docs/images/img15.png)

---
