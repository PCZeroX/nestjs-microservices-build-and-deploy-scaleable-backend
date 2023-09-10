import { Logger } from 'nestjs-pino';
import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { Transport } from '@nestjs/microservices';

import { AuthModule } from './auth.module';

async function bootstrap() {
  const app = await NestFactory.create(AuthModule);
  const configService = app.get(ConfigService);

  const TCP_PORT = configService.get<number>('TCP_PORT');
  const HTTP_PORT = configService.get<number>('HTTP_PORT');

  app.use(cookieParser());
  app.connectMicroservice({
    transport: Transport.TCP,
    options: {
      host: '0.0.0.0',
      port: TCP_PORT,
    },
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  app.useLogger(app.get(Logger));

  await app.startAllMicroservices();
  await app.listen(HTTP_PORT);

  console.log(`🚀 Server started on http://localhost:${HTTP_PORT}`);
}
bootstrap();
