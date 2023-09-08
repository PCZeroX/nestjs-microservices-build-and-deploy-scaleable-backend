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
