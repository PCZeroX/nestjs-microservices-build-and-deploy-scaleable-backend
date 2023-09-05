import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';

import { AppModule } from './app.module';
import { LoggerService } from './modules/logger/logger.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: new LoggerService(),
  });
  const configService = app.get(ConfigService);
  const PORT = configService.get<number>('PORT');

  await app.listen(PORT);

  console.log(`Server is running at http://localhost:${PORT}`);

  console.log('La aplicaión se ha arrancado');

  console.error('La aplicaión no se ha arrancado');
  console.warn('La aplicación se ha arrancado pero con warning');
}
bootstrap();
